from fastapi import APIRouter, Depends, Request, Response, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
import httpx
import json
import uuid
import secrets
from src.utils import get_project_by_api_key, assemble_lobstertrap_policy
from src.loggings import logging
from src.settings import settings
from src.database import get_session
from src.model import AuditEvent
from src.routers.utils import process_security_alert

gateway_router = APIRouter(tags=["Gateway"])

# The Data Plane (Lobster Trap) entry point
LOBSTERTRAP_URL = f"{settings.LOBSTERTRAP_BASE_URL}/chat/completions"

@gateway_router.post(
    "/chat/completions",
    status_code=status.HTTP_200_OK,
    summary="AI Gateway - Chat Completions Proxy (Standard)",
    description="Main entry point for AI Agent traffic. Proxies requests to Lobster Trap with automated observability and security policy injection.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid SOC API Key"},
        status.HTTP_400_BAD_REQUEST: {"description": "Invalid JSON payload"},
        status.HTTP_502_BAD_GATEWAY: {"description": "Lobster Trap Data Plane unreachable"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Internal server error during processing"}
    }
)
@gateway_router.post(
    "/v1/chat/completions",
    status_code=status.HTTP_200_OK,
    summary="AI Gateway - Chat Completions Proxy (OpenAI SDK Fallback)",
    description="Alias route. Normalizes paths from SDKs that hardcode /v1 into the base URL path.",
    include_in_schema=False
)
@gateway_router.post(
    "/openai/v1/chat/completions",
    status_code=status.HTTP_200_OK,
    summary="AI Gateway - Chat Completions Proxy (LangChain Groq Fallback)",
    description="Alias route. Normalizes paths from LangChain and other SDKs that hardcode the full /openai/v1 prefix.",
    include_in_schema=False
)

async def ai_gateway(
    request: Request,
    background_tasks: BackgroundTasks,
    project_context: dict = Depends(get_project_by_api_key),
    session: AsyncSession = Depends(get_session)
):
    """
    Intercepts LLM traffic, logs usage, and forwards to Lobster Trap for security analysis.

    This gateway performs:
    1. Correlation ID generation for end-to-end tracing.
    2. Dynamic security policy assembly and injection.
    3. Token-swap for backend provider authentication.
    4. Real-time observability capture (token usage, model names, security reports).
    5. Asynchronous security alerting for high-risk events.

    Args:
        request (Request): Incoming OpenAI-compatible request.
        background_tasks (BackgroundTasks): Background task manager for non-blocking alerts.
        project_context (dict): Context injected via API Key dependency (Project, APIKey, Policy).
        session (AsyncSession): Database session for audit logging.

    Returns:
        Response: The proxied response from the Lobster Trap verification engine.

    Raises:
        HTTPException: 401 if API Key is invalid.
        HTTPException: 400 if the request body is malformed.
        HTTPException: 502 if the Lobster Trap engine is unreachable.
        HTTPException: 500 on internal failures.
    """
    try:
        api_key_obj = project_context["api_key"]
        project_obj = project_context["project"]
        policy_obj = project_context["policy"]
        
        # 1. Generate Correlation ID
        request_id = f"req_{secrets.token_urlsafe(16)}"
        
        # 2. Prepare the payload
        try:
            body = await request.json()
        except json.JSONDecodeError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload.")

        # 3. Extract Prompt Snippet (Ingress Observability)
        prompt_snippet = ""
        try:
            messages = body.get("messages", [])
            if messages:
                last_msg = messages[-1].get("content", "")
                prompt_snippet = str(last_msg)[:50]
        except Exception:
            pass

        # 4. Initialize Audit Entry in memory (deferred write for performance)
        audit_entry = AuditEvent(
            project_id=project_obj.id,
            request_id=request_id,
            prompt_snippet=prompt_snippet,
            verdict="PENDING"
        )
        
        # 5. Assemble the full Go-compatible policy JSON
        try:
            selection = policy_obj.selection_json if policy_obj else {"enabled_ingress": [], "enabled_egress": []}
            full_policy = assemble_lobstertrap_policy(
                project_name=project_obj.name,
                enabled_ingress=selection.get("enabled_ingress", []),
                enabled_egress=selection.get("enabled_egress", [])
            )
        except Exception as e:
            logging.error(f"Policy assembly failed: {str(e)}", exc_info=True)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to assemble security policy.")
        
        # 6. Prepare headers for Lobster Trap
        headers = dict(request.headers)
        
        # --- Token Swap ---
        if api_key_obj.backend_api_key:
            headers["authorization"] = f"Bearer {api_key_obj.backend_api_key}"
        
        # Inject Lobster Trap Control Plane headers
        headers["X-Lobstertrap-Backend"] = api_key_obj.backend_url
        headers["X-Lobstertrap-Policy"] = json.dumps(full_policy)
        headers["X-Lobstertrap-Request-ID"] = request_id
        
        if "host" in headers:
            del headers["host"]
        if "accept-encoding" in headers:
            del headers["accept-encoding"]
        #logging.info(f"Headers: {headers}")
        #logging.info(f"Body: {body}")
        async with httpx.AsyncClient() as client:
            try:
                # Forward the request to Lobster Trap
                proxy_resp = await client.post(
                    LOBSTERTRAP_URL,
                    json=body,
                    headers=headers,
                    timeout=60.0
                )
                
                # 7. Extract Egress Observability (Usage, Model, Snippet, and Security Metadata)
                try:
                    resp_json = proxy_resp.json()
                    #logging.info(f"Response Body: {resp_json}")
                    #logging.info(f"Response Headers: {dict(proxy_resp.headers)}")
                    
                    # Usage & Model
                    usage = resp_json.get("usage", {})
                    audit_entry.model_used = resp_json.get("model")
                    audit_entry.prompt_tokens = usage.get("prompt_tokens", 0)
                    audit_entry.completion_tokens = usage.get("completion_tokens", 0)
                    audit_entry.total_tokens = usage.get("total_tokens", 0)
                    
                    # Response Snippet / Tool Calls
                    choices = resp_json.get("choices", [])
                    if choices:
                        message = choices[0].get("message", {})
                        content = message.get("content")
                        tool_calls = message.get("tool_calls")
                        
                        if tool_calls:
                            tool_names = [tc.get("function", {}).get("name", "unknown") for tc in tool_calls]
                            audit_entry.response_snippet = f"TOOL CALL: {', '.join(tool_names)}"
                        elif content:
                            audit_entry.response_snippet = content[:50] + ("..." if len(content) > 50 else "")
                    
                    # 8. Detailed Security Reports (Ingress & Egress DPI)
                    lobster_report = resp_json.get("_lobstertrap", {})
                    
                    # Store clean Ingress and Egress reports
                    audit_entry.metadata_ = {
                        "ingress": lobster_report.get("ingress", {}),
                        "egress": lobster_report.get("egress", {})
                    }
                    
                    # Pull verdict directly from the report
                    audit_entry.verdict = lobster_report.get("verdict", "UNKNOWN")
                    
                    session.add(audit_entry)
                    await session.commit()
                    
                    # 9. Smart Security Alerting (Triggered only on Security Events)
                    if audit_entry.verdict in ["DENY", "HUMAN_REVIEW"]:
                        background_tasks.add_task(
                            process_security_alert,
                            project_obj.id,
                            audit_entry.verdict,
                            request_id
                        )
                except Exception as e:
                    logging.warning(f"Failed to parse egress observability: {e}")
                    pass

                # Return the response from Lobster Trap back to the user
                # We exclude content-length and content-encoding so FastAPI can recalculate them correctly
                excluded_headers = {"content-length", "content-encoding", "transfer-encoding"}
                resp_headers = {k: v for k, v in proxy_resp.headers.items() if k.lower() not in excluded_headers}
                
                return Response(
                    content=proxy_resp.content,
                    status_code=proxy_resp.status_code,
                    headers=resp_headers
                )
                
            except httpx.RequestError as exc:
                logging.error(f"Error proxying to Lobster Trap: {exc}", exc_info=True)
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Verification Engine is unreachable or timed out.")

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Critical error in AI Gateway: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred in the AI Gateway.")
