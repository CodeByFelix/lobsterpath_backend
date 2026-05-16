from datetime import datetime, timedelta, timezone
from sqlmodel import select, func, desc
from src.database import async_session_local
from src.model import AuditEvent, Project, APIKey
from src.email.send_email import send_email, load_security_alert_template, load_report_template
from src.loggings import logging
import httpx
import json

async def process_security_alert(
    project_id: str, 
    verdict: str, 
    request_id: str
):
    """
    Evaluates security events and triggers background emails based on project thresholds.
    This helper is used by the AI Gateway to offload security monitoring.
    """
    try:
        async with async_session_local() as db:
            # 1. Fetch project alert configuration
            query = select(Project).where(Project.id == project_id)
            result = await db.execute(query)
            project = result.scalar_one_or_none()
            
            if not project or not project.alert_email:
                return

            should_notify = False
            subject = ""
            reason = ""

            # 2. Case: HUMAN_REVIEW (Immediate Alert)
            if verdict == "HUMAN_REVIEW":
                should_notify = True
                subject = f"🚨 ACTION REQUIRED: Human Review Needed - {project.name}"
                reason = "A request has been quarantined for manual human review. This requires your immediate attention."

            # 3. Case: DENY (Threshold-based Alerting)
            elif verdict == "DENY":
                window_start = datetime.now(timezone.utc) - timedelta(seconds=project.deny_alert_window)
                
                # Count denies in the last X seconds
                count_query = select(func.count(AuditEvent.id)).where(
                    AuditEvent.project_id == project_id,
                    AuditEvent.verdict == "DENY",
                    AuditEvent.created_at >= window_start
                )
                count_result = await db.execute(count_query)
                deny_count = count_result.scalar() or 0
                
                # Alert only when threshold is hit
                if deny_count >= project.deny_alert_threshold:
                    should_notify = True
                    subject = f"⚠️ SECURITY ALERT: High Denial Rate - {project.name}"
                    reason = f"Our engine has detected a high frequency of security blocks ({deny_count} denials) within the last {project.deny_alert_window} seconds. This could indicate a coordinated attack."

            # 4. Dispatch Email if triggered
            if should_notify:
                html_body = load_security_alert_template(
                    project_name=project.name,
                    subject=subject,
                    reason=reason,
                    request_id=request_id
                )
                success = await send_email(project.alert_email, subject, html_body)
                if success:
                    logging.info(f"Security alert email sent to {project.alert_email} for project {project.name}")
    
    except Exception as e:
        logging.error(f"Error in security alert processing: {str(e)}", exc_info=True)

async def generate_comprehensive_report(
    target_id: str,
    target_type: str, # "project" or "apikey"
    provider_url: str,
    provider_key: str,
    user_email: str,
    model: str
):
    """
    Background task that:
    1. Fetches recent logs for a project or API key.
    2. Sends them to an LLM for a summary/report using httpx.
    3. Emails the final report to the user.
    """
    try:
        async with async_session_local() as db:
            # 1. Fetch Logs
            if target_type == "project":
                query = select(AuditEvent).where(AuditEvent.project_id == target_id).order_by(desc(AuditEvent.created_at)).limit(50)
                name_query = select(Project.name).where(Project.id == target_id)
            else:
                query = select(AuditEvent).where(AuditEvent.api_key_id == target_id).order_by(desc(AuditEvent.created_at)).limit(50)
                name_query = select(APIKey.name).where(APIKey.id == target_id)
            
            result = await db.execute(query)
            logs = result.scalars().all()
            
            name_result = await db.execute(name_query)
            target_name = name_result.scalar() or "Unknown"

            if not logs:
                logging.info(f"No logs found for {target_type} {target_id}, sending notification.")
                await send_email(
                    user_email, 
                    f"ℹ️ Report Update: No Logs Found - {target_name}",
                    f"<h3>No Logs Found</h3><p>We attempted to generate a security report for <b>{target_name}</b>, but no audit events were found in the database. Once your agents start generating traffic, we'll be able to provide detailed insights!</p>"
                )
                return

            # 2. Format logs for LLM
            log_data = []
            for log in logs:
                log_data.append({
                    "time": log.created_at.isoformat(),
                    "verdict": log.verdict,
                    "model": log.model_used,
                    "tokens": log.total_tokens,
                    "prompt": log.prompt_snippet[:100] if log.prompt_snippet else "N/A"
                })
            prompt = f"""
            You are a senior AI Security Analyst. 
            Below are the last 50 audit logs for an AI project/API key named '{target_name}'.
            Please generate a comprehensive, professional security and usage report.
            Include:
            - Security Overview (Blocks vs Allows)
            - Usage Statistics (Token consumption)
            - Risk Assessment (Are there patterns of suspicious activity?)
            - Recommendations
            
            Format the report in clean HTML (no <html> tags, just <h3>, <p>, <ul>, etc.) 
            Keep it professional and concise.
            
            LOGS:
            {json.dumps(log_data, indent=2)}
            """

            # 3. Call LLM via httpx
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.post(
                        f"{provider_url.rstrip('/')}/chat/completions",
                        headers={"Authorization": f"Bearer {provider_key}"},
                        json={
                            "model": model, 
                            "messages": [
                                {"role": "system", "content": "You are a professional security auditor."},
                                {"role": "user", "content": prompt}
                            ]
                        },
                        timeout=60.0
                    )
                    
                    if response.status_code != 200:
                        logging.error(f"LLM Provider error: {response.text}")
                        await send_email(
                            user_email,
                            f"❌ Report Generation Failed: {target_name}",
                            f"<h3>Report Generation Failed</h3><p>We encountered an error while consulting the AI provider for your report on <b>{target_name}</b>.</p><p><b>Action Required:</b> Please review your provider URL and API Key settings in the dashboard and try again.</p>"
                        )
                        return
                    
                    report_content = response.json()["choices"][0]["message"]["content"]
                except Exception as llm_err:
                    logging.error(f"Error calling LLM: {str(llm_err)}")
                    await send_email(
                        user_email,
                        f"❌ Report Generation Failed: {target_name}",
                        f"<h3>Report Generation Failed</h3><p>We could not reach your AI provider to generate the report for <b>{target_name}</b>.</p><p><b>Action Required:</b> Please ensure your provider URL is correct and reachable, then try again.</p>"
                    )
                    return

            # 4. Email the report
            html_body = load_report_template(
                target_name=target_name,
                report_content=report_content
            )
            
            subject = f"📊 Comprehensive Security Report: {target_name}"
            await send_email(user_email, subject, html_body)
            logging.info(f"Comprehensive report sent to {user_email}")

    except Exception as e:
        logging.error(f"Error generating comprehensive report: {str(e)}", exc_info=True)
