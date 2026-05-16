from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from src.routers.auth_router import auth_router
from src.routers.project_router import project_router
from src.routers.gateway_router import gateway_router
from src.routers.webhook_router import webhook_router
from src.routers.rule_router import rule_router
from src.database import init_db, engine
from src.middleware import RateLimitMiddleware, RequestLoggingMiddleware, SecurityHeadersMiddleware
from src.settings import settings
from src.loggings import logging


@asynccontextmanager
async def lifespan (app: FastAPI):
    await init_db ()
    logging.info ("Database initialised successfully")
    yield
    await engine.dispose ()
    logging.info ("Database connections closed")


# --- Environment-Aware Documentation ---
# Docs are only available in development mode. In production, /docs, /redoc,
# and /openapi.json return 404, preventing users from discovering internal APIs.
_is_dev = settings.ENVIRONMENT == "development"

app = FastAPI (
    lifespan=lifespan,
    title="Lobster Path AI-SOC" if _is_dev else "Lobster Path",
    description="AI Security Operations Center - Control Plane API" if _is_dev else None,
    docs_url="/docs" if _is_dev else None,
    redoc_url="/redoc" if _is_dev else None,
    openapi_url="/openapi.json" if _is_dev else None,
)

# --- CORS Middleware ---
app.add_middleware (
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Rate Limiting Middleware ---
app.add_middleware (RateLimitMiddleware)

# --- Request Logging Middleware ---
app.add_middleware (RequestLoggingMiddleware)

# --- Security Headers Middleware ---
app.add_middleware (SecurityHeadersMiddleware)

app.include_router (auth_router)
app.include_router (project_router)
app.include_router (gateway_router)
app.include_router (webhook_router)
app.include_router (rule_router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Log the full exception for developers including stack trace
    logging.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)

    # Return a clean, safe response to the user
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected server error occurred. Please try again later."},
    )
