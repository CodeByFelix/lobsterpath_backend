import time
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from src.loggings import logging


class RateLimiter:
    """
    In-memory sliding window rate limiter.

    Tracks request timestamps per key (IP address) and rejects
    requests that exceed the configured threshold within the window.

    Args:
        max_requests: Maximum number of requests allowed within the window.
        window_seconds: The duration of the sliding window in seconds.
    """

    def __init__ (self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = {}
        self._last_purge: float = time.time ()

    def _cleanup (self, key: str, now: float) -> None:
        """Remove timestamps outside the current window for a single key."""
        if key in self.requests:
            cutoff = now - self.window_seconds
            self.requests[key] = [t for t in self.requests[key] if t > cutoff]

            # Remove the key entirely if no timestamps remain
            if not self.requests[key]:
                del self.requests[key]

    def _purge_expired (self, now: float) -> None:
        """
        Sweep all keys and remove those with only expired timestamps.

        This runs automatically every 60 seconds to prevent stale IPs
        from accumulating in memory indefinitely.
        """
        cutoff = now - self.window_seconds
        stale_keys = [
            key for key, timestamps in self.requests.items ()
            if not any (t > cutoff for t in timestamps)
        ]
        for key in stale_keys:
            del self.requests[key]

        self._last_purge = now

    def is_allowed (self, key: str) -> tuple[bool, int]:
        """
        Check if a request from the given key is allowed.

        Args:
            key: The identifier for the client (typically an IP address).

        Returns:
            A tuple of (allowed: bool, retry_after: int).
            If allowed is False, retry_after indicates how many seconds
            the client should wait before retrying.
        """
        now = time.time ()

        # Periodically purge all expired entries (every 60 seconds)
        if now - self._last_purge > 60:
            self._purge_expired (now)

        self._cleanup (key, now)

        timestamps = self.requests.get (key, [])

        if len (timestamps) >= self.max_requests:
            # Calculate how long until the oldest request in the window expires
            oldest = timestamps[0]
            retry_after = int (self.window_seconds - (now - oldest)) + 1
            return False, max (retry_after, 1)

        # Record this request
        self.requests.setdefault (key, []).append (now)
        return True, 0


def get_client_ip (request: Request) -> str:
    """
    Extract the real client IP address from the request.

    Checks the X-Forwarded-For header first (for requests behind
    a reverse proxy like Nginx or Cloudflare), then falls back
    to the direct connection IP.
    """
    forwarded_for = request.headers.get ("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
        # The first one is the real client IP
        return forwarded_for.split (",")[0].strip ()

    return request.client.host if request.client else "unknown"


# --- Global Rate Limiter Instance ---
global_limiter = RateLimiter (max_requests=60, window_seconds=60)


class RateLimitMiddleware (BaseHTTPMiddleware):
    """
    Global rate limiting middleware.

    Applies a broad request limit across all endpoints to prevent
    general abuse, bot traffic, and DDoS-style flooding.
    """

    async def dispatch (self, request: Request, call_next):
        client_ip = get_client_ip (request)
        allowed, retry_after = global_limiter.is_allowed (client_ip)

        if not allowed:
            logging.warning (f"Rate limit exceeded for IP: {client_ip}")
            return JSONResponse (
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many requests. Please slow down."},
                headers={"Retry-After": str (retry_after)}
            )

        response = await call_next (request)
        return response


class RequestLoggingMiddleware (BaseHTTPMiddleware):
    """
    Logs every incoming request with method, path, status code,
    client IP, and response time for observability and debugging.
    """

    async def dispatch (self, request: Request, call_next):
        client_ip = get_client_ip (request)
        start_time = time.time ()

        response = await call_next (request)

        duration_ms = round ((time.time () - start_time) * 1000)
        logging.info (
            f"{request.method} {request.url.path} | "
            f"{response.status_code} | "
            f"{client_ip} | "
            f"{duration_ms}ms"
        )

        return response


class SecurityHeadersMiddleware (BaseHTTPMiddleware):
    """
    Adds essential security headers to all HTTP responses to protect clients 
    from common vulnerabilities like XSS, framing attacks, and content sniffing.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Prevent clickjacking by forbidding iframe embedding
        response.headers["X-Frame-Options"] = "DENY"
        # Prevent browsers from MIME-sniffing a response away from the declared content-type
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Enable browser's built-in XSS protection (legacy defense in depth)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Enforce HTTPS on clients for the next year (if they ever connect directly)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Control how much referrer information sent to other sites
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        return response


# --- Strict Auth Rate Limiter Instances ---
login_limiter = RateLimiter (max_requests=5, window_seconds=60)
create_account_limiter = RateLimiter (max_requests=3, window_seconds=60)
otp_request_limiter = RateLimiter (max_requests=3, window_seconds=60)
otp_verify_limiter = RateLimiter (max_requests=5, window_seconds=60)


def rate_limit_dependency (limiter: RateLimiter):
    """
    Factory that creates a FastAPI dependency from a RateLimiter instance.

    Usage:
        @router.post("/login")
        async def login(... , _rate_limit = Depends(rate_limit_dependency(login_limiter))):

    Raises:
        HTTPException 429 if the client exceeds the allowed request count.
    """

    async def check_rate_limit (request: Request):
        client_ip = get_client_ip (request)
        allowed, retry_after = limiter.is_allowed (client_ip)

        if not allowed:
            logging.warning (f"Auth rate limit exceeded for IP: {client_ip} on {request.url.path}")
            raise HTTPException (
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many attempts. Try again in {retry_after} seconds.",
                headers={"Retry-After": str (retry_after)}
            )

    return check_rate_limit
