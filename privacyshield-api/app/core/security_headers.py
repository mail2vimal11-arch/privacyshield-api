"""
security_headers.py — Security response headers middleware.

Adds security headers to every API response. Prevents clickjacking,
MIME sniffing, and information disclosure. Required for enterprise
customer security reviews and SOC2 compliance.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Force HTTPS for 1 year
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # XSS protection (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Minimal referrer info
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Restrict browser features
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        # Content Security Policy — API only, no browser rendering needed
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

        # Remove server identification header
        response.headers.pop("server", None)
        response.headers.pop("Server", None)

        return response
