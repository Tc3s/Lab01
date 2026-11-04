"""
Correlation ID Middleware
Location: app/middleware/correlation.py

Generates or propagates a unique correlation_id (UUIDv4) per request for audit trail tracing.
Stores it in request.state for downstream access and sets X-Correlation-ID header on responses.
"""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        raw_cid = request.headers.get("X-Correlation-ID")
        correlation_id = raw_cid.strip() if (raw_cid and raw_cid.strip()) else str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
