"""
This module initializes the Audit logs
"""

import os
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from trading.views.trading_signal_view import router as trading_signal_router


app = FastAPI()
app.include_router(trading_signal_router)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("YOUR_SECRET_KEY"))


@app.middleware("http")
async def dynamic_cors_middleware(request: Request, call_next):
    """
    Dynamic CORS definition allowing all origins
    """
    if request.method == "OPTIONS":
        response = JSONResponse(content={"detail": "CORS preflight"})
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = \
            "OPTIONS, GET, POST, PUT, DELETE"
        response.headers["Access-Control-Allow-Headers"] = \
            "Authorization, Content-Type, X-CSRF-Token, Set-Cookie"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = \
        "OPTIONS, GET, POST, PUT, DELETE"
    response.headers["Access-Control-Allow-Headers"] = \
        "Authorization, Content-Type, X-CSRF-Token, Set-Cookie"
    return response


@app.on_event("startup")
async def set_audit_log_description():
    """
    Descriptions modules
    """
    app.openapi_tags = [
        {"name": "Trading",
         "description": "Service by register trading transactions"},
    ]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, port=8001)
