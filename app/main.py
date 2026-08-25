from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.middleware.waf_middleware import WAFMiddleware
from app.database.session import engine, Base
from app.dashboard.router import router as dashboard_router
from app.api.router import router as api_router
from app.models.ip_rule import IPRule

# إنشاء الجداول
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.APP_NAME)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# WAF Middleware
app.add_middleware(WAFMiddleware)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Routers
app.include_router(dashboard_router, prefix="/dashboard")
app.include_router(api_router, prefix="/api")

import httpx
from fastapi.responses import Response

DVWA_URL = "http://127.0.0.1:8080"

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def reverse_proxy(request: Request, path: str):
    EXCLUDED = ["dashboard", "static", "api", "favicon.ico"]
    for excluded in EXCLUDED:
        if path.startswith(excluded):
            from fastapi import HTTPException
            raise HTTPException(status_code=404)

    url = f"{DVWA_URL}/{path}"
    if request.url.query:
        url += f"?{request.url.query}"

    body = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)

    excluded_headers = ["transfer-encoding", "content-encoding", "content-length", "connection"]

    async with httpx.AsyncClient(follow_redirects=False, cookies=dict(request.cookies)) as client:
        response = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
        )

    response_headers = {k: v for k, v in response.headers.items() if k.lower() not in excluded_headers}

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers,
        media_type=response.headers.get("content-type"),
    )