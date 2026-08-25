import asyncio
import json
from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from app.database.session import get_db
from app.models.request_log import RequestLog
from app.dashboard.jwt_auth import create_access_token, verify_token, require_jwt
from app.core.config import settings
from app.models.ip_rule import IPRule

router = APIRouter()
templates = Jinja2Templates(directory="app/dashboard/templates")

subscribers: list[asyncio.Queue] = []
MAX_SUBSCRIBERS = 5


async def broadcast(log: dict):
    for queue in subscribers:
        await queue.put(log)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None
    })


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    if username == settings.DASHBOARD_USERNAME and password == settings.DASHBOARD_PASSWORD:
        token = create_access_token({"sub": username})
        response = RedirectResponse(url="/dashboard/", status_code=302)
        response.set_cookie(
            key="access_token",
            value=token,
            httponly=True,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
        return response

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "Invalid username or password"
    })


@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/dashboard/login", status_code=302)
    response.delete_cookie("access_token")
    return response


@router.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(require_jwt)
):
    total = db.query(RequestLog).count()
    malicious = db.query(RequestLog).filter(RequestLog.is_malicious == True).count()
    blocked = db.query(RequestLog).filter(RequestLog.blocked == True).count()

    attack_types = db.query(
        RequestLog.attack_type,
        func.count(RequestLog.attack_type).label("count")
    ).filter(
        RequestLog.attack_type != None
    ).group_by(
        RequestLog.attack_type
    ).all()

    recent_logs = db.query(RequestLog)\
                    .order_by(desc(RequestLog.timestamp))\
                    .limit(10)\
                    .all()

    return templates.TemplateResponse("index.html", {
        "request": request,
        "total": total,
        "malicious": malicious,
        "blocked": blocked,
        "safe": total - malicious,
        "attack_types": {a.attack_type: a.count for a in attack_types},
        "recent_logs": recent_logs,
        "username": username,
    })


@router.get("/requests", response_class=HTMLResponse)
async def requests_page(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(require_jwt),
    page: int = 1,
    attack_type: str = "",
    status: str = "",
    search: str = "",
):
    page_size = 50
    skip = (page - 1) * page_size

    query = db.query(RequestLog)

    # Filter by attack type
    if attack_type:
        query = query.filter(RequestLog.attack_type == attack_type)

    # Filter by status
    # Filter by status
    if status == "safe":
        query = query.filter(RequestLog.is_malicious == False)
    elif status == "blocked":
        query = query.filter(RequestLog.blocked == True)

    # Search by IP or URL
    if search:
        query = query.filter(
            RequestLog.ip_address.contains(search) |
            RequestLog.url.contains(search)
        )

    total = query.count()
    total_pages = (total + page_size - 1) // page_size

    logs = query.order_by(desc(RequestLog.timestamp))\
                .offset(skip)\
                .limit(page_size)\
                .all()

    # نجيب أنواع الهجمات للـ filter dropdown
    attack_types = db.query(RequestLog.attack_type)\
                     .filter(RequestLog.attack_type != None)\
                     .distinct()\
                     .all()
    attack_types = [a.attack_type for a in attack_types]

    return templates.TemplateResponse("requests.html", {
        "request": request,
        "logs": logs,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "attack_types": attack_types,
        "selected_attack": attack_type,
        "selected_status": status,
        "search": search,
    })


@router.get("/requests/{request_id}", response_class=HTMLResponse)
async def request_detail(
    request: Request,
    request_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_jwt)
):
    log = db.query(RequestLog)\
            .filter(RequestLog.id == request_id)\
            .first()

    return templates.TemplateResponse("request_detail.html", {
        "request": request,
        "log": log,
    })


@router.get("/stream")
async def stream(
    request: Request,
    username: str = Depends(require_jwt)
):
    if len(subscribers) >= MAX_SUBSCRIBERS:
        return HTMLResponse(status_code=429)

    queue: asyncio.Queue = asyncio.Queue()
    subscribers.append(queue)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=30)
                    yield f"data: {json.dumps(data)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            if queue in subscribers:
                subscribers.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream"
    )


@router.get("/ip-rules", response_class=HTMLResponse)
async def ip_rules_page(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(require_jwt)
):
    blacklist = db.query(IPRule).filter(IPRule.rule_type == "blacklist").all()
    whitelist = db.query(IPRule).filter(IPRule.rule_type == "whitelist").all()

    return templates.TemplateResponse("ip_rules.html", {
        "request": request,
        "blacklist": blacklist,
        "whitelist": whitelist,
    })


@router.post("/ip-rules/add")
async def add_ip_rule(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(require_jwt),
    ip_address: str = Form(...),
    rule_type: str = Form(...),
    reason: str = Form(""),
):
    # نتحقق إذا الـ IP موجود مسبقاً
    existing = db.query(IPRule).filter(IPRule.ip_address == ip_address).first()
    if existing:
        existing.rule_type = rule_type
        existing.reason = reason
        existing.active = True
    else:
        rule = IPRule(
            ip_address=ip_address,
            rule_type=rule_type,
            reason=reason,
            active=True
        )
        db.add(rule)

    db.commit()
    return RedirectResponse(url="/dashboard/ip-rules", status_code=302)


@router.post("/ip-rules/delete/{rule_id}")
async def delete_ip_rule(
    request: Request,
    rule_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_jwt),
):
    rule = db.query(IPRule).filter(IPRule.id == rule_id).first()
    if rule:
        db.delete(rule)
        db.commit()
    return RedirectResponse(url="/dashboard/ip-rules", status_code=302)


@router.post("/ip-rules/toggle/{rule_id}")
async def toggle_ip_rule(
    request: Request,
    rule_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_jwt),
):
    rule = db.query(IPRule).filter(IPRule.id == rule_id).first()
    if rule:
        rule.active = not rule.active
        db.commit()
    return RedirectResponse(url="/dashboard/ip-rules", status_code=302)