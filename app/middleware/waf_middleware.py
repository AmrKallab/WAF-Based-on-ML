import json
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from sqlalchemy.orm import Session
from app.detection.engine import analyze
from app.models.request_log import RequestLog
from app.models.ip_rule import IPRule
from app.database.session import SessionLocal
from app.dashboard.router import broadcast
from app.core.config import settings


EXCLUDED_PATHS = [
    "/dashboard",
    "/static",
    "/favicon.ico",
    "/api/stats",
    "/api/requests",
    "/.well-known",
    "/login.php",
    "/setup.php",
    "/dvwa",
]


def check_ip_rule(db: Session, ip: str) -> dict:
    rule = db.query(IPRule).filter(
        IPRule.ip_address == ip,
        IPRule.active == True
    ).first()

    if not rule:
        return {"action": "none"}

    return {"action": rule.rule_type, "reason": rule.reason}


class WAFMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        path = request.url.path
        print(f"MIDDLEWARE: {path}")

        # 1. تحقق من المسار المستثنى
        path = request.url.path
        for excluded in EXCLUDED_PATHS:
            if path.startswith(excluded):
                return await call_next(request)

        # 2. فحص حجم الـ request
        content_length = request.headers.get("content-length")
        content_type = request.headers.get("content-type", "")
        
        if content_length:
            # لو بيبعت ملف أو صورة → 10MB
            if "multipart/form-data" in content_type or "image/" in content_type:
                max_size = 10 * 1024 * 1024  # 10MB
            else:
                max_size = settings.MAX_REQUEST_SIZE  # 1MB
        
            if int(content_length) > max_size:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": "Request too large",
                        "max_size": max_size
                    }
                )

        # 3. فحص الـ IP
        db_check: Session = SessionLocal()
        try:
            ip_rule = check_ip_rule(db_check, request.client.host)
        finally:
            db_check.close()

        if ip_rule["action"] == "blacklist":
            return JSONResponse(
                status_code=403,
                content={
                    "error": "IP is blocked",
                    "reason": ip_rule.get("reason", "")
                }
            )

        if ip_rule["action"] == "whitelist":
            # نسجله بقاعدة البيانات
            body = await request.body()
            try:
                body_text = body.decode("utf-8")
            except Exception:
                body_text = ""
        
            db_white: Session = SessionLocal()
            try:
                log = RequestLog(
                    ip_address=request.client.host,
                    method=request.method,
                    url=str(request.url),
                    host=request.headers.get("host", ""),
                    content_type=request.headers.get("content-type", ""),
                    content_length=int(request.headers.get("content-length", 0) or 0),
                    body=body_text,
                    is_malicious=False,
                    attack_type=None,
                    ml_score=None,
                    blocked=False,
                )
                db_white.add(log)
                db_white.commit()
                db_white.refresh(log)
        
                await broadcast({
                    "id": log.id,
                    "ip_address": log.ip_address,
                    "method": log.method,
                    "url": log.url,
                    "is_malicious": False,
                    "attack_type": None,
                    "ml_score": None,
                    "blocked": False,
                    "timestamp": str(log.timestamp),
                })
            finally:
                db_white.close()
        
            return await call_next(request)

        # 4. نقرأ الـ body
        body = await request.body()
        try:
            body_text = body.decode("utf-8")
        except Exception:
            body_text = ""

        # 5. نجهز بيانات الـ request
        request_data = {
            "ip_address": request.client.host,
            "method": request.method,
            "url": str(request.url),
            "host": request.headers.get("host", ""),
            "content_type": request.headers.get("content-type", ""),
            "content_length": request.headers.get("content-length", 0),
            "accept": request.headers.get("accept", ""),
            "origin": request.headers.get("origin", ""),
            "referer": request.headers.get("referer", ""),
            "body": body_text,
            "accept-encoding": request.headers.get("accept-encoding", ""),
            "cache-control": request.headers.get("cache-control", ""),
            "accept-language": request.headers.get("accept-language", ""),
            "cookie": request.headers.get("cookie", ""),
            "user-agent": request.headers.get("user-agent", ""),
            "accept-charset": request.headers.get("accept-charset", ""),
            "pragma": request.headers.get("pragma", ""),
            "connection": request.headers.get("connection", ""),
        }

        # 6. نحلل الـ request
        try:
            result = await analyze(request_data)
            print(f"RESULT: {result}")
        except Exception as e:
            return await call_next(request)

        # 7. نسجل في قاعدة البيانات
        db: Session = SessionLocal()
        try:
            log = RequestLog(
                ip_address=request_data["ip_address"],
                method=request_data["method"],
                url=request_data["url"],
                host=request_data["host"],
                content_type=request_data["content_type"],
                content_length=int(request_data["content_length"] or 0),
                body=body_text,
                is_malicious=result["is_malicious"],
                attack_type=result.get("attack_type"),
                ml_score=result.get("ml_score"),
                blocked=result["blocked"],
            )
            db.add(log)
            db.commit()
            db.refresh(log)

            # لو blocked → نضيف الـ IP للـ blacklist تلقائياً
            if result["blocked"]:
                existing = db.query(IPRule).filter(
                    IPRule.ip_address == request.client.host
                ).first()

                if not existing:
                    ip_rule_entry = IPRule(
                        ip_address=request.client.host,
                        rule_type="blacklist",
                        reason=f"Auto-blocked: {result.get('attack_type', 'Unknown')}",
                        active=True
                    )
                    db.add(ip_rule_entry)
                    db.commit()

            await broadcast({
                "id": log.id,
                "ip_address": log.ip_address,
                "method": log.method,
                "url": log.url,
                "is_malicious": log.is_malicious,
                "attack_type": log.attack_type,
                "ml_score": log.ml_score,
                "blocked": log.blocked,
                "timestamp": str(log.timestamp),
            })

        except Exception as e:
            print(f"ERROR: {e}")
        finally:
            db.close()

        # 8. لو blocked → نرجع 403
        if ip_rule["action"] == "blacklist":
            db_bl: Session = SessionLocal()
            try:
                log = RequestLog(
                    ip_address=request.client.host,
                    method=request.method,
                    url=str(request.url),
                    host=request.headers.get("host", ""),
                    content_type=request.headers.get("content-type", ""),
                    content_length=int(request.headers.get("content-length", 0) or 0),
                    body="",
                    is_malicious=True,
                    attack_type="Blacklisted IP",
                    ml_score=None,
                    blocked=True,
                )
                db_bl.add(log)
                db_bl.commit()
                db_bl.refresh(log)
                print(f"IP RULE ACTION: {ip_rule}")
        
                await broadcast({
                    "id": log.id,
                    "ip_address": log.ip_address,
                    "method": log.method,
                    "url": log.url,
                    "is_malicious": True,
                    "attack_type": "Blacklisted IP",
                    "ml_score": None,
                    "blocked": True,
                    "timestamp": str(log.timestamp),
                })
            finally:
                db_bl.close()
        
            return JSONResponse(
                status_code=403,
                content={
                    "error": "IP is blocked",
                    "reason": ip_rule.get("reason", "")
                }
            )

        # 9. لو آمن → نكمل
        return await call_next(request)