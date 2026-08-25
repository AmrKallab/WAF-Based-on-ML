from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.session import get_db
from app.models.request_log import RequestLog
from app.schemas.request_log import RequestLogSchema
from typing import List

router = APIRouter()


@router.get("/requests", response_model=List[RequestLogSchema])
async def get_requests(
    limit: int = 50,
    skip: int = 0,
    db: Session = Depends(get_db)
):
    logs = db.query(RequestLog)\
                .order_by(desc(RequestLog.timestamp))\
                .offset(skip)\
                .limit(limit)\
                .all()
    return logs


@router.get("/requests/{request_id}", response_model=RequestLogSchema)
async def get_request(request_id: int, db: Session = Depends(get_db)):
    log = db.query(RequestLog).filter(RequestLog.id == request_id).first()
    return log


@router.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    total = db.query(RequestLog).count()
    malicious = db.query(RequestLog)\
                    .filter(RequestLog.is_malicious == True)\
                    .count()
    blocked = db.query(RequestLog)\
                .filter(RequestLog.blocked == True)\
                .count()

    # عدد كل نوع هجوم
    from sqlalchemy import func
    attack_types = db.query(
        RequestLog.attack_type,
        func.count(RequestLog.attack_type).label("count")
    ).filter(
        RequestLog.attack_type != None
    ).group_by(
        RequestLog.attack_type
    ).all()

    return {
        "total_requests": total,
        "malicious_requests": malicious,
        "blocked_requests": blocked,
        "safe_requests": total - malicious,
        "attack_types": {a.attack_type: a.count for a in attack_types}
    }