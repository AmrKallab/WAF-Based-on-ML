from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class RequestLogSchema(BaseModel):
    id: int

    # معلومات الـ Request
    ip_address: str
    method: str
    url: str
    host: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    body: Optional[str] = None

    # نتيجة الـ WAF
    is_malicious: bool
    attack_type: Optional[str] = None
    ml_score: Optional[float] = None
    blocked: bool

    # التوقيت
    timestamp: datetime

    class Config:
        from_attributes = True