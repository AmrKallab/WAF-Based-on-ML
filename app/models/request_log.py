from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.sql import func
from app.database.session import Base


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True)
    
    # معلومات الـ Request
    ip_address = Column(String, nullable=False)
    method = Column(String, nullable=False)        # GET, POST...
    url = Column(String, nullable=False)
    host = Column(String, nullable=True)
    content_type = Column(String, nullable=True)
    content_length = Column(Integer, nullable=True)
    body = Column(String, nullable=True)

    # نتيجة الـ WAF
    is_malicious = Column(Boolean, default=False)
    attack_type = Column(String, nullable=True)    # SQLi, XSS, ...
    ml_score = Column(Float, nullable=True)        # 0.0 - 1.0
    blocked = Column(Boolean, default=False)

    # التوقيت
    timestamp = Column(DateTime, server_default=func.now())