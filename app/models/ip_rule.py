from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from app.database.session import Base
import enum


class RuleType(str, enum.Enum):
    blacklist = "blacklist"
    whitelist = "whitelist"


class IPRule(Base):
    __tablename__ = "ip_rules"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, nullable=False, unique=True)
    rule_type = Column(String, nullable=False)  # blacklist / whitelist
    reason = Column(String, nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())