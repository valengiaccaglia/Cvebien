import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, String, func
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import declarative_base


Base = declarative_base()


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(320), nullable=False)
    app_name = Column(String(256), nullable=False)
    severities = Column(ARRAY(String), nullable=False, default=["critical"])
    active = Column(Boolean, nullable=False, default=True)
    unsubscribe_token = Column(String(36), nullable=False, unique=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class ProcessedCve(Base):
    __tablename__ = "processed_cves"

    cve_id = Column(String(32), primary_key=True)
    processed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
