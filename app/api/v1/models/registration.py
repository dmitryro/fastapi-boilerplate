from sqlalchemy import Column, Integer, String, ForeignKey, TIMESTAMP
from sqlalchemy.sql import func
from app.core.db import Base 

class Registration(Base):
    __tablename__ = "registrations"

    id = Column(Integer, primary_key=True, index=True)
    first = Column(String(255), nullable=False)
    last = Column(String(255), nullable=False)
    username = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    phone = Column(String(20), nullable=True)
    role_id = Column(Integer, ForeignKey("roles.id", onupdate="CASCADE", ondelete="RESTRICT"), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp(), nullable=True)

