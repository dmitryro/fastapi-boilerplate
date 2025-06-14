from sqlalchemy import Column, Integer, String, TIMESTAMP, func, Text, ARRAY
from sqlalchemy.orm import relationship
from app.core.db import Base

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    permissions = Column(ARRAY(Text), nullable=False, default=[])
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

    users = relationship("User", back_populates="role")
