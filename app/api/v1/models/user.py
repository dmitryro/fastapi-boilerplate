from sqlalchemy import Column, Integer, String, ForeignKey, Text, TIMESTAMP, func
from sqlalchemy.orm import relationship
from app.core.db import Base

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first = Column(Text, nullable=False)
    last = Column(Text, nullable=False)
    username = Column(Text, nullable=False, unique=True)
    email = Column(Text, nullable=False, unique=True)
    password = Column(Text, nullable=False)  # store hashed password here
    phone = Column(Text, nullable=True)
    role_id = Column(Integer, ForeignKey("roles.id", onupdate="CASCADE", ondelete="RESTRICT"), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    role = relationship("Role", back_populates="users")

    def verify_password(self, plain_password: str) -> bool:
        """Verify plain password against the stored hashed password."""
        try:
            return ph.verify(self.password, plain_password)
        except VerifyMismatchError:
            return False

    def set_password(self, plain_password: str):
        """Hash and set password."""
        self.password = ph.hash(plain_password)

