"""
Database Seeder for Pre-configured Lab Users (CSKH, KETOAN, ADMIN)
Location: app/db/seed.py
"""

import sys
from typing import Dict
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.db.database import SessionLocal, init_db
from app.db.models import User, UserRole

SEED_USERS = [
    {
        "username": "cskh_user",
        "raw_password": "Password123!",
        "role": UserRole.CSKH.value,
        "totp_secret": "JBSWY3DPEHPK3PXP",  # Valid RFC 3548 Base32 secret
        "mfa_enabled": True
    },
    {
        "username": "ketoan_user",
        "raw_password": "Password123!",
        "role": UserRole.KETOAN.value,
        "totp_secret": "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",  # Valid RFC 3548 Base32 secret
        "mfa_enabled": True
    },
    {
        "username": "admin_user",
        "raw_password": "AdminPassword123!",
        "role": UserRole.ADMIN.value,
        "totp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",  # Valid RFC 3548 Base32 secret
        "mfa_enabled": True
    }
]


def seed_users(db: Session) -> Dict[str, User]:
    """Idempotently seeds required users into the database."""
    seeded = {}
    for user_info in SEED_USERS:
        user = db.query(User).filter(User.username == user_info["username"]).first()
        p_hash = hash_password(user_info["raw_password"])
        if not user:
            user = User(
                username=user_info["username"],
                password_hash=p_hash,
                role=user_info["role"],
                totp_secret=user_info["totp_secret"],
                mfa_enabled=user_info["mfa_enabled"]
            )
            db.add(user)
        else:
            user.password_hash = p_hash
            user.role = user_info["role"]
            user.totp_secret = user_info["totp_secret"]
            user.mfa_enabled = user_info["mfa_enabled"]
        db.flush()
        seeded[user.username] = user
    db.commit()
    return seeded


def main():
    init_db()
    db = SessionLocal()
    try:
        users = seed_users(db)
        print(f"Successfully seeded {len(users)} users:")
        for username, u in users.items():
            print(f" - {username} (ID: {u.id}, Role: {u.role})")
    finally:
        db.close()


if __name__ == "__main__":
    main()
