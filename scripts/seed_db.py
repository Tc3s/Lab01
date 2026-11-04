#!/usr/bin/env python3
"""
CLI Wrapper to Initialize Database and Seed Test Users
Location: scripts/seed_db.py
"""

import os
import sys

# Ensure repository root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.db.database import SessionLocal, init_db
from app.db.seed import seed_users


def main():
    print(f"Initializing database tables (project root: {PROJECT_ROOT})...")
    init_db()
    db = SessionLocal()
    try:
        print("Seeding default lab users...")
        users = seed_users(db)
        print(f"Successfully initialized and seeded {len(users)} users:")
        for username, user in users.items():
            print(f"  * Username: {username:12} | ID: {user.id} | Role: {user.role:7} | MFA: {user.mfa_enabled}")
        print("Database seeding completed successfully.")
    except Exception as e:
        print(f"Error seeding database: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
