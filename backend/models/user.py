"""
models/user.py — User model for JWT authentication.

MVP: single admin user loaded from environment variables. The comment below
marks exactly where a database-backed user model replaces this pattern.

Production upgrade path:
  - Replace _load_admin_user() with a SQLAlchemy or Tortoise ORM model
  - Add user table with: id, username, password_hash, roles, created_at
  - Update get_user() to query the database
"""

from pydantic import BaseModel


class User(BaseModel):
    username: str
    is_admin: bool = True
