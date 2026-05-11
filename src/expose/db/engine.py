"""Async SQLAlchemy engine + session factory for Postgres.

State is externalized per ADR-003: connection string comes from environment;
the application has no Postgres-specific operational logic.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


class DatabaseSettings(BaseSettings):
    """Database connection configuration (12-factor — env-driven per ADR-003)."""

    model_config = SettingsConfigDict(
        env_prefix="EXPOSE_DB_",
        env_file=None,
        case_sensitive=False,
        extra="forbid",
    )

    host: str = "localhost"
    port: int = Field(default=5432, ge=1, le=65535)
    database: str = "expose"
    user: str = "expose"
    password: SecretStr = SecretStr("")
    sslmode: str = "prefer"

    pool_size: int = Field(default=20, ge=1)
    max_overflow: int = Field(default=10, ge=0)
    pool_timeout: int = Field(default=5, ge=1)
    pool_pre_ping: bool = True
    echo: bool = False

    def dsn(self) -> str:
        """asyncpg DSN; password is interpolated only at engine-build time."""
        pw = self.password.get_secret_value()
        # asyncpg dialect — connection-pool managed by SQLAlchemy.
        return (
            f"postgresql+asyncpg://{self.user}:{pw}"
            f"@{self.host}:{self.port}/{self.database}"
        )


def create_async_engine_from_settings(settings: DatabaseSettings) -> AsyncEngine:
    """Build an asyncpg-backed AsyncEngine from settings."""
    return create_async_engine(
        settings.dsn(),
        pool_size=settings.pool_size,
        max_overflow=settings.max_overflow,
        pool_timeout=settings.pool_timeout,
        pool_pre_ping=settings.pool_pre_ping,
        echo=settings.echo,
        connect_args={"ssl": settings.sslmode if settings.sslmode != "disable" else None},
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Standard async session factory — no autoflush, expire_on_commit off for
    artifact-generation paths that need read-after-write within a transaction."""
    return async_sessionmaker(
        bind=engine,
        expire_on_commit=False,
        autoflush=False,
        class_=AsyncSession,
    )


@asynccontextmanager
async def session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Context manager wrapping a session in begin/commit/rollback semantics."""
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
