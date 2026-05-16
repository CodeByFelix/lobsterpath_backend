from typing import AsyncGenerator
from sqlmodel import SQLModel, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from src.settings import settings

import ssl


class DbConnectionError (Exception):
    pass


ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False   # important for Supabase pooled endpoints
ssl_context.verify_mode = ssl.CERT_NONE

DB_URL = settings.async_db_url

engine = create_async_engine (
    url=DB_URL, 
    echo=False, 
    future=True, 
    connect_args={"ssl": ssl_context},
    pool_pre_ping=True,
    pool_recycle=3600,
    pool_size=5,
    max_overflow=10,
    pool_timeout=30,
)

async_session_local = sessionmaker (
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False
)

USER_DATA = "user_data"


async def init_db () -> None:
    try:
        async with engine.begin () as conn:
            await conn.execute (text (f"CREATE SCHEMA IF NOT EXISTS {USER_DATA}"))
            await conn.run_sync(SQLModel.metadata.create_all)
    except Exception as e:
        raise DbConnectionError (f"Error connecting to DB {e}") from e


async def get_session () -> AsyncGenerator [AsyncSession, None]:
    async with async_session_local () as session:
        yield session