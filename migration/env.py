import asyncio
from logging.config import fileConfig
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context

# 1. IMPORT YOUR PROJECT SETTINGS AND MODELS
from sqlmodel import SQLModel
from src.model import *  # Loads all your tables
from src.settings import settings
from src.database import USER_DATA

# Interpret the config file for Python logging.
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# 2. SET TARGET METADATA
target_metadata = SQLModel.metadata

def include_object(object, name, type_, reflected, compare_to):
    """Only include objects from the 'user_data' schema."""
    if type_ == "table":
        return object.schema == USER_DATA
    return True

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = settings.async_db_url
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
        include_object=include_object, # Filter schemas
        version_table_schema=USER_DATA,
    )

    with context.begin_transaction():
        context.run_migrations()

def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection, 
        target_metadata=target_metadata,
        include_schemas=True,
        include_object=include_object, # Filter schemas
        version_table_schema=USER_DATA,
    )

    with context.begin_transaction():
        context.run_migrations()

async def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    # We create the engine directly using your settings
    connectable = create_async_engine(
        url=settings.async_db_url,
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        # Run migrations within a sync context as required by Alembic
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()

if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
