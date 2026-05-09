"""
Alembic environment configuration.
Reads the database URL from the environment and uses the app's SQLAlchemy Base
metadata for autogenerate support.
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Ensure the backend directory is on sys.path so models can be imported.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Import settings first so the .env file is loaded via pydantic-settings,
# then import Base and models so Alembic can discover all mapped tables.
from config import settings  # noqa: E402
from database import Base  # noqa: E402
import models.user  # noqa: E402, F401 — registers models on Base.metadata
import models.scan  # noqa: E402, F401 — registers scan models on Base.metadata

# this is the Alembic Config object, which provides access to the .ini file.
config = context.config

# Always override the placeholder URL with the real DATABASE_URL from .env.
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine, though an
    Engine is acceptable here as well. By skipping the Engine creation we don't
    even need a DBAPI to be available.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.

    In this scenario we need to create an Engine and associate a connection
    with the context.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
