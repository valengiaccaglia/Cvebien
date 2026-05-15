import re

from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models import Base

engine: AsyncEngine | None = None
async_session: sessionmaker | None = None


def get_database_url() -> URL:
    raw = settings.DATABASE_URL
    if not raw:
        raise RuntimeError("DATABASE_URL must be set before creating a database connection")

    # Parse components manually so special chars in the password ([ ] ñ etc.)
    # don't confuse SQLAlchemy's URL parser ([ is reserved for IPv6 literals).
    m = re.match(
        r"(?:postgresql|postgres)(?:\+\w+)?://([^:@]+):(.+)@([^:@/\[\]]+):(\d+)/(.+)$",
        raw,
    )
    if not m:
        raise RuntimeError(f"Could not parse DATABASE_URL. Expected format: postgresql+driver://user:pass@host:port/dbname")

    user, password, host, port, dbname = m.groups()
    return URL.create(
        "postgresql+asyncpg",
        username=user,
        password=password,
        host=host,
        port=int(port),
        database=dbname,
    )


def get_engine() -> AsyncEngine:
    global engine, async_session
    if engine is None:
        engine = create_async_engine(
            get_database_url(),
            future=True,
            echo=settings.DEBUG,
        )
        async_session = sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return engine


async def get_session() -> AsyncSession:
    if async_session is None:
        get_engine()

    async with async_session() as session:  # type: ignore[arg-type]
        yield session


async def init_db() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
