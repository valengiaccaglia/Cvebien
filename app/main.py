import time
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.crud import create_subscription, deactivate_subscription, get_subscription_by_token
from app.database import get_session, init_db
from app.schemas import SubscriptionCreate
from app.cve_client import fetch_cves_for_app, search_cpe
from app.email_service import send_subscription_confirmation
from app.worker import start_scheduler

limiter = Limiter(key_func=get_remote_address)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

app = FastAPI(
    title="CVE Notifications",
    description="CVE subscription and notification system",
    version="0.1.0",
    debug=settings.DEBUG,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_scheduler: AsyncIOScheduler | None = None

# In-memory cache for live NVD results — avoids hammering NVD on every card open
_live_cache: dict = {}
_CACHE_TTL = 900  # 15 minutes


@app.on_event("startup")
async def on_startup() -> None:
    global _scheduler
    try:
        await init_db()
    except Exception as e:
        import logging
        logging.warning(f"Database initialization failed: {e}. App will run without DB.")
    _scheduler = start_scheduler()


@app.on_event("shutdown")
async def on_shutdown() -> None:
    if _scheduler:
        _scheduler.shutdown(wait=False)


@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/cves", response_class=HTMLResponse)
async def browse_cves(request: Request, query: str | None = None):
    cves: list = []
    if query:
        try:
            cves = await fetch_cves_for_app(query, results=50)
        except Exception:
            cves = []
    return templates.TemplateResponse(
        "cves.html",
        {"request": request, "cves": cves, "query": query or ""},
    )


@app.post("/subscribe", response_class=HTMLResponse)
@limiter.limit("5/hour")
async def subscribe(
    request: Request,
    email: str = Form(...),
    app_name: str = Form(...),
    severities: list[str] | None = Form(default=None),
    session: AsyncSession = Depends(get_session),
):
    if not severities:
        severities = ["critical"]

    payload = SubscriptionCreate(email=email, app_name=app_name, severities=severities)
    subscription = await create_subscription(session, payload)

    try:
        await send_subscription_confirmation(
            subscription.email, subscription.app_name,
            subscription.severities, subscription.unsubscribe_token,
        )
    except Exception:
        pass

    return templates.TemplateResponse(
        "subscribe_success.html",
        {
            "request": request,
            "email": subscription.email,
            "app_name": subscription.app_name,
            "severities": ", ".join(subscription.severities),
        },
    )


@app.get("/unsubscribe/{token}", response_class=HTMLResponse)
async def unsubscribe(request: Request, token: str, session: AsyncSession = Depends(get_session)):
    subscription = await get_subscription_by_token(session, token)
    if subscription is None:
        raise HTTPException(status_code=404, detail="Subscription not found")

    await deactivate_subscription(session, subscription)
    return templates.TemplateResponse(
        "unsubscribe_success.html",
        {"request": request, "email": subscription.email, "app_name": subscription.app_name},
    )


@app.get("/api/cves")
async def api_cves(app: str | None = None):
    if not app:
        return []
    key = app.lower()
    now = time.monotonic()
    cached = _live_cache.get(key)
    if cached and (now - cached[0]) < _CACHE_TTL:
        return cached[1]
    try:
        cves = await fetch_cves_for_app(app, results=100)
    except Exception:
        cves = []
    _live_cache[key] = (now, cves)
    return cves


@app.get("/api/search-apps")
async def api_search_apps(q: str = ""):
    if len(q) < 2:
        return []
    try:
        return await search_cpe(q)
    except Exception:
        return []


@app.post("/api/subscribe")
@limiter.limit("5/hour")
async def api_subscribe(
    request: Request,
    payload: SubscriptionCreate,
    session: AsyncSession = Depends(get_session),
):
    subscription = await create_subscription(session, payload)

    try:
        await send_subscription_confirmation(
            subscription.email, subscription.app_name,
            subscription.severities, subscription.unsubscribe_token,
        )
    except Exception:
        pass

    return {
        "ok": True,
        "email": subscription.email,
        "app_name": subscription.app_name,
        "severities": subscription.severities,
        "unsubscribe_token": subscription.unsubscribe_token,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "app": "CVE Notifications"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=settings.DEBUG,
    )
