import asyncio
import re
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.cve_client import _nvd_sleep, build_cve_record, fetch_recent_cve_ids
from app import database
from app.email_service import send_cve_alert
from app.models import ProcessedCve, Subscription


def _normalize_text(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _build_cve_match_text(cve: dict) -> str:
    parts = [cve.get("description", "")]
    parts.extend(cve.get("affected_vendors", []) or [])
    parts.extend(cve.get("affected_products", []) or [])
    parts.extend(cve.get("affected_packages", []) or [])
    parts.extend(cve.get("affected_ecosystems", []) or [])
    parts.extend(cve.get("affected_keywords", []) or [])
    return _normalize_text(" ".join(str(p) for p in parts if p))


def _match_app_name(app_name: str, cve: dict) -> bool:
    if not app_name or not cve:
        return False
    query = _normalize_text(app_name)
    if not query:
        return False
    cve_text = _build_cve_match_text(cve)
    if query in cve_text:
        return True
    query_parts = [p for p in query.split() if p]
    cve_tokens = set(cve_text.split())
    return bool(query_parts) and all(p in cve_tokens for p in query_parts)


async def _get_matching_subscriptions(session: AsyncSession, cve: dict) -> list[Subscription]:
    result = await session.execute(select(Subscription).where(Subscription.active == True))
    matches = []
    for sub in result.scalars().all():
        if sub.severities and cve["severity"].lower() not in [s.lower() for s in sub.severities]:
            continue
        if _match_app_name(sub.app_name, cve):
            matches.append(sub)
    return matches


async def process_new_cves() -> None:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=1)

    cve_ids = await fetch_recent_cve_ids(window_start, now)
    if not cve_ids:
        return

    if database.async_session is None:
        return

    async with database.async_session() as session:
        for cve_id in cve_ids:
            # Skip if already processed
            if await session.get(ProcessedCve, cve_id):
                continue

            try:
                cve_record = await build_cve_record(cve_id)
            except Exception:
                await asyncio.sleep(_nvd_sleep())
                continue

            subscriptions = await _get_matching_subscriptions(session, cve_record)
            for subscription in subscriptions:
                await send_cve_alert(
                    subscription.email,
                    {"unsubscribe_token": subscription.unsubscribe_token, "app_name": subscription.app_name},
                    cve_record,
                )

            session.add(ProcessedCve(cve_id=cve_id))
            await session.commit()
            await asyncio.sleep(_nvd_sleep())


def start_scheduler() -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()
    scheduler.add_job(process_new_cves, "interval", hours=1, next_run_time=datetime.now(timezone.utc))
    scheduler.start()
    return scheduler
