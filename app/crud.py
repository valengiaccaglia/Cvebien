from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Subscription
from app.schemas import SubscriptionCreate


async def create_subscription(session: AsyncSession, payload: SubscriptionCreate) -> Subscription:
    subscription = Subscription(
        email=payload.email,
        app_name=payload.app_name.strip(),
        severities=[severity.lower() for severity in payload.severities],
    )
    session.add(subscription)
    await session.commit()
    await session.refresh(subscription)
    return subscription


async def get_subscription_by_token(session: AsyncSession, token: str) -> Subscription | None:
    result = await session.execute(select(Subscription).where(Subscription.unsubscribe_token == token))
    return result.scalars().first()


async def deactivate_subscription(session: AsyncSession, subscription: Subscription) -> Subscription:
    subscription.active = False
    await session.commit()
    await session.refresh(subscription)
    return subscription
