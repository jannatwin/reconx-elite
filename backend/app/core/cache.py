import json
import logging
from typing import Any, Optional

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from app.core.config import settings

logger = logging.getLogger(__name__)

_redis_client: Optional[aioredis.Redis] = None


def get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


def build_cache_key(user_id: int, resource: str, params: str = "") -> str:
    """Build a user-scoped cache key."""
    return f"reconx:{user_id}:{resource}:{params}"


async def get_cached(key: str) -> Optional[Any]:
    try:
        value = await get_redis().get(key)
        if value is None:
            return None
        return json.loads(value)
    except RedisError as e:
        logger.warning("Redis get failed for key %s: %s", key, e)
        return None


async def set_cached(key: str, value: Any, ttl: int = None) -> None:
    if ttl is None:
        ttl = settings.redis_cache_ttl
    try:
        await get_redis().setex(key, ttl, json.dumps(value))
    except RedisError as e:
        logger.warning("Redis set failed for key %s: %s", key, e)


async def invalidate(key: str) -> None:
    try:
        await get_redis().delete(key)
    except RedisError as e:
        logger.warning("Redis delete failed for key %s: %s", key, e)


async def invalidate_prefix(prefix: str) -> None:
    try:
        redis = get_redis()
        keys = [key async for key in redis.scan_iter(match=f"{prefix}*")]
        if keys:
            await redis.delete(*keys)
    except RedisError as e:
        logger.warning("Redis delete failed for prefix %s: %s", prefix, e)
