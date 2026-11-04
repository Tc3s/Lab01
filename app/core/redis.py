"""
Redis Client and State Management Primitives
Provides connection pooling, anti-replay guards, session tracking, and bulk revocation.
Location: app/core/redis.py
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, Optional, Set
import redis.asyncio as aioredis
from redis.exceptions import RedisError

from app.core.config import settings

logger = logging.getLogger(__name__)

# Global client and connection pool references
_redis_pool: Optional[aioredis.ConnectionPool] = None
redis_client: Optional[aioredis.Redis] = None
_current_loop: Optional[Any] = None


async def init_redis_pool() -> aioredis.Redis:
    """Initialize Redis connection pool and verify connection."""
    global _redis_pool, redis_client, _current_loop
    _current_loop = asyncio.get_running_loop()
    _redis_pool = aioredis.ConnectionPool.from_url(
        settings.REDIS_URL,
        max_connections=settings.REDIS_MAX_CONNECTIONS,
        socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
        socket_connect_timeout=settings.REDIS_SOCKET_CONNECT_TIMEOUT,
        health_check_interval=settings.REDIS_HEALTH_CHECK_INTERVAL,
        decode_responses=True
    )
    redis_client = aioredis.Redis(connection_pool=_redis_pool)
    # Verify connection
    await redis_client.ping()
    logger.info("Redis connection pool initialized successfully.")
    return redis_client


async def close_redis_pool() -> None:
    """Gracefully close Redis client and connection pool."""
    global _redis_pool, redis_client, _current_loop
    if redis_client is not None:
        try:
            await redis_client.aclose()
        except Exception:
            pass
        redis_client = None
    if _redis_pool is not None:
        try:
            await _redis_pool.disconnect()
        except Exception:
            pass
        _redis_pool = None
    _current_loop = None
    logger.info("Redis connection pool closed.")


async def get_redis_client() -> aioredis.Redis:
    """Dependency injector / accessor for Redis client."""
    global _redis_pool, redis_client, _current_loop
    running_loop = asyncio.get_running_loop()
    if redis_client is None or _current_loop != running_loop:
        if redis_client is not None or _redis_pool is not None:
            await close_redis_pool()
        redis_client = await init_redis_pool()
    return redis_client



# ============================================================================
# Core Primitive 1: Anti-Replay Guard (R1.2, T2)
# ============================================================================

async def check_and_set_otp_replay(user_id: int, time_step: int, ttl: int = settings.OTP_REPLAY_TTL_SECONDS) -> bool:
    """
    Atomically checks and consumes a TOTP time step for a user.
    Uses: SET otp_replay:{user_id}:{time_step} "consumed" EX {ttl} NX

    Returns:
        True: If lock was acquired (OTP is fresh and first-time used).
        False: If key already exists (Replay attempt detected).
    """
    client = await get_redis_client()
    key = f"otp_replay:{user_id}:{time_step}"
    try:
        # In redis.asyncio with decode_responses=True:
        # Returns True if key was set, None if key already existed
        result = await client.set(key, "consumed", ex=ttl, nx=True)
        return bool(result)
    except RedisError as e:
        logger.error(f"Redis error during check_and_set_otp_replay for user {user_id}: {e}")
        raise


# ============================================================================
# Core Primitive 2: Session Storage & User Indexing (R1.3, R1.6, T4, T8)
# ============================================================================

async def store_session(session_id: str, data: Dict[str, Any], ttl: int = settings.SESSION_IDLE_TIMEOUT_SECONDS) -> None:
    """
    Stores session payload and indexes it under user_sessions:{user_id}.
    Automatically populates 'created_at' timestamp if not already present.
    Executed atomically via Redis pipeline transaction.
    """
    client = await get_redis_client()
    session_key = f"session:{session_id}"
    
    if "created_at" not in data:
        data["created_at"] = time.time()

    user_id = data.get("user_id")

    pipe = client.pipeline(transaction=True)
    pipe.set(session_key, json.dumps(data), ex=ttl)

    if user_id is not None:
        user_key = f"user_sessions:{user_id}"
        pipe.sadd(user_key, session_id)
        # Ensure user index set expires with absolute timeout to avoid orphan keys
        pipe.expire(user_key, settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS)

    await pipe.execute()


async def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves session data by session_id.
    Returns None if session does not exist, has expired, or exceeded absolute timeout.
    """
    client = await get_redis_client()
    session_key = f"session:{session_id}"
    try:
        raw_data = await client.get(session_key)
        if not raw_data:
            return None
        data = json.loads(raw_data)

        # Enforce absolute timeout defense-in-depth
        created_at = data.get("created_at")
        if created_at is not None:
            now = time.time()
            if (now - float(created_at)) >= settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS:
                logger.info(f"Session {session_id} exceeded absolute timeout; deleting.")
                user_id = data.get("user_id")
                pipe = client.pipeline(transaction=True)
                pipe.delete(session_key)
                if user_id is not None:
                    pipe.srem(f"user_sessions:{user_id}", session_id)
                await pipe.execute()
                return None

        return data
    except (json.JSONDecodeError, TypeError, RedisError) as e:
        logger.warning(f"Error retrieving session {session_id}: {e}")
        return None


async def touch_session(session_id: str, ttl: int = settings.SESSION_IDLE_TIMEOUT_SECONDS) -> bool:
    """
    Refreshes the TTL of an active session to implement rolling idle timeout,
    strictly capped by the session absolute timeout (SESSION_ABSOLUTE_TIMEOUT_SECONDS).
    Returns True if TTL was refreshed, False if session does not exist or absolute timeout reached.
    """
    client = await get_redis_client()
    session_key = f"session:{session_id}"
    try:
        raw_data = await client.get(session_key)
        if not raw_data:
            return False

        try:
            data = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            await client.delete(session_key)
            return False

        now = time.time()
        created_at = float(data.get("created_at", now))
        remaining = (created_at + settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS) - now
        user_id = data.get("user_id")

        if remaining <= 0:
            logger.info(f"Session {session_id} expired by absolute timeout ({remaining:.1f}s remaining).")
            pipe = client.pipeline(transaction=True)
            pipe.delete(session_key)
            if user_id is not None:
                pipe.srem(f"user_sessions:{user_id}", session_id)
            await pipe.execute()
            return False

        new_ttl = min(ttl, int(remaining))
        if new_ttl <= 0:
            logger.info(f"Session {session_id} remaining absolute TTL is 0; deleting.")
            pipe = client.pipeline(transaction=True)
            pipe.delete(session_key)
            if user_id is not None:
                pipe.srem(f"user_sessions:{user_id}", session_id)
            await pipe.execute()
            return False

        pipe = client.pipeline(transaction=True)
        pipe.expire(session_key, new_ttl)
        if user_id is not None:
            user_key = f"user_sessions:{user_id}"
            pipe.expire(user_key, settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS)

        results = await pipe.execute()
        return bool(results[0])
    except RedisError as e:
        logger.error(f"Redis error touching session {session_id}: {e}")
        return False


async def update_session(session_id: str, data: Dict[str, Any], ttl: Optional[int] = None) -> bool:
    """
    Updates the session data payload, preserving created_at and enforcing absolute timeout bounds.
    """
    client = await get_redis_client()
    session_key = f"session:{session_id}"
    try:
        raw_data = await client.get(session_key)
        if not raw_data:
            return False

        try:
            existing_data = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            existing_data = {}

        # Preserve created_at if not explicitly overwritten
        if "created_at" not in data and "created_at" in existing_data:
            data["created_at"] = existing_data["created_at"]
        elif "created_at" not in data:
            data["created_at"] = time.time()

        now = time.time()
        created_at = float(data.get("created_at", now))
        remaining = (created_at + settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS) - now
        user_id = data.get("user_id", existing_data.get("user_id"))

        if remaining <= 0:
            pipe = client.pipeline(transaction=True)
            pipe.delete(session_key)
            if user_id is not None:
                pipe.srem(f"user_sessions:{user_id}", session_id)
            await pipe.execute()
            return False

        if ttl is not None:
            effective_ttl = min(ttl, int(remaining))
        else:
            current_ttl = await client.ttl(session_key)
            if current_ttl > 0:
                effective_ttl = min(current_ttl, int(remaining))
            else:
                effective_ttl = int(remaining)

        if effective_ttl <= 0:
            pipe = client.pipeline(transaction=True)
            pipe.delete(session_key)
            if user_id is not None:
                pipe.srem(f"user_sessions:{user_id}", session_id)
            await pipe.execute()
            return False

        await client.set(session_key, json.dumps(data), ex=effective_ttl)
        return True
    except RedisError as e:
        logger.error(f"Redis error updating session {session_id}: {e}")
        return False


async def delete_session(session_id: str, user_id: Optional[int] = None) -> bool:
    """
    Deletes an individual session and removes it from the user's tracking set.
    """
    client = await get_redis_client()
    session_key = f"session:{session_id}"

    # If user_id not provided, look up before deletion
    if user_id is None:
        data = await get_session(session_id)
        if data:
            user_id = data.get("user_id")

    pipe = client.pipeline(transaction=True)
    pipe.delete(session_key)
    if user_id is not None:
        pipe.srem(f"user_sessions:{user_id}", session_id)

    results = await pipe.execute()
    # results[0] contains the number of deleted session keys (1 if found, 0 if not)
    return bool(results[0] > 0)


async def revoke_all_user_sessions(user_id: int) -> int:
    """
    Revokes all active sessions for a user across all devices/browsers.
    Retrieves all SIDs from user_sessions:{user_id}, deletes each session:{sid},
    and deletes the index set atomically.

    Returns:
        Number of sessions revoked.
    """
    client = await get_redis_client()
    user_key = f"user_sessions:{user_id}"

    try:
        sids: Set[str] = await client.smembers(user_key)
        if not sids:
            await client.delete(user_key)
            return 0

        keys_to_delete = [f"session:{sid}" for sid in sids]
        keys_to_delete.append(user_key)

        await client.delete(*keys_to_delete)
        logger.info(f"Revoked {len(sids)} active sessions for user {user_id}")
        return len(sids)
    except RedisError as e:
        logger.error(f"Redis error revoking all sessions for user {user_id}: {e}")
        raise
