"""Request-local task cancellation with a process-wide active-task registry.

The database remains the durable source of task status.  This registry only
owns live asyncio task handles, so a cancel request can stop work that is
currently executing instead of merely changing the persisted status.
"""
from __future__ import annotations

import asyncio


class ExecutionRegistry:
    def __init__(self) -> None:
        self._active: dict[str, asyncio.Task] = {}
        self._cancel_requested: set[str] = set()
        self._lock = asyncio.Lock()

    async def register(self, item_id: str, task: asyncio.Task | None = None) -> None:
        current = task or asyncio.current_task()
        if current is None:
            raise RuntimeError("execution must run inside an asyncio task")
        async with self._lock:
            existing = self._active.get(item_id)
            if existing is not None and existing is not current and not existing.done():
                raise RuntimeError("task execution is already active")
            self._active[item_id] = current
            cancel_now = item_id in self._cancel_requested
        if cancel_now:
            current.cancel()

    async def request_cancel(self, item_id: str) -> bool:
        async with self._lock:
            self._cancel_requested.add(item_id)
            task = self._active.get(item_id)
        if task is not None and not task.done():
            task.cancel()
            return True
        return False

    async def is_cancel_requested(self, item_id: str) -> bool:
        async with self._lock:
            return item_id in self._cancel_requested

    def active_ids(self) -> list[str]:
        """IDs of tasks with live asyncio executions (EMERGENCY STOP support)."""
        return [item_id for item_id, task in list(self._active.items()) if not task.done()]

    async def checkpoint(self, item_id: str) -> None:
        if await self.is_cancel_requested(item_id):
            raise asyncio.CancelledError

    async def unregister(self, item_id: str) -> None:
        current = asyncio.current_task()
        async with self._lock:
            if self._active.get(item_id) is current:
                self._active.pop(item_id, None)
            self._cancel_requested.discard(item_id)

