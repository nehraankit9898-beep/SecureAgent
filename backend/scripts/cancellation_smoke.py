import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.execution_registry import ExecutionRegistry


async def main():
    registry = ExecutionRegistry()
    started = asyncio.Event()
    stopped = asyncio.Event()

    async def worker():
        await registry.register("active")
        try:
            started.set()
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            stopped.set()
        finally:
            await registry.unregister("active")

    task = asyncio.create_task(worker())
    await started.wait()
    assert await registry.request_cancel("active") is True
    await asyncio.wait_for(task, 2)
    assert stopped.is_set()

    # A cancel arriving just before registration must also stop the worker.
    assert await registry.request_cancel("race") is False

    async def late_worker():
        try:
            await registry.register("race")
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            return "cancelled"
        finally:
            await registry.unregister("race")

    assert await asyncio.wait_for(asyncio.create_task(late_worker()), 2) == "cancelled"
    print("CANCELLATION_SMOKE_PASS checks=2")


asyncio.run(main())
