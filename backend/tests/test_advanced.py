import hashlib
from pathlib import Path

import pytest

from app.coding import InspectProject, ReplaceInFile, SearchCode
from app.memory import MemoryStore
from app.models import Permission, ScheduleCreate
from app.security import RateLimiter, redact
from app.tools.base import Registry


@pytest.mark.asyncio
async def test_coding_tools_are_workspace_confined_and_stale_safe(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", "utf-8")
    registry = Registry()
    registry.add(InspectProject(tmp_path))
    registry.add(SearchCode(tmp_path))
    registry.add(ReplaceInFile(tmp_path))
    tree = await registry.execute("inspect_project", {"path": "."}, {Permission.READ})
    assert tree.success and tree.output["files"][0]["path"] == "app.py"
    found = await registry.execute("search_code", {"query": "value"}, {Permission.READ})
    assert found.output["matches"][0]["line"] == 1
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    changed = await registry.execute("replace_in_file", {"path": "app.py", "old_text": "value = 1", "new_text": "value = 2", "expected_sha256": digest}, {Permission.WRITE})
    assert changed.success and source.read_text() == "value = 2\n"
    stale = await registry.execute("replace_in_file", {"path": "app.py", "old_text": "value = 2", "new_text": "value = 3", "expected_sha256": digest}, {Permission.WRITE})
    assert stale.success is False


@pytest.mark.asyncio
async def test_schedule_validation_and_persistence(tmp_path: Path):
    store = MemoryStore(tmp_path / "state.db")
    await store.init()
    with pytest.raises(ValueError):
        await store.create_schedule(ScheduleCreate(name="bad", prompt="x", kind="interval"))
    item = await store.create_schedule(ScheduleCreate(name="daily", prompt="summarize", kind="interval", interval_seconds=3600))
    assert item["permissions"] == []
    assert (await store.schedules())[0]["id"] == item["id"]


def test_security_helpers():
    assert "secret-value" not in redact("api_key=secret-value")
    limiter = RateLimiter(2)
    assert limiter.allow("x") and limiter.allow("x") and not limiter.allow("x")
