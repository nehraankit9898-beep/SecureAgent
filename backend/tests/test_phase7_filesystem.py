"""Phase 7 — Secure Filesystem Agent acceptance and regression tests.

Acceptance gate coverage:
  * path traversal tests pass (absolute, .., symlink escape, hardlink)
  * protected paths cannot be modified without the explicit policy override
  * delete is reversible (recycle -> restore round trip)
plus unit coverage for list/inspect/read/create/copy/move/rename, atomic
writes with backups, size limits and binary handling, and tool-level checks
that no shell is used for ordinary file operations.
"""
import hashlib
import os
import stat
from pathlib import Path

import pytest

from app.tools.builtins import (
    BackupFileTool,
    CopyFile,
    CreateDirectory,
    DeleteFile,
    InspectFile,
    ListFiles,
    ListTrash,
    MovePath,
    PurgeTrash,
    ReadFile,
    RecycleFile,
    RenamePath,
    RestoreRecycled,
    WriteFile,
)
from app.workspace import WorkspacePolicy


@pytest.fixture()
def policy(tmp_path: Path) -> WorkspacePolicy:
    return WorkspacePolicy(
        tmp_path / "ws",
        max_read_bytes=10_000,
        max_write_bytes=5_000,
        protected_paths=["memory", "knowledge"],
    )


# --------------------------------------------------------------------- #
# Path normalization / traversal (negative security)                    #
# --------------------------------------------------------------------- #

@pytest.mark.parametrize("bad", ["/etc/passwd", "..", "../escape", "a/../../b", "C:\\Windows\\x", "\\\\server\\share"])
def test_traversal_and_absolute_paths_fail_closed(policy, bad):
    with pytest.raises((PermissionError, ValueError)):
        policy.resolve(bad)


def test_parent_directory_outside_root_rejected(policy):
    with pytest.raises((PermissionError, ValueError)):
        policy.atomic_write("../outside.txt", "x")


def test_symlink_escape_is_blocked(policy):
    outside = policy.root.parent / "outside-secret.txt"
    outside.write_text("secret")
    link = policy.root / "link.txt"
    link.symlink_to(outside)
    with pytest.raises(PermissionError):
        policy.read_bytes("link.txt")
    with pytest.raises(PermissionError):
        policy.inspect("link.txt")


def test_hardlinked_file_refused_for_copy(policy):
    src = policy.root / "src.txt"
    src.write_text("data")
    twin = policy.root / "twin.txt"
    os.link(src, twin)
    with pytest.raises(PermissionError):
        policy.copy_file("src.txt", "copy.txt")


def test_sensitive_names_still_blocked(policy):
    with pytest.raises(PermissionError):
        policy.resolve(".ssh/id_rsa")
    with pytest.raises(PermissionError):
        policy.atomic_write("sub/.env", "TOKEN=1")


# --------------------------------------------------------------------- #
# Protected paths                                                       #
# --------------------------------------------------------------------- #

def test_protected_reads_allowed_writes_blocked(policy):
    policy.atomic_write("memory/notes.txt", "hello")
    data, _ = policy.read_bytes("memory/notes.txt")
    assert data == b"hello"
    with pytest.raises(PermissionError):
        policy.atomic_write("memory/notes.txt", "evil", overwrite=True)
    with pytest.raises(PermissionError):
        policy.delete("memory/notes.txt", "DELETE")
    with pytest.raises(PermissionError):
        policy.move_path("memory/notes.txt", "elsewhere.txt")
    with pytest.raises(PermissionError):
        policy.recycle_file("memory/notes.txt", "DELETE")


def test_protected_override_token_allows_explicit_mutation(policy):
    policy.atomic_write("memory/notes.txt", "hello")
    policy.atomic_write("memory/notes.txt", "updated", overwrite=True, allow_protected=True)
    assert policy.read_bytes("memory/notes.txt")[0] == b"updated"


def test_inspect_flags_protection(policy):
    policy.atomic_write("knowledge/doc.md", "# hi")
    info = policy.inspect("knowledge/doc.md")
    assert info["protected"] is True
    assert info["sha256"] == hashlib.sha256(b"# hi").hexdigest()


# --------------------------------------------------------------------- #
# Core operations                                                       #
# --------------------------------------------------------------------- #

def test_create_list_inspect_read_roundtrip(policy):
    policy.create_directory("projects/app")
    policy.atomic_write("projects/app/main.txt", "print('hi')")
    entries = sorted(p.relative_to(policy.root).as_posix() for p in policy.walk_bounded("projects"))
    assert "projects/app/main.txt" in entries
    info = policy.inspect("projects/app/main.txt")
    # "print('hi')" is exactly 11 UTF-8 bytes; size must match the on-disk file.
    assert info["type"] == "file" and info["size"] == 11 and info["binary"] is False
    assert (policy.root / "projects/app/main.txt").stat().st_size == info["size"]
    text, truncated, raw = policy.read_text("projects/app/main.txt")
    assert text == "print('hi')" and not truncated


def test_copy_move_rename(policy):
    policy.atomic_write("a.txt", "one")
    policy.copy_file("a.txt", "b.txt")
    assert policy.read_bytes("b.txt")[0] == b"one"
    assert policy.read_bytes("a.txt")[0] == b"one"  # copy keeps source
    with pytest.raises(ValueError):
        policy.copy_file("a.txt", "b.txt")  # exists, overwrite=False
    policy.move_path("b.txt", "dir/b.txt") if False else policy.create_directory("dir")
    policy.move_path("b.txt", "dir/b.txt")
    assert not (policy.root / "b.txt").exists()
    assert (policy.root / "dir/b.txt").read_bytes() == b"one"
    new = policy.rename_path("dir/b.txt", "c.txt")
    assert new == "dir/c.txt"
    assert (policy.root / "dir/c.txt").read_bytes() == b"one"


def test_move_directory_into_itself_rejected(policy):
    policy.create_directory("top/mid")
    with pytest.raises(ValueError):
        policy.move_path("top", "top/mid/inner")


def test_rename_rejects_traversal_in_new_name(policy):
    policy.atomic_write("x.txt", "d")
    with pytest.raises((ValueError, PermissionError)):
        policy.rename_path("x.txt", "../y")
    with pytest.raises(ValueError):
        policy.rename_path("x.txt", "sub/y")


# --------------------------------------------------------------------- #
# Atomic writes and backups                                             #
# --------------------------------------------------------------------- #

def test_overwrite_backup_snapshot_created(policy):
    policy.atomic_write("note.txt", "v1")
    backup = policy.backup_file("note.txt")
    assert backup.startswith(".secureagent-backups/note.txt/")
    assert policy.read_bytes(backup)[0] == b"v1"
    policy.atomic_write("note.txt", "v2", overwrite=True, backup=True)
    snaps = list((policy.root / ".secureagent-backups/note.txt").iterdir())
    assert len(snaps) >= 2


def test_trash_control_dirs_hidden_from_walk(policy):
    policy.atomic_write("keep.txt", "k")
    policy.recycle_file("keep.txt", "DELETE")
    listed = [p.name for p in policy.walk_bounded(".")]
    assert ".secureagent-trash" not in listed
    assert ".secureagent-backups" not in listed


# --------------------------------------------------------------------- #
# Reversible delete (acceptance gate)                                   #
# --------------------------------------------------------------------- #

def test_recycle_restore_roundtrip(policy):
    policy.atomic_write("docs/report.txt", "important")
    entry = policy.recycle_file("docs/report.txt", "DELETE")
    assert not (policy.root / "docs/report.txt").exists()
    assert entry.startswith(".secureagent-trash/docs/report.txt/")
    entries = policy.list_recycle_entries()
    assert any(e["entry"] == entry and e["original"] == "docs/report.txt" for e in entries)
    restored = policy.restore_recycled(entry)
    assert restored == "docs/report.txt"
    assert (policy.root / "docs/report.txt").read_bytes() == b"important"


def test_delete_requires_confirmation_and_purge_confirms(policy):
    policy.atomic_write("gone.txt", "x")
    with pytest.raises(PermissionError):
        policy.recycle_file("gone.txt", "maybe")
    entry = policy.recycle_file("gone.txt", "DELETE")
    with pytest.raises(PermissionError):
        policy.purge_recycle_entry(entry, "DELETE")
    policy.purge_recycle_entry(entry, "PURGE")
    assert policy.list_recycle_entries() == [] or all(e["entry"] != entry for e in policy.list_recycle_entries())


def test_restore_refuses_existing_target(policy):
    policy.atomic_write("dup.txt", "first")
    entry = policy.recycle_file("dup.txt", "DELETE")
    policy.atomic_write("dup.txt", "second")
    with pytest.raises(ValueError):
        policy.restore_recycled(entry)


def test_recycle_rejects_non_regular_files(policy):
    policy.create_directory("adir")
    with pytest.raises((ValueError, PermissionError)):
        policy.recycle_file("adir", "DELETE")


# --------------------------------------------------------------------- #
# Size limits and binary handling                                       #
# --------------------------------------------------------------------- #

def test_write_size_limit(policy):
    with pytest.raises(ValueError):
        policy.atomic_write("big.txt", "A" * (policy.max_write_bytes + 1))


def test_binary_detection(policy):
    policy.atomic_write("blob.bin", b"\x00\x01\x02binary\xff")
    info = policy.inspect("blob.bin")
    assert info["binary"] is True and info["encoding"] is None
    data, truncated = policy.read_bytes("blob.bin", 4)
    assert truncated is True


# --------------------------------------------------------------------- #
# Tool layer (registry-facing behavior)                                 #
# --------------------------------------------------------------------- #

@pytest.fixture()
def tools(tmp_path: Path):
    root = tmp_path / "ws"
    return root


@pytest.mark.asyncio()
async def test_tool_level_flow(tools):
    root = tools
    write = WriteFile(root)
    read = ReadFile(root)
    inspect = InspectFile(root)
    lst = ListFiles(root)
    recycle = RecycleFile(root)
    trash = ListTrash(root)
    restore = RestoreRecycled(root)
    deleter = DeleteFile(root)
    copier = CopyFile(root)
    mover = MovePath(root)
    renamer = RenamePath(root)
    mkdir = CreateDirectory(root)
    backup = BackupFileTool(root)
    purge = PurgeTrash(root)

    out = await write.run({"path": "notes/todo.txt", "content": "buy milk"})
    # "buy milk" is 8 UTF-8 bytes; report must match the on-disk file exactly.
    assert out["bytes_written"] == len("buy milk".encode("utf-8")) == 8
    assert (root / "notes/todo.txt").stat().st_size == out["bytes_written"]
    got = await read.run({"path": "notes/todo.txt"})
    assert got["content"] == "buy milk" and got["binary"] is False

    # protected default paths from settings ("memory") refuse mutation
    await write.run({"path": "memory/x.txt", "content": "ok"})
    with pytest.raises(PermissionError):
        await write.run({"path": "memory/x.txt", "content": "evil", "overwrite": True})
    forced = await write.run({"path": "memory/x.txt", "content": "managed", "overwrite": True,
                              "policy_override": "PROTECTED-OVERRIDE"})
    assert forced["backup_path"] is not None  # pre-overwrite backup taken

    info = await inspect.run({"path": "notes/todo.txt"})
    assert info["info"]["type"] == "file"

    listing = await lst.run({"path": ".", "recursive": True, "limit": 100})
    assert any(e["path"] == "notes/todo.txt" for e in listing["entries"])

    copied = await copier.run({"source": "notes/todo.txt", "destination": "notes/copy.txt"})
    assert copied["copied"] is True
    moved = await mover.run({"source": "notes/copy.txt", "destination": "notes/moved.txt"})
    assert moved["moved"] is True
    renamed = await renamer.run({"path": "notes/moved.txt", "new_name": "final.txt"})
    assert renamed["new_path"] == "notes/final.txt"
    created = await mkdir.run({"path": "archive"})
    assert created["created"] is True
    snap = await backup.run({"path": "notes/final.txt"})
    assert snap["backup_path"].startswith(".secureagent-backups/")

    recycled = await recycle.run({"path": "notes/final.txt", "confirmation": "DELETE"})
    assert recycled["reversible"] is True
    assert not (root / "notes/final.txt").exists()
    entries = await trash.run({})
    assert any(e["entry"] == recycled["recycle_entry"] for e in entries["entries"])
    back = await restore.run({"entry": recycled["recycle_entry"]})
    assert back["restored"] is True and (root / "notes/final.txt").read_bytes() == b"buy milk"

    permanent = await deleter.run({"path": "notes/todo.txt", "confirmation": "DELETE", "permanent": True})
    assert permanent["reversible"] is False and permanent["recycle_entry"] is None
    assert not (root / "notes/todo.txt").exists()

    with pytest.raises(Exception):
        await read.run({"path": "../../etc/passwd"})


@pytest.mark.asyncio()
async def test_tools_use_no_shell(tools):
    """Ordinary filesystem tools must not spawn shells."""
    import subprocess
    real_popen = subprocess.Popen
    calls = []

    class SpyPopen(real_popen):
        def __init__(self, *args, **kwargs):
            calls.append(args or kwargs)
            super().__init__(*args, **kwargs)

    subprocess.Popen = SpyPopen
    try:
        write = WriteFile(tools)
        read = ReadFile(tools)
        copier = CopyFile(tools)
        await write.run({"path": "safe.txt", "content": "no shell here"})
        await read.run({"path": "safe.txt"})
        await copier.run({"source": "safe.txt", "destination": "safe2.txt"})
    finally:
        subprocess.Popen = real_popen
    assert calls == []
