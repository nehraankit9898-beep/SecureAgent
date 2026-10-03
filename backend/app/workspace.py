import errno
import hashlib
import os
import time
import re
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import unquote
from uuid import uuid4

RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
BAD_NAME = re.compile(r"[\x00-\x1f<>:\"|?*\\]")
MAX_PATH_CHARS = 4096
MAX_PART_CHARS = 255
SENSITIVE_PARTS={'.env','.ssh','id_rsa','id_ed25519','docker.sock','credentials','secrets'}
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
_SECURE_DIR_FD = os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd and os.unlink in os.supports_dir_fd


class WorkspacePolicy:
    """Authoritative cross-platform lexical and filesystem workspace boundary."""

    def __init__(
        self,
        root: Path,
        max_read_bytes: int = 1_000_000,
        max_write_bytes: int = 1_000_000,
        max_search_file_bytes: int = 512_000,
        max_search_files: int = 2_000,
        max_depth: int = 8,
    ):
        expanded = root.expanduser()
        expanded.mkdir(parents=True, exist_ok=True)
        self.root = expanded.resolve(strict=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("workspace root must be a real directory")
        self.max_read_bytes = max_read_bytes
        self.max_write_bytes = max_write_bytes
        self.max_search_file_bytes = max_search_file_bytes
        self.max_search_files = max_search_files
        self.max_depth = max_depth

    def _parts(self, relative: str) -> tuple[str, ...]:
        if not isinstance(relative, str) or not relative or len(relative) > MAX_PATH_CHARS:
            raise ValueError("invalid path")
        if "\x00" in relative or "\\" in relative:
            raise ValueError("invalid path")

        decoded = relative
        for _ in range(3):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        if decoded != relative:
            decoded_posix = PurePosixPath(decoded)
            decoded_windows = PureWindowsPath(decoded)
            if (
                "\x00" in decoded
                or "\\" in decoded
                or decoded_posix.is_absolute()
                or decoded_windows.is_absolute()
                or decoded_windows.drive
                or ".." in decoded_posix.parts
                or ".." in decoded_windows.parts
            ):
                raise PermissionError("encoded path traversal is not allowed")

        windows = PureWindowsPath(relative)
        posix = PurePosixPath(relative)
        if posix.is_absolute() or windows.is_absolute() or windows.drive or windows.root:
            raise PermissionError("absolute paths are not allowed")
        parts = tuple(part for part in posix.parts if part not in ("", "."))
        if not parts and relative != ".":
            raise ValueError("invalid path")
        if ".." in parts:
            raise PermissionError("path traversal is not allowed")
        if len(parts) > self.max_depth:
            raise ValueError("maximum directory depth exceeded")
        for part in parts:
            if len(part) > MAX_PART_CHARS:
                raise ValueError("path component is too long")
            stem = part.rstrip(". ").split(".")[0].upper()
            if BAD_NAME.search(part) or stem in RESERVED or part.endswith((" ", ".")):
                raise ValueError("dangerous filename")
            if part.casefold() in SENSITIVE_PARTS:
                raise PermissionError("sensitive workspace path is not accessible")
        return parts

    def resolve(self, relative: str, must_exist: bool = False) -> Path:
        parts = self._parts(relative)
        candidate = self.root.joinpath(*parts)
        existing = candidate
        while not existing.exists() and existing != self.root:
            existing = existing.parent
        resolved_existing = existing.resolve(strict=True)
        if resolved_existing != self.root and self.root not in resolved_existing.parents:
            raise PermissionError("path escapes workspace")
        if candidate.exists() or must_exist:
            resolved = candidate.resolve(strict=must_exist)
            if resolved != self.root and self.root not in resolved.parents:
                raise PermissionError("path escapes workspace")
            if candidate.is_symlink():
                raise PermissionError("symlinks and junction-like redirects are not allowed")
        return candidate

    def _open_parent_fd(self, parts: tuple[str, ...], create: bool = False) -> tuple[int, str]:
        if not parts:
            raise ValueError("a file path is required")
        descriptor = os.open(self.root, _DIR_FLAGS)
        try:
            for part in parts[:-1]:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                child = os.open(part, _DIR_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor, parts[-1]
        except OSError as error:
            os.close(descriptor)
            if error.errno in {errno.ELOOP,errno.ENOTDIR,errno.EACCES,errno.EPERM}:raise PermissionError('unsafe workspace path') from None
            if error.errno==errno.ENOENT:raise FileNotFoundError('workspace path not found') from None
            raise
        except Exception:
            os.close(descriptor)
            raise

    def relative(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def stat_regular(self, relative: str, max_bytes: int | None = None) -> os.stat_result:
        data, truncated, info = self._read_with_stat(relative, max_bytes)
        del data
        if truncated:
            raise ValueError("file exceeds configured byte limit")
        return info

    def _read_with_stat(self, relative: str, max_bytes: int | None = None) -> tuple[bytes, bool, os.stat_result]:
        parts = self._parts(relative)
        maximum = min(max_bytes or self.max_read_bytes, self.max_read_bytes)
        if _SECURE_DIR_FD:
            parent_fd, name = self._open_parent_fd(parts)
            try:
                try:
                    descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
                except OSError as error:
                    if error.errno in {errno.ELOOP, errno.ENOTDIR, errno.EACCES, errno.EPERM}:
                        raise PermissionError('unsafe workspace path') from None
                    if error.errno == errno.ENOENT:
                        raise FileNotFoundError('workspace path not found') from None
                    raise
            finally:
                os.close(parent_fd)
        else:
            path = self.resolve(relative, must_exist=True)
            descriptor = os.open(path, _FILE_FLAGS)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("not a regular file")
            if before.st_nlink != 1:
                raise PermissionError("hard-linked files are not allowed")
            chunks: list[bytes] = []
            total = 0
            while total <= maximum:
                block = os.read(descriptor, min(65_536, maximum + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise RuntimeError("file changed during read")
            data = b"".join(chunks)
            return data[:maximum], len(data) > maximum, after
        finally:
            os.close(descriptor)

    def read_bytes(self, relative: str, max_bytes: int | None = None) -> tuple[bytes, bool]:
        data, truncated, _ = self._read_with_stat(relative, max_bytes)
        return data, truncated

    def read_text(self, relative: str, max_bytes: int | None = None) -> tuple[str, bool, bytes]:
        data, truncated = self.read_bytes(relative, max_bytes)
        return data.decode("utf-8", errors="replace"), truncated, data

    def atomic_write(
        self,
        relative: str,
        content: str | bytes,
        overwrite: bool = False,
        max_bytes: int | None = None,
        expected_sha256: str | None = None,
    ) -> Path:
        data = content.encode("utf-8") if isinstance(content, str) else content
        maximum = min(max_bytes or self.max_write_bytes, self.max_write_bytes)
        if len(data) > maximum:
            raise ValueError("write exceeds configured byte limit")
        parts = self._parts(relative)
        path = self.root.joinpath(*parts)

        if not _SECURE_DIR_FD:
            return self._atomic_write_portable(relative, data, overwrite, maximum, expected_sha256)

        parent_fd, name = self._open_parent_fd(parts, create=True)
        temporary = f".secureagent-{uuid4().hex}.tmp"
        temp_fd: int | None = None
        try:
            try:
                current_fd = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
            except FileNotFoundError:
                current_fd = None
            if current_fd is not None:
                try:
                    info = os.fstat(current_fd)
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError("target is not a regular file")
                    if info.st_nlink != 1:
                        raise PermissionError("hard-linked files are not allowed")
                    if not overwrite:
                        raise ValueError("file exists")
                    current = b""
                    while block := os.read(current_fd, 65_536):
                        current += block
                        if len(current) > maximum:
                            break
                    if expected_sha256 is not None and (
                        len(current) > maximum or hashlib.sha256(current).hexdigest() != expected_sha256
                    ):
                        raise ValueError("file changed; inspect it again")
                finally:
                    os.close(current_fd)
            elif expected_sha256 is not None:
                raise FileNotFoundError("file not found")

            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            temp_fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
            with os.fdopen(temp_fd, "wb", closefd=True) as handle:
                temp_fd = None
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())

            if expected_sha256 is not None:
                verify_fd = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
                try:
                    current = b""
                    while block := os.read(verify_fd, 65_536):
                        current += block
                        if len(current) > maximum:
                            break
                    if len(current) > maximum or hashlib.sha256(current).hexdigest() != expected_sha256:
                        raise ValueError("file changed during edit")
                finally:
                    os.close(verify_fd)

            if overwrite:
                os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            else:
                os.link(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
                os.unlink(temporary, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except Exception:
            if temp_fd is not None:
                os.close(temp_fd)
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(parent_fd)
        return path

    def _atomic_write_portable(self, relative: str, data: bytes, overwrite: bool, maximum: int, expected_sha256: str | None) -> Path:
        path = self.resolve(relative)
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise ValueError("target is not a regular file")
            if not overwrite:
                raise ValueError("file exists")
            if expected_sha256 is not None:
                current, truncated = self.read_bytes(relative, maximum)
                if truncated or hashlib.sha256(current).hexdigest() != expected_sha256:
                    raise ValueError("file changed; inspect it again")
        elif expected_sha256 is not None:
            raise FileNotFoundError("file not found")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.resolve(str(path.parent.relative_to(self.root)), must_exist=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".secureagent-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            self.resolve(str(path.parent.relative_to(self.root)), must_exist=True)
            if expected_sha256 is not None:
                current, truncated = self.read_bytes(relative, maximum)
                if truncated or hashlib.sha256(current).hexdigest() != expected_sha256:
                    raise ValueError("file changed during edit")
            if not overwrite and path.exists():
                raise FileExistsError("file exists")
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        return path

    def walk_bounded(self, relative=".", max_files=None, max_dirs=10000, max_total_bytes=1_000_000_000, timeout_seconds=10, stop_at_limit=False):
        """Bounded workspace traversal.

        stop_at_limit=False (default) keeps the fail-closed contract used by
        sandbox copying: exceeding the file/byte budget raises ValueError.
        stop_at_limit=True is for read-only listings (list_files,
        inspect_project, search_code): the traversal simply ends once the
        configured budget is reached, so large workspaces truncate their
        results (the tool schemas advertise truncated=true) instead of
        failing the whole tool call. Timeout and directory-limit violations
        still raise in both modes: they indicate a pathological tree or an
        I/O stall rather than an ordinary large workspace.
        """
        base=self.resolve(relative,must_exist=True); deadline=time.monotonic()+timeout_seconds
        if not base.is_dir(): raise ValueError("not a directory")
        stack=[(base,0)]; files=dirs=total=0
        file_limit=max_files or self.max_search_files
        while stack:
            if time.monotonic()>deadline: raise TimeoutError("workspace traversal timeout")
            directory,depth=stack.pop()
            try: entries=list(os.scandir(directory))
            except OSError as e: raise PermissionError("workspace traversal failed") from e
            for entry in entries:
                if entry.is_symlink(): continue
                path=Path(entry.path); rel=path.relative_to(self.root)
                if depth+1>self.max_depth: continue
                if entry.is_dir(follow_symlinks=False):
                    dirs+=1
                    if dirs>max_dirs: raise ValueError("workspace directory limit exceeded")
                    stack.append((path,depth+1)); yield path
                elif entry.is_file(follow_symlinks=False):
                    files+=1; total+=entry.stat(follow_symlinks=False).st_size
                    if files>file_limit or total>max_total_bytes:
                        if stop_at_limit: return
                        raise ValueError("workspace traversal limits exceeded")
                    yield path

    def iter_files(self, relative: str = ".", max_files: int | None = None) -> Iterator[Path]:
        base = self.resolve(relative, must_exist=True)
        if not base.is_dir():
            raise ValueError("not a directory")
        maximum = min(max_files or self.max_search_files, self.max_search_files)
        seen = 0
        for path in self.walk_bounded(relative, maximum, stop_at_limit=True):
            rel = path.relative_to(self.root)
            if len(rel.parts) > self.max_depth or path.is_symlink() or not path.is_file():
                continue
            seen += 1
            if seen > maximum:
                break
            yield path

    def safe_copy_tree(self, relative: str, destination: Path, max_files: int, max_total_bytes: int) -> tuple[int, int]:
        source = self.resolve(relative, must_exist=True)
        if not source.is_dir():
            raise ValueError("project path is not a directory")
        files = total = 0
        for path in self.walk_bounded(relative, max_files, max_total_bytes=max_total_bytes):
            rel = path.relative_to(source)
            if len(rel.parts) > self.max_depth:
                continue
            if path.is_symlink():
                raise PermissionError("sandbox copy refuses symlinks")
            target = destination / rel
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not path.is_file():
                continue
            workspace_relative = self.relative(path)
            data, truncated = self.read_bytes(workspace_relative, max_total_bytes - total + 1)
            if truncated:
                raise ValueError("project exceeds sandbox copy limits")
            files += 1
            total += len(data)
            if files > max_files or total > max_total_bytes:
                raise ValueError("project exceeds sandbox copy limits")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return files, total

    def delete(self, relative: str, confirmation: str) -> None:
        if confirmation != "DELETE":
            raise PermissionError("explicit DELETE confirmation required")
        parts = self._parts(relative)
        if not _SECURE_DIR_FD:
            path = self.resolve(relative, must_exist=True)
            if path.is_symlink() or not path.is_file():
                raise ValueError("only regular files may be deleted")
            if path.stat().st_nlink != 1:raise PermissionError("hard-linked files are not allowed")
            path.unlink()
            return
        parent_fd, name = self._open_parent_fd(parts)
        quarantine = f".secureagent-delete-{uuid4().hex}.tmp"
        try:
            descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode):
                    raise ValueError("only regular files may be deleted")
                if opened.st_nlink != 1:
                    raise PermissionError("hard-linked files are not allowed")
                os.replace(name, quarantine, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                moved = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
                if (opened.st_dev, opened.st_ino) != (moved.st_dev, moved.st_ino):
                    if not os.path.exists(self.root.joinpath(*parts)):
                        os.replace(quarantine, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    raise RuntimeError("file changed during deletion")
                os.unlink(quarantine, dir_fd=parent_fd)
                os.fsync(parent_fd)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent_fd)
