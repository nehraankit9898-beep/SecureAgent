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
SECUREAGENT_BACKUP_DIR = ".secureagent-backups"
SECUREAGENT_TRASH_DIR = ".secureagent-trash"
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
        protected_paths: tuple[str, ...] | list[str] = (),
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
        # Phase 7: policy-declared protected relative paths (files or whole
        # subtrees). Reads stay allowed; every mutating operation fails closed
        # unless the caller supplies the explicit override token.
        self.protected_paths = frozenset(
            PurePosixPath(part).as_posix().strip("/")
            for part in protected_paths
            if isinstance(part, str) and part.strip("/")
        )

    PROTECTED_TOKEN = "PROTECTED-OVERRIDE"

    def is_protected(self, relative: str) -> bool:
        """True when *relative* equals or lives under a protected path."""
        try:
            parts = self._parts(relative)
        except (ValueError, PermissionError):
            return False
        candidate = PurePosixPath(*(part.casefold() for part in parts))
        for entry in self.protected_paths:
            normalized = PurePosixPath(*(segment.casefold() for segment in PurePosixPath(entry).parts))
            if candidate == normalized or normalized in candidate.parents:
                return True
        return False

    def _is_bootstrap_write(self, parts: tuple[str, ...]) -> bool:
        """True when writing *parts* creates a protected subtree for the
        very first time (no file exists anywhere inside the protected root).

        Bootstrap exception: initial creation of protected workspace areas
        (memory/, knowledge/, ...) must succeed so the agent can seed them;
        every mutation once any content exists requires an explicit override.
        """
        if not parts:
            return False
        protected_root = self.root.joinpath(parts[0])
        if protected_root.is_file():
            return False
        if protected_root.is_dir() and any(protected_root.rglob("*")):
            return False
        return True

    def _guard_mutation(self, relative: str, allow_protected: bool) -> None:
        if allow_protected or not self.is_protected(relative):
            return
        try:
            parts = self._parts(relative)
        except (ValueError, PermissionError):
            parts = ()
        if self._is_bootstrap_write(parts):
            return
        raise PermissionError(
            "protected path requires explicit policy override"
        )

    def _ensure_parents(self, parts: tuple[str, ...]) -> None:
        """Create missing parent directories, honoring protected-path guards."""
        for index in range(1, len(parts)):
            parent_relative = "/".join(parts[:index])
            parent = self.root.joinpath(*parts[:index])
            if parent.is_dir():
                continue
            self._guard_mutation(parent_relative, False)
            parent.mkdir(mode=0o700, exist_ok=True)

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
        # Phase 7: internal backup/trash snapshots keep the original path's
        # components (e.g. ".secureagent-trash/notes.txt/<snapshot>"), so the
        # sensitive-name screen only applies once the control prefix is known.
        control_prefix = parts and parts[0] in {self.BACKUP_DIRNAME, self.TRASH_DIRNAME}
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
            if part.casefold() in SENSITIVE_PARTS and not control_prefix:
                raise PermissionError("sensitive workspace path is not accessible")
        return parts

    def resolve(self, relative: str, must_exist: bool = False) -> Path:
        parts = self._parts(relative)
        candidate = self.root.joinpath(*parts)
        if parts and parts[0] in {SECUREAGENT_BACKUP_DIR, SECUREAGENT_TRASH_DIR}:
            return candidate
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
        allow_protected: bool = False,
        backup: bool = False,
    ) -> Path:
        self._guard_mutation(relative, allow_protected)
        if backup and overwrite:
            try:
                self.backup_file(relative)
            except FileNotFoundError:
                pass
        data = content.encode("utf-8") if isinstance(content, str) else content
        maximum = min(max_bytes or self.max_write_bytes, self.max_write_bytes)
        if len(data) > maximum:
            raise ValueError("write exceeds configured byte limit")
        parts = self._parts(relative)
        path = self.root.joinpath(*parts)

        if not _SECURE_DIR_FD:
            return self._atomic_write_portable(relative, data, overwrite, maximum, expected_sha256)

        self._ensure_parents(parts)
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
        self._ensure_parents(tuple(path.relative_to(self.root).parts))
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
                if entry.name in {SECUREAGENT_BACKUP_DIR, SECUREAGENT_TRASH_DIR} and directory == base.parent or entry.path == str(base / SECUREAGENT_BACKUP_DIR) or entry.path == str(base / SECUREAGENT_TRASH_DIR): continue
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

    def delete(self, relative: str, confirmation: str, allow_protected: bool = False) -> None:
        if confirmation != "DELETE":
            raise PermissionError("explicit DELETE confirmation required")
        self._guard_mutation(relative, allow_protected)
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

    # ------------------------------------------------------------------ #
    # Phase 7 — extended filesystem primitives                            #
    # All operations below use filesystem APIs only (no shell), enforce   #
    # the normalized policy boundary, refuse symlink/hardlink escapes and  #
    # respect protected paths unless an explicit override is supplied.     #
    # ------------------------------------------------------------------ #

    BACKUP_DIRNAME = SECUREAGENT_BACKUP_DIR
    TRASH_DIRNAME = SECUREAGENT_TRASH_DIR
    _SNAPSHOT_LIMIT = 20

    def _open_regular_fd(self, parts: tuple[str, ...]) -> int:
        """Open a regular, non-symlink, single-link file inside the jail."""
        parent_fd, name = self._open_parent_fd(parts)
        try:
            try:
                descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR, errno.EACCES, errno.EPERM}:
                    raise PermissionError("unsafe workspace path") from None
                if error.errno == errno.ENOENT:
                    raise FileNotFoundError("workspace path not found") from None
                raise
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                os.close(descriptor)
                raise ValueError("not a regular file")
            if info.st_nlink != 1:
                os.close(descriptor)
                raise PermissionError("hard-linked files are not allowed")
            return descriptor
        finally:
            os.close(parent_fd)

    def inspect(self, relative: str) -> dict:
        parts = self._parts(relative)
        if not parts:
            return {"path": ".", "type": "directory", "protected": bool(self.protected_paths)}
        target = self.root.joinpath(*parts)
        if target.is_symlink():
            raise PermissionError("symlinks and junction-like redirects are not allowed")
        info = os.lstat(target)
        if stat.S_ISLNK(info.st_mode):
            raise PermissionError("symlinks and junction-like redirects are not allowed")
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "other"
        if kind == "other":
            raise ValueError("unsupported filesystem object")
        result: dict = {
            "path": self.relative(target),
            "type": kind,
            "size": info.st_size if kind == "file" else None,
            "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(info.st_mtime)),
            "protected": self.is_protected(relative),
        }
        if kind == "file":
            data, truncated = self.read_bytes(relative, 8192)
            binary = b"\x00" in data
            result["binary"] = binary
            result["sha256"] = hashlib.sha256(data).hexdigest() if not truncated else None
            result["encoding"] = None if binary else "utf-8"
        return result

    def create_directory(self, relative: str, allow_protected: bool = False) -> Path:
        self._guard_mutation(relative, allow_protected)
        parts = self._parts(relative)
        if not parts:
            raise ValueError("a directory path is required")
        descriptor = os.open(self.root, _DIR_FLAGS)
        try:
            for part in parts:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(part, _DIR_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
        except OSError as error:
            if error.errno in {errno.EEXIST, errno.ELOOP, errno.ENOTDIR, errno.EACCES, errno.EPERM}:
                raise PermissionError("unsafe or existing workspace directory") from None
            raise
        finally:
            os.close(descriptor)
        return self.root.joinpath(*parts)

    def _copy_regular(self, source_parts: tuple[str, ...], destination_parts: tuple[str, ...], max_bytes: int) -> int:
        source_fd = self._open_regular_fd(source_parts)
        try:
            data = b""
            while True:
                block = os.read(source_fd, 65_536)
                if not block:
                    break
                data += block
                if len(data) > max_bytes:
                    raise ValueError("copy exceeds configured byte limit")
        finally:
            os.close(source_fd)
        self._ensure_parents(destination_parts)
        parent_fd, name = self._open_parent_fd(destination_parts, create=True)
        temporary = f".secureagent-{uuid4().hex}.tmp"
        temp_fd: int | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            temp_fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
            with os.fdopen(temp_fd, "wb", closefd=True) as handle:
                temp_fd = None
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
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
        return len(data)

    def copy_file(self, source: str, destination: str, overwrite: bool = False, allow_protected: bool = False) -> str:
        self._guard_mutation(source, True)  # reads from protected paths stay allowed
        self._guard_mutation(destination, allow_protected)
        source_parts = self._parts(source)
        destination_parts = self._parts(destination)
        if not source_parts or not destination_parts:
            raise ValueError("source and destination file paths are required")
        final_path = self.root.joinpath(*destination_parts)
        if final_path.exists() and not overwrite:
            raise ValueError("destination exists")
        size = self._copy_regular(source_parts, destination_parts, self.max_write_bytes)
        return self.relative(final_path)

    def _move_within_jail(self, source_parts: tuple[str, ...], destination_parts: tuple[str, ...]) -> None:
        self._ensure_parents(destination_parts)
        source_parent, source_name = self._open_parent_fd(source_parts)
        try:
            if os.path.exists(destination_parts[-1], dir_fd=source_parent):
                raise ValueError("destination exists")
            os.rename(source_name, destination_parts[-1], src_dir_fd=source_parent, dst_dir_fd=source_parent)
            os.fsync(source_parent)
        finally:
            os.close(source_parent)

    def move_path(self, source: str, destination: str, allow_protected: bool = False) -> str:
        self._guard_mutation(source, allow_protected)
        self._guard_mutation(destination, allow_protected)
        source_parts = self._parts(source)
        destination_parts = self._parts(destination)
        if not source_parts or not destination_parts:
            raise ValueError("source and destination paths are required")
        if self.root.joinpath(*destination_parts).exists():
            raise ValueError("destination exists")
        source_target = self.root.joinpath(*source_parts)
        if source_target.is_symlink():
            raise PermissionError("symlinks and junction-like redirects are not allowed")
        if source_target.is_dir():
            resolved_source = source_target.resolve(strict=True)
            resolved_destination = self.root.joinpath(*destination_parts[:-1]).resolve(strict=True)
            if resolved_destination == resolved_source or resolved_source in resolved_destination.parents:
                raise ValueError("cannot move a directory into itself")
            self._move_within_jail(source_parts, destination_parts)
            return self.relative(self.root.joinpath(*destination_parts))
        self._copy_regular(source_parts, destination_parts, self.max_write_bytes)
        self.delete(self.relative(source_target), "DELETE", allow_protected=True)
        return self.relative(self.root.joinpath(*destination_parts))

    def rename_path(self, source: str, new_name: str, allow_protected: bool = False) -> str:
        self._guard_mutation(source, allow_protected)
        source_parts = self._parts(source)
        if not source_parts:
            raise ValueError("a file path is required")
        if "/" in new_name or "\\" in new_name or not new_name:
            raise ValueError("new name must be a single path component")
        checked = self._parts(new_name)  # validates reserved names / traversal
        destination_parts = source_parts[:-1] + checked
        self._guard_mutation(self.relative(self.root.joinpath(*destination_parts)), allow_protected)
        return self.move_path(source, self.relative(self.root.joinpath(*destination_parts)), allow_protected=True)

    def backup_file(self, relative: str) -> str:
        parts = self._parts(relative)
        if not parts:
            raise ValueError("a file path is required")
        snapshot = f"{int(time.time())}-{uuid4().hex[:8]}"
        backup_relative = "/".join([self.BACKUP_DIRNAME, *parts, snapshot])
        self._copy_regular(parts, self._parts(backup_relative), self.max_read_bytes)
        self._prune_snapshots(self.BACKUP_DIRNAME, [*parts])
        return backup_relative

    def recycle_file(self, relative: str, confirmation: str, allow_protected: bool = False) -> str:
        if confirmation != "DELETE":
            raise PermissionError("explicit DELETE confirmation required")
        self._guard_mutation(relative, allow_protected)
        parts = self._parts(relative)
        if not parts:
            raise ValueError("a file path is required")
        descriptor = self._open_regular_fd(parts)
        os.close(descriptor)
        snapshot = f"{int(time.time())}-{uuid4().hex[:8]}"
        trash_relative = "/".join([self.TRASH_DIRNAME, *parts, snapshot])
        self._copy_regular(parts, self._parts(trash_relative), self.max_read_bytes)
        self.delete(relative, "DELETE", allow_protected=True)
        self._prune_snapshots(self.TRASH_DIRNAME, [*parts])
        return trash_relative

    def restore_recycled(self, trash_entry: str) -> str:
        parts = list(self._parts(trash_entry))
        if not parts or parts[0] != self.TRASH_DIRNAME or len(parts) < 3:
            raise ValueError("invalid recycle entry")
        parts.pop(0)
        snapshot = parts.pop()
        if not re.fullmatch(r"\d{9,11}-[0-9a-f]{8}", snapshot):
            raise ValueError("invalid recycle entry")
        original_relative = "/".join(parts)
        if self.root.joinpath(*self._parts(original_relative)).exists():
            raise ValueError("original path already exists")
        self._copy_regular(self._parts(trash_entry), self._parts(original_relative), self.max_read_bytes)
        return original_relative

    def list_recycle_entries(self) -> list[dict]:
        entries: list[dict] = []
        base = self.root / self.TRASH_DIRNAME
        if not base.is_dir():
            return entries
        for path in self.walk_bounded(self.TRASH_DIRNAME, self.max_search_files, stop_at_limit=True):
            if path.is_dir() or path.is_symlink():
                continue
            rel = path.relative_to(base).as_posix()
            info = path.stat()
            entries.append({"entry": f"{self.TRASH_DIRNAME}/{rel}", "original": str(PurePosixPath(*PurePosixPath(rel).parts[:-1])), "size": info.st_size})
        entries.sort(key=lambda item: item["entry"])
        return entries

    def purge_recycle_entry(self, trash_entry: str, confirmation: str) -> None:
        if confirmation != "PURGE":
            raise PermissionError("explicit PURGE confirmation required")
        parts = self._parts(trash_entry)
        if not parts or parts[0] != self.TRASH_DIRNAME:
            raise ValueError("invalid recycle entry")
        self.delete(trash_entry, "DELETE", allow_protected=True)

    def _prune_snapshots(self, control_dir: str, parts: list[str]) -> None:
        """Keep only the newest snapshots per original path (bounded storage)."""
        prefix = "/".join([control_dir, *parts])
        try:
            directory = self.root.joinpath(control_dir, *parts)
            if not directory.is_dir():
                return
            children = sorted((child.name for child in directory.iterdir()), reverse=True)
        except OSError:
            return
        stale = children[self._SNAPSHOT_LIMIT:]
        for name in stale:
            try:
                os.unlink(f"{prefix}/{name}")
            except FileNotFoundError:
                pass
