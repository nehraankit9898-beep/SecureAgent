"""Plugin architecture — load additional tools from validated manifests.

Layout:

    backend/app/plugins/
        loader.py                      this module (manifest validation + import)
        available/<plugin_name>/
            manifest.json              strict metadata contract
            plugin.py                  register(ctx) -> list[Tool]

Manifest contract (all fields required unless marked optional):

    {
      "name": "docker_info",            # [a-z][a-z0-9_]{2,63}
      "version": "1.0.0",
      "description": "...",
      "module": "plugin",               # file name inside the plugin dir, no path parts
      "tools": ["docker_inspect"],      # tool names the module will register
      "permissions": ["execute"],       # union of tool permissions (display only)
      "risk_levels": {"docker_inspect": "low"},
      "platforms": ["linux"],           # supported platforms
      "enabled": false                  # plugins ship disabled by default
    }

Validation is fail-closed: a manifest that misses a field, declares unknown
permissions/risk levels/platforms, contains path separators in ``module``,
or whose module fails to import or register is skipped with a recorded
error — a broken plugin can never take the backend down.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models import Permission, RiskLevel
from app.tools.base import Registry, Tool

PLUGIN_NAME = re.compile(r"[a-z][a-z0-9_]{2,63}")
MODULE_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{0,63}")
VERSION = re.compile(r"\d+\.\d+\.\d+([-+][A-Za-z0-9.]+)?")
VALID_PLATFORMS = {"linux", "windows", "macos"}


@dataclass
class LoadedPlugin:
    name: str
    version: str
    description: str
    tools: list[str]
    permissions: list[str]
    platforms: list[str]
    path: str
    error: str | None = None


class PluginLoader:
    def __init__(self, plugins_dir: Path, enabled: bool):
        self.plugins_dir = plugins_dir
        self.enabled = enabled
        self.loaded: list[LoadedPlugin] = []

    def discover(self, registry: Registry, config_platform: str = "linux") -> list[LoadedPlugin]:
        self.loaded = []
        if not self.enabled or not self.plugins_dir.is_dir():
            return self.loaded
        for manifest_path in sorted(self.plugins_dir.glob("*/manifest.json")):
            plugin_dir = manifest_path.parent
            plugin = self._load_plugin(manifest_path, plugin_dir, registry, config_platform)
            self.loaded.append(plugin)
        return self.loaded

    def _load_plugin(self, manifest_path: Path, plugin_dir: Path,
                     registry: Registry, config_platform: str) -> LoadedPlugin:
        try:
            manifest = self._validate_manifest(manifest_path)
        except ValueError as error:
            return LoadedPlugin(plugin_dir.name, "0.0.0", "", [], [], [], str(plugin_dir), error=str(error))
        base = LoadedPlugin(
            name=manifest["name"], version=manifest["version"], description=manifest["description"],
            tools=list(manifest["tools"]), permissions=list(manifest["permissions"]),
            platforms=list(manifest["platforms"]), path=str(plugin_dir),
        )
        if not manifest.get("enabled", False):
            base.error = "plugin disabled by manifest"
            return base
        if config_platform not in manifest["platforms"]:
            base.error = f"plugin does not support platform {config_platform}"
            return base
        module_path = plugin_dir / f"{manifest['module']}.py"
        if not module_path.is_file():
            base.error = f"module {manifest['module']}.py not found"
            return base
        spec = importlib.util.spec_from_file_location(f"secureagent_plugin_{manifest['name']}", module_path)
        if spec is None or spec.loader is None:
            base.error = "module could not be imported"
            return base
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            tools = module.register()
            if not isinstance(tools, list) or not tools:
                raise ValueError("register() must return a non-empty list of tools")
            names = []
            for tool in tools:
                if not isinstance(tool, Tool):
                    raise ValueError("register() returned an object that is not a Tool")
                if tool.name not in manifest["tools"]:
                    raise ValueError(f"tool '{tool.name}' is not declared in the manifest")
                if tool.risk_level.value != manifest["risk_levels"].get(tool.name):
                    raise ValueError(f"risk level mismatch for tool '{tool.name}'")
                registry.add(tool)
                names.append(tool.name)
            return base
        except Exception as error:  # noqa: BLE001 - plugin faults must not break startup
            base.error = f"{type(error).__name__}: {str(error)[:200]}"
            return base

    @staticmethod
    def _validate_manifest(manifest_path: Path) -> dict[str, Any]:
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"manifest unreadable: {error}") from error
        if not isinstance(raw, dict):
            raise ValueError("manifest must be a JSON object")
        required = ("name", "version", "description", "module", "tools", "permissions",
                    "risk_levels", "platforms")
        missing = [key for key in required if key not in raw]
        if missing:
            raise ValueError(f"manifest missing fields: {', '.join(missing)}")
        if not PLUGIN_NAME.fullmatch(str(raw["name"])):
            raise ValueError("invalid plugin name")
        if not VERSION.fullmatch(str(raw["version"])):
            raise ValueError("invalid plugin version")
        if not MODULE_NAME.fullmatch(str(raw["module"])):
            raise ValueError("invalid module name")
        if not isinstance(raw["description"], str) or not 1 <= len(raw["description"]) <= 500:
            raise ValueError("invalid description")
        if not isinstance(raw["tools"], list) or not 1 <= len(raw["tools"]) <= 20:
            raise ValueError("invalid tools list")
        if any(not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", str(name)) for name in raw["tools"]):
            raise ValueError("invalid tool name in manifest")
        if len(raw["tools"]) != len(set(raw["tools"])):
            raise ValueError("duplicate tool names in manifest")
        try:
            for permission in raw["permissions"]:
                Permission(permission)
            for name, risk in raw["risk_levels"].items():
                RiskLevel(risk)
        except ValueError as error:
            raise ValueError(f"invalid permission or risk level: {error}") from error
        if set(raw["risk_levels"]) != set(raw["tools"]):
            raise ValueError("risk_levels must cover exactly the declared tools")
        if not isinstance(raw["platforms"], list) or not raw["platforms"] or \
                any(platform not in VALID_PLATFORMS for platform in raw["platforms"]):
            raise ValueError("invalid platforms")
        return raw
