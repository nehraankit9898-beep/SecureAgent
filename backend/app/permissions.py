"""Central runtime tool availability and approval policy."""
import sys

from app.models import Permission, RiskLevel


class PermissionManager:
    def __init__(self, config):
        self.config = config

    def apply(self, tool):
        enabled = bool(self.config.tools_enabled)
        reason = None
        platforms = getattr(tool, "platforms", None) or ["linux", "windows", "macos"]
        current = sys.platform
        normalized = "linux" if current.startswith("linux") else "darwin" if current == "darwin" else "windows"
        if normalized not in platforms:
            enabled, reason = False, f"PLATFORM_UNSUPPORTED: tool is not available on {normalized}"
        if tool.category == "filesystem" and not self.config.filesystem_tools_enabled:
            enabled, reason = False, "FILESYSTEM_TOOLS_DISABLED: Disabled in Settings"
        elif tool.category == "coding" and not self.config.coding_tools_enabled:
            enabled, reason = False, "CODING_TOOLS_DISABLED: Disabled in Settings"
        elif tool.category == "terminal" and not self.config.terminal_tools_enabled:
            enabled, reason = False, "TERMINAL_TOOLS_DISABLED: Disabled in Settings"
        elif tool.category == "workflow" and not self.config.security_workflows_enabled:
            enabled, reason = False, "WORKFLOWS_DISABLED: Disabled in Settings"
        elif tool.category == "browser" and not self.config.browser_enabled:
            enabled, reason = False, "BROWSER_DISABLED: Browser automation is disabled in Settings"
        elif tool.category == "voice" and not getattr(self.config, "voice_enabled", False):
            enabled, reason = False, "VOICE_DISABLED: Voice is disabled in Settings"
        elif tool.name == "web_search" and not self.config.web_search_enabled:
            enabled, reason = False, "WEB_SEARCH_DISABLED: Disabled in Settings"
        elif tool.name == "http_request" and not self.config.http_requests_enabled:
            enabled, reason = False, "HTTP_REQUESTS_DISABLED: Disabled in Settings"
        elif tool.name == "python_executor" and self.config.python_execution_backend != "docker":
            enabled, reason = False, "PYTHON_SANDBOX_UNAVAILABLE: Docker sandbox is not configured"
        if not self.config.tools_enabled:
            enabled, reason = False, "TOOLS_DISABLED: Tool execution is disabled in Settings"
        tool.enabled = bool(tool.enabled and enabled)
        if not tool.enabled and not tool.disabled_reason:
            tool.disabled_reason = reason or "TOOL_DISABLED: Disabled by runtime policy"
        tool.requires_approval = bool(
            tool.requires_approval
            or tool.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            or self.config.approval_mode == "all"
            or tool.name == "http_request"
            or (Permission.NETWORK in tool.permissions and self.config.require_approval_for_external_network and self.config.network_mode == "full")
        )
        return tool
