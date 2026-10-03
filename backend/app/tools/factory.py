from functools import lru_cache

from app.coding import InspectProject, ReplaceInFile, RunTests, SearchCode
from app.config import settings
from app.sandbox import DockerPythonSandbox, DockerSandbox, SandboxPolicy
from app.tools.base import Registry
from app.permissions import PermissionManager
from app.tools.builtins import (
    Calculator, DateTimeTool, DeleteFile, HttpRequestTool, ListFiles, PythonTool, TerminalTool,
    ReadFile, SearchTool, TextTool, WriteFile,
)
from app.workspace import WorkspacePolicy


def _build_registry(config, root, store=None, executor=None):
    registry_instance = Registry(max(config.tool_timeout_seconds, config.test_timeout_seconds), config.max_tool_output_chars)
    limit = config.max_tool_output_chars
    test_sandbox = None
    if config.test_sandbox_enabled:
        test_sandbox = DockerSandbox(SandboxPolicy(
            image=config.test_sandbox_image or "",
            timeout_seconds=config.test_timeout_seconds,
            memory_mb=config.test_memory_mb,
            cpu_limit=config.test_cpu_limit,
            pids_limit=config.test_pids_limit,
            output_limit=config.test_output_limit,
            network=config.test_network,
        ))
    python_sandbox = None
    if config.python_execution_backend == "docker" and config.python_sandbox_image:
        python_sandbox = DockerPythonSandbox(SandboxPolicy(
            image=config.python_sandbox_image,
            timeout_seconds=config.python_timeout_seconds,
            memory_mb=config.python_memory_mb,
            cpu_limit=config.python_cpu_limit,
            pids_limit=config.python_pids_limit,
            output_limit=limit,
            network=False,
        ))
    tools = [
        Calculator(), DateTimeTool(), TextTool(),
        ListFiles(root, limit), ReadFile(root, limit), WriteFile(root, limit), DeleteFile(root, limit),
        PythonTool(root, python_sandbox, config.python_timeout_seconds, limit),
        SearchTool(config.searxng_base_url, config.enable_network_tools, config.network_mode, config.allow_local_network, config.allow_private_network, config.allow_external_network, config.dns_enabled, config.network_timeout_seconds, config.network_max_response_bytes, config.network_rate_limit_per_minute),
        HttpRequestTool(config.http_requests_enabled, config.network_mode, config.allow_local_network, config.allow_private_network, config.allow_external_network, config.dns_enabled, config.network_timeout_seconds, config.network_max_response_bytes, config.network_rate_limit_per_minute),
    ]
    if config.terminal_backend == "linux":
        # Linux-native terminal agent suite (command policy engine + bash jail)
        from app.terminal_tools import (
            TerminalEnvironmentInfo, TerminalExecute, TerminalExecuteApproved,
            TerminalExecuteScript, TerminalInspectNetwork, TerminalInspectProcess,
            TerminalInspectServices, TerminalInspectSystem, TerminalListDirectory,
            TerminalReadFile, TerminalSearchFiles, TerminalWorkingDirectory,
        )
        if executor is None:
            from app.linux_terminal import LinuxTerminalExecutor
            executor = LinuxTerminalExecutor(config)
        tools.extend([
            TerminalExecute(executor, limit),
            TerminalExecuteApproved(executor, limit),
            TerminalExecuteScript(executor, limit),
            TerminalWorkingDirectory(executor),
            TerminalListDirectory(executor),
            TerminalReadFile(executor, limit),
            TerminalSearchFiles(executor),
            TerminalInspectProcess(executor, limit),
            TerminalInspectNetwork(executor, limit),
            TerminalInspectServices(executor, limit),
            TerminalInspectSystem(executor, limit),
            TerminalEnvironmentInfo(executor, limit),
        ])
    else:
        # original Docker-sandbox terminal (unchanged behavior)
        tools.append(TerminalTool(root, test_sandbox, limit))
    tools.extend([
        InspectProject(root, limit), SearchCode(root, limit), ReplaceInFile(root, limit),
        RunTests(root, test_sandbox, limit),
    ])
    policy = PermissionManager(config)
    for tool in tools:
        registry_instance.add(policy.apply(tool))
    # Plugin architecture: fail-closed loader, disabled unless explicitly enabled
    if config.plugins_enabled:
        from pathlib import Path
        from app.plugins.loader import PluginLoader
        plugins_dir = Path(__file__).resolve().parents[1] / "plugins" / "available"
        loader = PluginLoader(plugins_dir, enabled=True)
        loader.discover(registry_instance)
    return registry_instance

@lru_cache
def registry():
    config=settings();return _build_registry(config,config.workspace_root)

def registry_for_workspace(relative:str):
    config=settings();boundary=WorkspacePolicy(config.workspace_root,config.max_read_bytes,config.max_write_bytes,config.max_search_file_bytes,config.max_search_files,config.max_directory_depth)
    root=boundary.resolve(relative,must_exist=True)
    if not root.is_dir():raise ValueError('scheduled workspace is not a directory')
    return _build_registry(config,root)
