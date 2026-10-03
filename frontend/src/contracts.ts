// Frozen frontend representation of backend contract v1.0.0.
export type Permission = 'safe'|'read'|'write'|'execute'|'network'|'schedule'|'automation'|'admin'
export type RiskLevel = 'low'|'medium'|'high'|'critical'
export type StepStatus = 'pending'|'running'|'waiting_confirmation'|'completed'|'failed'|'cancelled'
export type TaskStatus = 'planning'|'running'|'waiting_confirmation'|'completed'|'failed'|'cancelled'

export type ToolResult = {
  name: string
  success: boolean
  output: Record<string, unknown>|null
  error: string|null
  code: string|null
  retryable: boolean
  duration_ms: number
}
export type Step = {id:string;title:string;tool:string;arguments:Record<string,unknown>;status:StepStatus;result:ToolResult|null}
export type Task = {id:string;conversation_id:string;goal:string;intent:string;status:TaskStatus;steps:Step[];current_step:number;errors:string[];answer:string|null;created_at:string;updated_at:string}
export type ToolDef = {name:string;description:string;category:string;risk_level:RiskLevel;required_permissions:Permission[];permissions:Permission[];input_schema:Record<string,unknown>;output_schema:Record<string,unknown>;timeout_seconds:number;network_required:boolean;sandbox_required:boolean;audit_required:boolean;idempotent:boolean;enabled:boolean;requires_approval:boolean;disabled_reason:string|null;platforms?:string[]}
export type MemoryItem = {id:string;content:string;category:string;created_at:string;updated_at:string}
export type SchedulePolicy = {allowed_tools?:string[];workspace?:string;max_steps?:number;max_runtime?:number;network_policy?:'deny'|'allow';retry_limit?:number;approval_required?:boolean;approval_granted?:boolean;[key:string]:unknown}
export type Schedule = {id:string;name:string;prompt:string;kind:'once'|'interval';next_run:string;interval_seconds:number|null;permissions:Permission[];policy:SchedulePolicy;enabled:boolean;cancelled:boolean;failure_count:number;created_at:string;updated_at:string}
export type Audit = {id:string;event:string;actor:string;details:Record<string,unknown>;created_at:string}
export type DocumentRecord = {id:string;title:string;path:string;created_at:string;updated_at?:string;content_hash?:string;version:number;metadata:Record<string,string>;chunk_count:number}
export type ScheduleRun = {id:string;schedule_id:string;status:string;task_id:string|null;answer:string|null;errors:string[];created_at:string}
export type SystemHealth = Health & {configuration?:string;permissions?:string;filesystem?:string;logs?:string;search?:string;components?:Record<string,{status:string;error:string|null;fix:string|null}>}
export type Health = {status:string;version:string;backend?:string;database?:string;workspace?:string;ollama?:string;chat_model?:string;embedding_model?:string;network?:string;tools?:string;agent?:string;automation?:string;python_sandbox?:string;provider?:string}
export type AuthStatus = {required:boolean;environment:string;local_bypass:boolean}
export type SearchHit = {document_id:string;title:string;content:string;score:number;path:string;document_version:number;chunk_index:number;source:{document_id:string;path:string;chunk_index:number};untrusted:true}
export type ExecutionError = {error_code:string;message:string;details:Record<string,unknown>}
export type ExecutionResponse = {response_type:'direct_answer'|'tool_result'|'multi_step_result'|'approval_required'|'llm_response'|'deterministic_local_result'|'controlled_error';status:TaskStatus;answer:string|null;task:Task;provider:string;roles:string[];review_approved:boolean;notes:string[];error:ExecutionError|null}
export type Settings = {app_name:string;active_provider:'LOCAL CORE'|'OLLAMA';local_core:boolean;ollama_available:boolean;generative_available:boolean;embedding_available?:boolean;model:string;embedding_model:string;max_completion_tokens:number;workspace:'configured';agent_enabled:boolean;autonomous_mode:boolean;max_agent_steps:number;tools_enabled:boolean;filesystem_tools:boolean;coding_tools:boolean;terminal_tools:boolean;memory_enabled:boolean;knowledge_enabled:boolean;network_tools:boolean;web_search:boolean;http_requests:boolean;network_mode:'disabled'|'local'|'full';network_provider:'SearXNG'|null;network_url_configured:boolean;allow_local_network:boolean;allow_private_network:boolean;allow_external_network:boolean;approval_mode:'all'|'high-risk';automation:boolean;automation_require_approval:boolean;automation_max_concurrent_jobs:number;authentication:boolean;environment:string;python_execution:'disabled'|'docker';terminal_backend?:'docker'|'linux';security_workflows?:boolean;plugins_enabled?:boolean}
export type ApiFailure = {success:false;error:{code:string;message:string;details?:unknown};request_id:string}

// --- Linux terminal agent, workflows, reports, permission center ------------- //
export type TerminalStatus = {backend:'docker'|'linux';enabled:boolean;available:boolean;shell:string;workspace_root:string;allowed_paths:string[];sudo_enabled:boolean;timeout_seconds:number;max_output_bytes:number;unavailable_reason:string|null}
export type TerminalExecution = {id:string;command:string;cwd:string;risk:string;approval:string;status:'running'|'completed'|'timeout'|'cancelled'|'failed';exit_code:number|null;duration_ms:number;started_at?:number;finished_at?:number;stdout:string;stderr:string;output_bytes?:number;truncated:boolean;error:string|null;reasons?:string[];requires_elevation?:boolean;created_at?:string}
export type Workflow = {name:string;title:string;description:string}
export type SecurityFinding = {check:string;status:'OBSERVED'|'INFERRED'|'RECOMMENDED'|'NOT_AVAILABLE';severity:'info'|'low'|'medium'|'high'|'critical';component:string;summary:string;evidence:string[];recommendation:string|null}
export type SecurityReport = {id:string;workflow:string;title:string;generated_at:string;status:'completed'|'failed';duration_ms:number;scope:Record<string,string|number>;summary:{checks:number;inferred_counts_by_severity:Record<string,number>;overall_severity:string;not_available:number};findings:SecurityFinding[];performed_commands:{command:string;exit_code:number|null;duration_ms:number}[];limitations:string[]}
export type Grant = {id:string;permission:Permission;scope:string;note:string;created_at:string;expires_at:string|null}
export type Notification = {id:string;kind:string;severity:string;message:string;target:Record<string,string>;created_at:string|null}
export type SystemInfo = {platform:string;linux:boolean;distro:{id:string|null;name:string|null;version:string|null;like:string|null};kernel:string;architecture:string;hostname:string;python_version:string;shell:{path:string|null;version:string|null};tools:Record<string,{installed:boolean;path:string|null;version:string|null}>;missing_optional_tools:string[];install_hints:Record<string,string>}

// --- SecureAgent 2.0 additions ---------------------------------------------- //
export type HealthV2 = {
  overall: 'READY'|'DEGRADED'|'STARTING'|'STOPPED'|'FAILED'
  database: 'READY'|'FAILED'|'DEGRADED'
  workspace: 'READY'|'FAILED'
  ollama: 'READY'|'DEGRADED'|'FAILED'|'NOT_INSTALLED'
  chat_model: 'READY'|'NOT_CONFIGURED'
  embedding_model: 'READY'|'NOT_CONFIGURED'
  terminal: 'READY'|'DEGRADED'|'NOT_AVAILABLE'
  tools: 'READY'|'FAILED'
  configuration: 'READY'|'DEGRADED'
  permissions: 'READY'|'DEGRADED'
  logs: 'READY'|'DEGRADED'
  automation: 'READY'|'STOPPED'|'FAILED'
  python_sandbox: 'READY'|'NOT_AVAILABLE'
  provider: string
  emergency_stopped: boolean
}
export type HealthV2Response = Health & {
  health_v2: HealthV2
  tool_counts: {enabled: number; total: number; disabled: number}
  ollama_detail: {
    on_path: boolean
    reachable: boolean
    models: string[]
    last_error: {code: string; message: string; component: string; recovery_action: string} | null
  }
}
export type DiagnosticVerdict = 'PASS'|'FAIL'|'WARNING'|'NOT_AVAILABLE'
export type DiagnosticTest = {
  component: string
  status: DiagnosticVerdict
  reason: string
  diagnostic: string
  suggested_fix: string
  duration_ms: number
  evidence: Record<string, unknown>
}
export type DiagnosticsReport = {
  generated_at: string
  overall: 'READY'|'DEGRADED'|'FAILED'
  summary: {total: number; pass: number; warning: number; fail: number; not_available: number}
  duration_ms: number
  tests: DiagnosticTest[]
}
export type AgentMode = 'SAFE'|'ASSIST'|'CONTROL'|'CUSTOM'
export type ModeResponse = {mode: AgentMode; source: string; emergency_stopped: boolean; note?: string}
export type ModeSetResponse = {ok: boolean; mode: AgentMode; snapshot: Record<string, unknown>}
