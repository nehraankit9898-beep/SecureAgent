/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

type DesktopBackendState = {state:'STARTING'|'READY'|'DEGRADED'|'ERROR'|'STOPPED';ready?:boolean;origin?:string;port?:number;restarts?:number;error?:string|null;message?:string}
type DesktopCheck = {ok: boolean; value: string}
type DesktopChecks = Record<string, DesktopCheck>

interface SecureAgentDesktopBridge {
  bootstrap(): Promise<{ setupComplete: boolean; version: string; origin: string; models: {chat: string; embedding: string}; backend: DesktopBackendState}>
  backendRequest(request:{path:string;method?:string;body?:string}): Promise<{status:number;headers:{requestId:string|null;contractVersion:string|null};body:string}>
  checkAll(): Promise<DesktopChecks>
  getSettings(): Promise<DesktopSettings>
  updateSettings(settings: Partial<DesktopSettings>): Promise<{ok: boolean; settings: DesktopSettings; ollama: OllamaStatus; origin: string}>
  saveSettings(settings: Partial<DesktopSettings>): Promise<{ok: boolean; settings: DesktopSettings; restartRequired: boolean; message: string}>
  resetSettings(): Promise<DesktopSettings>
  testOllama(): Promise<OllamaStatus>
  testChatModel(): Promise<{status: string; model: string; response: string}>
  testEmbeddingModel(): Promise<{status: string; model: string; dimension: number}>
  refreshModels(): Promise<string[]>
  testNetwork(): Promise<{status: string; provider: string; result_count: number; duration_ms: number}>
  runDiagnostic(component:'backend'|'agent'|'tools'|'permissions'|'search'): Promise<Record<string,unknown>>
  setupOllama(): Promise<void>
  installModels(models: string[]): Promise<DesktopChecks>
  completeSetup(): Promise<{ok: boolean}>
  retryBackend(): Promise<{ok: boolean}>
  openLogs(): Promise<string>
  createDiagnostics(): Promise<{jsonPath: string; markdownPath: string}>
  exit(): Promise<{ok: boolean}>
  onLaunchStatus(callback: (status: DesktopBackendState) => void): () => void
  // SecureAgent 2.0: live config-sync subscription so the dashboard refreshes
  // immediately when the Control Center toggles a switch (spec section 28).
  // The desktop preload exposes this; it returns an unsubscribe function.
  onConfigSync?(callback: (revision: number) => void): () => void
}

type DesktopSettings = {setupComplete?:boolean; preferredPort?:number; ollamaEnabled:boolean; ollamaBaseUrl: string; chatModel: string; embeddingModel: string; maxCompletionTokens:number; agentEnabled:boolean; autonomousMode:boolean; maxAgentSteps:number; toolsEnabled:boolean; filesystemToolsEnabled:boolean; codingToolsEnabled:boolean; terminalToolsEnabled:boolean; terminalSandboxImage:string; memoryEnabled:boolean; knowledgeEnabled:boolean; networkEnabled: boolean; networkMode: 'disabled'|'local'|'full'; searxngBaseUrl: string; networkTrustedPrivateEndpoint: boolean; webSearchEnabled:boolean; httpRequestsEnabled:boolean; dnsEnabled:boolean; allowLocalNetwork:boolean; allowPrivateNetwork:boolean; allowExternalNetwork:boolean; requireApprovalForExternalNetwork:boolean; approvalMode:'all'|'high-risk'; requireApprovalForHighRisk:boolean; automationEnabled: boolean; automationRequireApproval:boolean; automationMaxConcurrentJobs:number; automationMaxRuntimeSeconds:number; pythonExecutionBackend: 'disabled'|'docker';pythonSandboxImage:string}
type OllamaStatus = {installed: boolean; service: boolean; version: string|null; models: string[]; chatModel: boolean; embeddingModel: boolean; code: string; error: string|null}

interface Window {
  readonly secureAgent?: SecureAgentDesktopBridge
}
