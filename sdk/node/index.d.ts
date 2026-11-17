/** Native OSv Sandbox API client. Requires Node.js 20 or newer. */
export class SandboxError extends Error {}
export class ConfigurationError extends SandboxError {}
export class TransportError extends SandboxError {}
export class TimeoutException extends TransportError {}
export class ProtocolError extends SandboxError {}
export class UnsupportedCapability extends SandboxError {}
export class APIError extends SandboxError {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string);
}
export class TemplateMismatch extends APIError {}
export interface PortConnectionInfo {
  readonly id: string; readonly port: number;
  readonly status: 'opening' | 'open' | 'cancelling' | 'completed' | 'cancelled' | 'failed';
  readonly sent_bytes: number; readonly received_bytes: number; readonly error: string | null;
}
export type PortFrame = {kind: 'data'; data: Uint8Array} | {kind: 'eof'} | {kind: 'finished'; info: PortConnectionInfo};
export interface PortOpenOptions {
  connectionId?: string; maxBytes?: number; timeoutMs?: number; idleTimeoutMs?: number; requestTimeoutMs?: number;
}
export class SessionPorts {
  constructor(session: Session);
  preview(port: number, previewId: string): PreviewGrant;
  /** Create once. Uncertain errors retain a preview handle; never replay POST. */
  createPreview(port: number, options?: {previewId?: string; ttlMs?: number; requestTimeoutMs?: number}): Promise<PreviewGrant>;
  connection(port: number, connectionId: string): PortConnection;
  /** Open once. An uncertain error retains its connection handle; never replay. */
  open(port: number, options?: PortOpenOptions): Promise<PortConnection>;
}
export interface PreviewGrantInfo {
  readonly protocol: 'osv-sandbox-preview/v1';
  readonly id: string; readonly session_id: string; readonly port: number; readonly origin: string;
  readonly created_at: string; readonly expires_at: string;
  readonly status: 'active' | 'revoked' | 'expired' | 'session_closed' | 'server_closed';
}
export class PreviewGrant {
  constructor(session: Session, port: number, id: string);
  readonly id: string; readonly port: number;
  readonly created: (PreviewGrantInfo & {readonly bootstrap_url: string}) | undefined;
  readonly bootstrapURL: string | undefined;
  toJSON(): {id: string; port: number};
  info(options?: {requestTimeoutMs?: number}): Promise<PreviewGrantInfo>;
  /** Revokes browser authorization; does not prove physical guest cleanup. */
  revoke(options?: {requestTimeoutMs?: number}): Promise<PreviewGrantInfo>;
}
export class PortConnection {
  constructor(session: Session, port: number, id: string);
  readonly id: string; readonly port: number;
  toJSON(): {id: string; port: number};
  /** One 1..16384-byte frame; one write may run concurrently with one read. */
  write(data: Uint8Array): Promise<void>;
  closeWrite(): Promise<void>;
  /** Application EOF does not replace FINISHED. No automatic output accumulation. */
  readFrame(): Promise<PortFrame>;
  info(options?: {requestTimeoutMs?: number}): Promise<PortConnectionInfo>;
  cancel(options?: {requestTimeoutMs?: number}): Promise<PortConnectionInfo>;
  /** Close local transport; does not prove guest cleanup. */
  close(): void;
}
export class CodeCleanupError extends TransportError {
  constructor(execution: CodeExecution, originalError: unknown, cleanupError: unknown);
  readonly execution: CodeExecution; readonly originalError: unknown; readonly cleanupError: unknown;
  readonly ownerCloseRequested: true;
}
export class CodeExecutionFailed extends SandboxError {
  constructor(execution: CodeExecution | undefined, status: string, failure?: string | null);
  readonly execution: CodeExecution | undefined; readonly status: string; readonly failure?: string | null;
}
export interface Context { readonly id: string; readonly language: CodeLanguage; readonly cwd: string; }
export class OutputMessage {
  constructor(line: string, timestamp: number, error?: boolean);
  readonly line: string; readonly timestamp: number; readonly error: boolean;
  toString(): string;
}
export class ExecutionError {
  constructor(name: string, value: string, traceback: string);
  name: string; value: string; traceback: string;
}
export class Result {
  constructor(data: Record<string, unknown>, isMainResult: boolean);
  readonly raw: Record<string, unknown>; readonly mimeData: Record<string, unknown>; readonly extra: Record<string, unknown>;
  readonly isMainResult: boolean; readonly text?: string; readonly html?: string; readonly markdown?: string;
  readonly svg?: string; readonly png?: string; readonly jpeg?: string; readonly pdf?: string;
  readonly latex?: string; readonly json?: unknown; readonly javascript?: string;
  formats(): string[]; toJSON(): Record<string, unknown>;
}
export class Execution {
  constructor(results?: Result[], logs?: {stdout: string[]; stderr: string[]}, error?: ExecutionError, executionCount?: number);
  results: Result[]; logs: {stdout: string[]; stderr: string[]}; error?: ExecutionError;
  executionCount?: number; executionId?: string; readonly text?: string;
  toJSON(): Record<string, unknown>;
}
export interface RunCodeOptions {
  envs?: Record<string, string>; timeoutMs?: number; requestTimeoutMs?: number; signal?: AbortSignal;
  onStdout?: (output: OutputMessage) => void | Promise<void>;
  onStderr?: (output: OutputMessage) => void | Promise<void>;
  onResult?: (result: Result) => void | Promise<void>;
  onError?: (error: ExecutionError) => void | Promise<void>;
}

export interface InputFile {
  path: string;
  data: Uint8Array;
  mode?: 0 | 292;
}
export interface JobRequest {
  entrypoint: string;
  args?: string[];
  memoryMiB?: number;
  vcpus?: number;
  timeoutMs?: number;
  network?: 'none' | 'proxy';
  inputFiles?: InputFile[];
  environment?: Record<string, string>;
  stdin?: Uint8Array;
  cwd?: string;
}
export interface TemplateSelector {
  backend: string;
  artifactManifestSha256: string;
}
export interface JobResult {
  templateId?: string;
  artifactManifestSha256?: string;
  startupMode?: "cold" | "warm";
  id: string;
  state: string;
  backend: string;
  exitCode: number;
  timedOut: boolean;
  durationMs: number;
  output: string;
  outputTruncated: boolean;
  protocolOk: boolean;
  guestResult: Record<string, unknown> | null;
  succeeded: boolean;
}
export interface SessionRequest {
  memoryMiB?: number;
  vcpus?: number;
  ttlMs?: number;
  network?: 'none' | 'proxy';
  inputFiles?: InputFile[];
}
export interface SessionCommand {
  interactiveStdin?: boolean;
  entrypoint: string;
  args?: string[];
  timeoutMs?: number;
  environment?: Record<string,string>;
  cwd?: string;
}
export interface SessionInfo {
  id: string;
  state: 'running';
  backend: 'firecracker-linux';
  artifactManifestSha256: string;
  createdAt: string;
  expiresAt: string;
  network?: 'none' | 'proxy';
  startupMode?: 'cold' | 'warm';
  maxExpiresAt?: string; memoryMiB?: number; vcpus?: number; guestProtocol?: string;
}
export class Session {
  readonly code: CodeContexts;
  readonly ports: SessionPorts;
  readonly ml: SessionML;
  capabilities(options?: InferenceRequestOptions): Promise<Capabilities & {session_id:string}>;
  readonly id: string;
  readonly created: SessionInfo;
  info(): Promise<SessionInfo>;
  setTimeout(ttlMs: number): Promise<SessionInfo>;
  run(command: SessionCommand): Promise<JobResult>;
  startCommand(command: SessionCommand): Promise<CommandHandle>;
  listCommands(): Promise<CommandInfo[]>;
  connectCommand(id: string): Promise<CommandHandle>;
  startFileWatch(path: string, options?: {recursive?: boolean; includeEntry?: boolean; timeoutMs?: number}): Promise<FileWatchHandle>;
  listFileWatches(): Promise<FileWatchInfo[]>;
  close(): Promise<void>;
  readFile(path: string): Promise<Uint8Array>;
	createArtifact(path?: string, options?: InferenceRequestOptions): Promise<ArtifactInfo>;
	readArtifact(id: string, offset?: number, length?: number, options?: InferenceRequestOptions): Promise<ArtifactChunk>;
	downloadArtifact(info: ArtifactInfo, options?: InferenceRequestOptions): Promise<Uint8Array>;
	deleteArtifact(id: string, options?: InferenceRequestOptions): Promise<void>;
  writeFile(path: string, data: Uint8Array, metadata?: Record<string, string>): Promise<number>;
  listFiles(path?: string): Promise<string[]>;
  statFile(path: string): Promise<{ kind: 'file' | 'directory'; size: number }>;
  deleteFile(path: string): Promise<void>;
  makeDir(path: string): Promise<boolean>;
  renameFile(path: string, destination: string): Promise<WorkspaceEntryInfo>;
  removePath(path: string): Promise<void>;
}
export interface ArtifactInfo {
  id: string; session_id: string; path: string; source_kind: 'file'|'directory'; format: 'tar';
  size: number; sha256: string; entries: number; files: number; payload_bytes: number;
}
export interface ArtifactChunk {
  id: string; session_id: string; offset: number; total_size: number; data_base64: string;
  data_sha256: string; archive_sha256: string; eof: boolean;
}
export interface FileWatchInfo {
  id: string; session_id: string; path: string; recursive: boolean; include_entry: boolean;
  state: 'starting'|'watching'|'closed'|'failed'; created_at: string; error_code?: string;
}
export interface FileWatchEvent {sequence: number; name: string; type: 'create'|'write'|'chmod'|'rename'|'remove'; entry?: WorkspaceEntryInfo;}
export interface FileWatchPage {info: FileWatchInfo; events: FileWatchEvent[]; next_sequence: number; complete: boolean;}
export type CodeLanguage = 'python' | 'javascript' | 'typescript';
export type CodeStatus = 'running' | 'completed' | 'cancelled' | 'timed_out' | 'failed';
export interface CodeContext {
  readonly session_id: string; readonly id: string; readonly generation: number;
  readonly language: CodeLanguage; readonly cwd: string;
  readonly state: 'starting' | 'idle' | 'running' | 'interrupting' | 'stopping' | 'failed';
  readonly pid: number | null; readonly failure: string | null;
  readonly discarded_late_events: number; readonly discarded_late_bytes: number;
}
export type CodeEvent =
  | {type: 'started'}
  | {type: 'stdout' | 'stderr'; data: string}
  | {type: 'result'; data: Record<string, unknown>; is_main_result: boolean}
  | {type: 'error'; name: string; value: string; traceback: string}
  | {type: 'finished'; status: Exclude<CodeStatus, 'running'>; context_usable: boolean};
export interface CodeExecutionPage {
  session_id: string; id: string; context_id: string; generation: number; language: CodeLanguage;
  status: CodeStatus; events: Array<{sequence: number; event: CodeEvent}>;
  last_sequence: number; next_sequence: number; events_evicted: boolean; failure: string | null;
}
export interface CodeRequestOptions { requestTimeoutMs?: number; }
export interface CodeExecuteOptions extends CodeRequestOptions {
  executionId?: string; environment?: Record<string, string>; timeoutMs?: number;
}
export class CodeContexts {
  constructor(session: Session);
  create(options?: CodeRequestOptions & {language?: CodeLanguage; cwd?: string; contextId?: string}): Promise<CodeContext>;
  default(language?: CodeLanguage, options?: CodeRequestOptions): Promise<CodeContext>;
  get(contextId: string, options?: CodeRequestOptions): Promise<CodeContext>;
  list(options?: CodeRequestOptions): Promise<CodeContext[]>;
  restart(context: CodeContext, options?: CodeRequestOptions): Promise<CodeContext>;
  remove(context: CodeContext, options?: CodeRequestOptions): Promise<void>;
  connectExecution(context: CodeContext, executionId: string): CodeExecution;
  execute(context: CodeContext, code: string, options?: CodeExecuteOptions): Promise<CodeExecution>;
}
export class CodeExecution {
  constructor(controller: CodeContexts, context: CodeContext, executionId: string);
  readonly id: string; readonly context: CodeContext;
  poll(after?: number, options?: CodeRequestOptions): Promise<CodeExecutionPage>;
  cancel(options?: CodeRequestOptions): Promise<void>;
}

export class FileWatchHandle {
  readonly id: string; readonly created: FileWatchInfo;
  poll(after?: number): Promise<FileWatchPage>;
  stop(): Promise<boolean>;
}
export const FilesystemEventType: Readonly<{CHMOD:'chmod'; CREATE:'create'; REMOVE:'remove'; RENAME:'rename'; WRITE:'write'}>;
export interface FilesystemEvent {name: string; type: FileWatchEvent['type']; entry?: E2BEntryInfo;}
export interface WatchOptions {recursive?: boolean; includeEntry?: boolean; timeoutMs?: number; allowNetworkMounts?: false; onExit?: (error?: Error) => void|Promise<void>;}
export class WatchHandle {stop(): Promise<void>;}
export interface CommandInfo {
  id: string; session_id: string; state: 'running' | 'succeeded' | 'guest_error' | 'timed_out' | 'cancelled' | 'failed';
  entrypoint: string; args: string[]; started_at: string; completed_at?: string; error?: string;
  pid?: number; environment?: Record<string,string>; cwd?: string;
}
export interface CommandPage {
  info: CommandInfo; events: { sequence: number; stream: 'stdout' | 'stderr'; data_base64: string }[];
  next_sequence: number; complete: boolean;
  result?: { session_id: string; result: Record<string, unknown> };
}
export interface CommandEvent {
  sequence: number; stream?: 'stdout' | 'stderr'; data?: Uint8Array; result?: JobResult;
}
export interface CommandInputReceipt {
  session_id: string; command_id: string; sequence: number; state: "pending"|"delivered"|"closed"|"failed";
  written_bytes: number; closed: boolean; error_code?: "stdin_closed"|"stdin_io"|"command_exited";
}
export interface StdinRequestOptions { requestTimeoutMs?: number; }
export class CommandHandle {
  readonly id: string;
  readonly created: CommandInfo;
  submitStdin(data?: Uint8Array, options?: {close?:boolean;requestTimeoutMs?:number}): Promise<CommandInputReceipt>;
  pollStdin(sequence: number, requestTimeoutMs?: number): Promise<CommandInputReceipt>;
  sendStdin(data: Uint8Array, options?: StdinRequestOptions): Promise<void>;
  closeStdin(options?: StdinRequestOptions): Promise<void>;
  poll(after?: number): Promise<CommandPage>;
  kill(): Promise<boolean>;
  events(after?: number, options?: { timeoutMs?: number; signal?: AbortSignal }): AsyncGenerator<CommandEvent>;
  wait(): Promise<JobResult>;
}
export interface WorkspaceEntryInfo {
  name: string; path: string; type: 'file' | 'directory' | 'symlink' | 'other';
  size: number; mode: number; permissions: string; owner: string; group: string;
  modified_time_ms: number; symlink_target?: string; metadata?: Record<string, string>;
}
export interface E2BWriteInfo {
  name: string;
  path: string;
  type: 'file';
  metadata?: Record<string, string>;
}
export interface E2BEntryInfo {
  name: string;
  path: string;
  type?: 'file' | 'dir' | 'symlink';
  size: number;
  mode: number;
  permissions: string;
  owner: string;
  group: string;
  modifiedTime: Date;
  symlinkTarget?: string;
  metadata?: Record<string, string>;
}
export interface Capabilities {
	remote_inference_policy?: InferencePolicy;
	code_languages?: CodeLanguage[];
	code_runtime?: {
	  architecture: 'amd64' | 'arm64'; kernel_protocol: 'osv-code-kernel/v2';
	  python_version: string; node_version: string; typescript_version: string; prewarm_language: CodeLanguage;
	  runtime_inventory_sha256: string; kernel_scripts_sha256: Record<string, string>; minimum_cpu_features: string[];
	};
	 template_id?: string;
  protocol: 'osv-sandbox-capabilities/v1';
  methods: string[];
  allowed_entrypoints: string[];
  backend: string;
  artifact_authenticated?: boolean;
  artifact_manifest_sha256?: string;
  features?: Record<string, unknown>;
  [key: string]: unknown;
}
export interface TemplateCatalog {
  protocol: 'osv-sandbox-template-catalog/v1';
  default_template_id: string;
  templates: {id:string;available:boolean;unavailable_code?:string;capabilities:Capabilities}[];
}
export interface DoctorReport {
  ready: boolean;
  checks: unknown[];
  [key: string]: unknown;
}
export interface ClientOptions {
  token: string;
  certFile: string;
  keyFile: string;
  caFile?: string;
  requestTimeoutMs?: number;
}
export interface NetworkFetchResult {
  requestId: string;
  url: string;
  status: number;
  headers: Record<string,string[]>;
  body: Uint8Array;
  redirects: number;
  durationMs: number;
  requestBytes: number;
  responseBytes: number;
}
export class Client {
  constructor(baseUrl: string, options: ClientOptions);
  capabilities(options?: {template?:TemplateSelector;requestTimeoutMs?:number}): Promise<Capabilities>;
  getInferenceBill(taskId: string, options?: InferenceRequestOptions): Promise<InferenceBill>;
  templates(): Promise<TemplateCatalog>;
  doctor(): Promise<DoctorReport>;
  fetchNetwork(url: string, options?: {method?: 'GET'|'HEAD'|'POST'|'PUT'|'PATCH'|'DELETE'|'OPTIONS'; body?: Uint8Array; headers?: Record<string,string>; followRedirects?: boolean; timeoutMs?: number}): Promise<NetworkFetchResult>;
  run(job: JobRequest, options?: { template?: TemplateSelector }): Promise<JobResult>;
  runLegacy(job: JobRequest): Promise<JobResult>;
  createSession(session?: SessionRequest, options?: { template?: TemplateSelector }): Promise<Session>;
  connectSession(id: string): Promise<Session>;
  listSessions(options?: {limit?:number;cursor?:string;order?:"asc"|"desc"}): Promise<{sessions:SessionInfo[];nextCursor?:string}>;
}

export type InferenceJSON = null | boolean | number | string | InferenceJSON[] | {[key: string]: InferenceJSON};
/** Canonical unsigned 64-bit decimal strings; never floating-point amounts. */
export interface InferencePrice { readonly request_units: string; readonly input_byte_units: string; readonly output_byte_units: string; }
export interface InferencePolicy {
  readonly protocol: 'osv-sandbox-inference-capabilities/v1';
  readonly endpoints: readonly {readonly name: string; readonly price: InferencePrice}[];
  readonly max_request_bytes: number; readonly max_response_bytes: number; readonly timeout_ms: number;
  readonly max_invocations: number; readonly budget_units?: string;
}
export interface InferenceReceipt {
  readonly id: string; readonly endpoint: string; readonly state: 'reserved'|'uncertain'|'succeeded'|'failed';
  readonly epoch: string; readonly price: InferencePrice; readonly input_bytes: number; readonly max_output_bytes: number;
  readonly output_bytes: number; readonly dispatched: boolean; readonly http_status: number; readonly code?: string;
  readonly reserved_units: string; readonly settled_units: string; readonly started_at: string;
  readonly finished_at?: string; readonly duration_ms: number;
}
export interface InferenceBill {
  readonly protocol: 'osv-sandbox-inference-bill/v1'; readonly tenant: string; readonly task_id: string;
  readonly vm_id: string; readonly lease_id: string; readonly closed: boolean; readonly unit: 'microcredits';
  readonly max_invocations: number; readonly budget_units?: string; readonly settled_units: string; readonly held_units: string;
  readonly invocations: readonly InferenceReceipt[];
}
export interface InferenceRequestOptions { requestTimeoutMs?: number; signal?: AbortSignal; }
export interface InferenceOptions extends InferenceRequestOptions { invocationId?: string; timeoutMs?: number; }
export interface InferenceResult { readonly taskId: string; readonly invocationId: string; readonly invocation: InferenceReceipt; readonly data: InferenceJSON; }
export class InferenceError extends SandboxError {
  constructor(taskId: string, invocationId: string, cause: Error, attempted: boolean);
  readonly taskId: string; readonly invocationId: string; readonly cause: Error;
  readonly deliveryUnknown: boolean; readonly code: string; readonly status?: number;
}
export class SessionML {
  constructor(session: Session);
  invoke(endpoint: string, payload: InferenceJSON, options?: InferenceOptions): Promise<InferenceResult>;
  bill(options?: InferenceRequestOptions): Promise<InferenceBill>;
}

/** Explicit E2B 2.51.0 facade over one authenticated native session. */
export class Sandbox {
  readonly sandboxId: string;
  readonly files: {
    read(path: string, opts?: { format?: 'text' }): Promise<string>;
    read(path: string, opts: { format: 'bytes' }): Promise<Uint8Array>;
    exists(path: string): Promise<boolean>;
    write(path: string, data: string | ArrayBuffer | Uint8Array, options?: { metadata?: Record<string, string> }): Promise<E2BWriteInfo>;
    write(files: Array<{ path: string; data: string | ArrayBuffer | Uint8Array }>, options?: { metadata?: Record<string, string> }): Promise<E2BWriteInfo[]>;
    writeFiles(files: Array<{ path: string; data: string | ArrayBuffer | Uint8Array }>, options?: { metadata?: Record<string, string> }): Promise<E2BWriteInfo[]>;
    list(path: string, options?: { depth?: 1 }): Promise<E2BEntryInfo[]>;
    getInfo(path: string): Promise<E2BEntryInfo>;
    makeDir(path: string): Promise<boolean>;
    rename(oldPath: string, newPath: string): Promise<E2BEntryInfo>;
    remove(path: string): Promise<void>;
    watchDir(path: string, onEvent: (event: FilesystemEvent) => void|Promise<void>, options?: WatchOptions): Promise<WatchHandle>;
  };
  readonly commands: {
    run(cmd: string, options: E2BCommandOptions & { background: true }): Promise<E2BCommandHandle>;
    run(cmd: string, options?: E2BCommandOptions & { background?: false }): Promise<E2BCommandResult>;
    run(cmd: string, options: E2BCommandOptions): Promise<E2BCommandResult | E2BCommandHandle>;
    list(): Promise<E2BProcessInfo[]>;
    connect(pid: number, options?: Pick<E2BCommandOptions,'timeoutMs'|'onStdout'|'onStderr'>): Promise<E2BCommandHandle>;
    kill(pid: number): Promise<boolean>;
    sendStdin(pid: number, data: string|Uint8Array, options?: StdinRequestOptions): Promise<void>;
    closeStdin(pid: number, options?: StdinRequestOptions): Promise<void>;
  };
  static create(template: 'firecracker-linux', options: { client: Client; timeoutMs?: number }): Promise<Sandbox>;
  static connect(sandboxId: string, options: { client: Client }): Promise<Sandbox>;
  static list(options:{client:Client;limit?:number;nextToken?:string;order?:"asc"|"desc";query?:{state:["running"]}}): E2BSandboxPaginator;
  isRunning(): Promise<boolean>;
  kill(): Promise<boolean>;
  getInfo(): Promise<E2BSandboxInfo>;
  setTimeout(timeoutMs: number): Promise<void>;
  pause(...args: unknown[]): never;
  fork(...args: unknown[]): never;
  getHost(...args: unknown[]): never;
  uploadUrl(...args: unknown[]): never;
  downloadUrl(...args: unknown[]): never;
  runCode(code: string, options?: RunCodeOptions & ({language?: CodeLanguage;context?:never}|{context:Context|CodeContext;language?:never})): Promise<Execution>;
  createCodeContext(options?: {language?:CodeLanguage;cwd?:string;requestTimeoutMs?:number}): Promise<Context>;
  listCodeContexts(): Promise<Context[]>;
  restartCodeContext(context: Context | CodeContext | string): Promise<void>;
  removeCodeContext(context: Context | CodeContext | string): Promise<void>;
}

export interface E2BCommandResult { stdout: string; stderr: string; exitCode: number; error?: string; }
export interface E2BProcessInfo { pid: number; cmd: string; args: string[]; envs: Record<string,string>; cwd?: string; tag?: string; }
export interface E2BCommandOptions {
  background?: boolean; envs?: Record<string,string>; cwd?: string;
  timeoutMs?: number; stdin?: boolean; onStdout?: (text: string)=>void; onStderr?: (text:string)=>void;
}
export class CommandExitError extends SandboxError implements E2BCommandResult {
  readonly stdout: string; readonly stderr: string; readonly exitCode: number; readonly error?: string;
}
export class E2BCommandHandle {
  readonly pid: number; readonly stdout: string; readonly stderr: string;
  wait(): Promise<E2BCommandResult>; kill(): Promise<boolean>; disconnect(): Promise<void>;
  sendStdin(data: string|Uint8Array, options?: StdinRequestOptions): Promise<void>; closeStdin(options?: StdinRequestOptions): Promise<void>;
}

export interface E2BSandboxInfo {
  sandboxId:string; templateId:string; metadata:Record<string,string>; startedAt:Date; endAt:Date; maxEndAt:Date;
  state:'running'; cpuCount:number; memoryMB:number; envdVersion:string; allowInternetAccess:false;
  lifecycle:{onTimeout:'kill';autoResume:false}; volumeMounts:[];
}
export class E2BSandboxPaginator {
  readonly hasNext:boolean;readonly nextToken?:string;
  nextItems(): Promise<E2BSandboxInfo[]>;
}
