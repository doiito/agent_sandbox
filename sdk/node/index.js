/** Dependency-free Node.js client for the native OSv Sandbox API. */
import { readFileSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { randomBytes, createHash } from 'node:crypto';

const DIGEST = /^[0-9a-f]{64}$/;
const SESSION_ID = /^[0-9a-f]{24}$/;
const MAX_REQUEST = 1 << 20;
const MAX_RESPONSE = 4 << 20;
const MAX_ERROR = 64 << 10;
const SESSION_FILE_LIMIT = 512 << 10;
const SESSION_FILE_LIST_LIMIT = 256;
const SESSION_FILE_LIST_NAME_BYTES_LIMIT = 64 << 10;

export class SandboxError extends Error {}
export class ConfigurationError extends SandboxError {}
export class TransportError extends SandboxError {}
export class TimeoutException extends TransportError {}
export class ProtocolError extends SandboxError {}
export class UnsupportedCapability extends SandboxError {}
export class APIError extends SandboxError {
  constructor(status, code, message) {
    super(`HTTP ${status} ${code}: ${message}`);
    this.status = status;
    this.code = code;
  }
}
export class TemplateMismatch extends APIError {}

const PORT_MAX_BYTES = 64 << 20;
const PORT_FRAME_BYTES = 16384;
const PORT_FAILED = ['connection_refused', 'timeout', 'idle_timeout', 'connection_lost',
  'byte_limit', 'protocol_error', 'io_error'];

function portInfo(value, id, port, maximum) {
  requireObject(value, 'invalid port connection');
  const keys = ['id', 'port', 'status', 'sent_bytes', 'received_bytes', 'error'];
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key)) ||
      value.id !== id || value.port !== port || ['sent_bytes', 'received_bytes'].some(key =>
        !Number.isSafeInteger(value[key]) || value[key] < 0 || value[key] > maximum) ||
      !((['opening', 'open', 'cancelling', 'completed'].includes(value.status) && value.error === null) ||
        (value.status === 'cancelled' && ['cancelled', 'service_closed'].includes(value.error)) ||
        (value.status === 'failed' && PORT_FAILED.includes(value.error)))) {
    throw new ProtocolError('invalid port connection binding, state or counts');
  }
  return Object.freeze({...value});
}

export class SessionPorts {
  constructor(session) { this._session = session; }
  preview(port, previewId) {
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535 ||
        typeof previewId !== 'string' || !SESSION_ID.test(previewId)) {
      throw new ConfigurationError('port and previewId must be valid');
    }
    return new PreviewGrant(this._session, port, previewId);
  }
  async createPreview(port, {previewId = randomBytes(12).toString('hex'), ttlMs = 300000, requestTimeoutMs} = {}) {
    const handle = this.preview(port, previewId);
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > 300000) {
      throw new ConfigurationError('preview ttlMs must be 1000..300000');
    }
    requestTimeoutMs = codeRequestTimeout(requestTimeoutMs);
    try {
      const report = await this._session.capabilities({requestTimeoutMs});
      if (report.backend !== 'firecracker-linux' || !['osv-sandbox-artifacts/v6', 'osv-sandbox-artifacts/v7', 'osv-sandbox-artifacts/v8'].includes(report.artifact_manifest_protocol) ||
          report.features?.port_forward !== true || report.features?.port_preview !== true) {
        throw new UnsupportedCapability('selected session has no authenticated preview');
      }
      const value = await this._session._client._exchange('POST',
        `/v2/sessions/${this._session.id}/ports/${port}/previews/${handle.id}`, {ttl_ms: ttlMs}, [201], requestTimeoutMs);
      handle._created = handle._validate(value, true);
      return handle;
    } catch (error) { Object.defineProperty(error, 'preview', {value: handle, configurable: true}); throw error; }
  }
  connection(port, connectionId) {
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535 ||
        typeof connectionId !== 'string' || !SESSION_ID.test(connectionId)) {
      throw new ConfigurationError('port and connectionId must be valid');
    }
    return new PortConnection(this._session, port, connectionId);
  }
  async open(port, {connectionId = randomBytes(12).toString('hex'), maxBytes = PORT_MAX_BYTES,
    timeoutMs = 300000, idleTimeoutMs = 300000, requestTimeoutMs} = {}) {
    const handle = this.connection(port, connectionId);
    for (const [value, maximum] of [[maxBytes, PORT_MAX_BYTES], [timeoutMs, 300000], [idleTimeoutMs, 300000]]) {
      if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
        throw new ConfigurationError('port limits must be positive and within advertised maxima');
      }
    }
    codeRequestTimeout(requestTimeoutMs);
    try {
      const report = await this._session.capabilities({requestTimeoutMs});
      if (report.backend !== 'firecracker-linux' || !['osv-sandbox-artifacts/v6', 'osv-sandbox-artifacts/v7', 'osv-sandbox-artifacts/v8'].includes(report.artifact_manifest_protocol) ||
          report.features?.port_forward !== true) throw new UnsupportedCapability('selected session has no native port tunnel');
      await handle._open({max_bytes: maxBytes, timeout_ms: timeoutMs, idle_timeout_ms: idleTimeoutMs}, requestTimeoutMs);
      return handle;
    } catch (error) { Object.defineProperty(error, 'connection', {value: handle, configurable: true}); throw error; }
  }
}

/** Session-owned browser authorization. Creating never retries or renews a grant. */
export class PreviewGrant {
  [Symbol.for('nodejs.util.inspect.custom')]() { return this.toJSON(); }
  toJSON() { return {id: this.id, port: this.port}; }
  constructor(session, port, id) {
    Object.defineProperties(this, {id: {value: id, enumerable: true}, port: {value: port, enumerable: true}});
    this._session = session;
    this._path = `/v2/sessions/${session.id}/previews/${id}`;
  }
  get created() { return this._created; }
  get bootstrapURL() { return this._created?.bootstrap_url; }
  _validate(value, creating = false) {
    requireObject(value, 'invalid preview grant');
    const keys = ['protocol', 'id', 'session_id', 'port', 'origin', 'created_at', 'expires_at', 'status'];
    if (creating) keys.push('bootstrap_url');
    if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key)) ||
        value.protocol !== 'osv-sandbox-preview/v1' || value.id !== this.id || value.session_id !== this._session.id ||
        value.port !== this.port || !['active', 'revoked', 'expired', 'session_closed', 'server_closed'].includes(value.status)) {
      throw new ProtocolError('invalid preview identity or state');
    }
    const originPattern = /^https:\/\/[0-9a-f]{24}\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::[1-9][0-9]{0,4})?$/;
    let valid = typeof value.origin === 'string' && originPattern.test(value.origin);
    try { valid &&= new URL(value.origin).origin === value.origin; } catch { valid = false; }
    const dates = [previewTimestamp(value.created_at), previewTimestamp(value.expires_at)];
    valid &&= dates.every(date => date !== undefined);
    if (valid) valid &&= dates[1] > dates[0] && dates[1] - dates[0] <= 300000000000n;
    if (creating) valid &&= value.status === 'active' && typeof value.bootstrap_url === 'string' &&
      value.bootstrap_url.startsWith(value.origin + '/.osv/authorize?token=') &&
      /^[0-9a-f]{64}$/.test(value.bootstrap_url.slice((value.origin + '/.osv/authorize?token=').length));
    if (this._created) valid &&= ['origin', 'created_at', 'expires_at'].every(key => value[key] === this._created[key]);
    if (!valid) throw new ProtocolError('invalid preview origin, lifetime or bootstrap URL');
    return Object.freeze({...value});
  }
  async info({requestTimeoutMs} = {}) {
    requestTimeoutMs = codeRequestTimeout(requestTimeoutMs);
    return this._validate(await this._session._client._exchange('GET', this._path, undefined, [200], requestTimeoutMs));
  }
  async revoke({requestTimeoutMs} = {}) {
    requestTimeoutMs = codeRequestTimeout(requestTimeoutMs);
    const value = this._validate(await this._session._client._exchange('DELETE', this._path, undefined, [200], requestTimeoutMs));
    if (value.status === 'active') throw new ProtocolError('preview revocation response is still active');
    return value;
  }
}

function previewTimestamp(text) {
  if (typeof text !== 'string') return undefined;
  const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/.exec(text);
  if (!match) return undefined;
  const local = Date.parse(match[1] + 'Z'), epoch = Date.parse(match[1] + match[3]);
  if (!Number.isFinite(local) || !Number.isFinite(epoch) || new Date(local).toISOString().slice(0, 19) !== match[1]) return undefined;
  return BigInt(epoch) * 1000000n + BigInt((match[2] ?? '').padEnd(9, '0'));
}

/** Native duplex tunnel. EOF is distinct from FINISHED; local close does not confirm guest cleanup. */
export class PortConnection {
  [Symbol.for('nodejs.util.inspect.custom')]() { return {id: this.id, port: this.port}; }
  toJSON() { return {id: this.id, port: this.port}; }
  constructor(session, port, id) {
    Object.defineProperties(this, {id: {value: id, enumerable: true}, port: {value: port, enumerable: true}});
    this._session = session;
    this._path = `/v2/sessions/${session.id}/ports/${port}/connections/${id}`;
    this._maximum = PORT_MAX_BYTES;
    this._written = this._received = 0;
    this._readEOF = this._writeEOF = this._closed = this._expired = false;
    this._reading = this._writing = false;
  }
  async _open(limits, requestTimeoutMs) {
    const client = this._session._client;
    this._maximum = limits.max_bytes;
    this._timer = setTimeout(() => { this._expired = true; this.close(); }, limits.timeout_ms);
    this._timer.unref?.();
    const body = Buffer.from(JSON.stringify(limits));
    try {
      await new Promise((resolve, reject) => {
        let settled = false;
        const fail = error => {
          if (settled) return;
          settled = true;
          clearTimeout(handshakeTimer);
          this.close();
          reject(error);
        };
        const req = this._request = httpsRequest({
          hostname: client._url.hostname, port: client._url.port || 443, method: 'POST', path: this._path,
          agent: false, ...client._tls, ALPNProtocols: ['http/1.1'], maxHeaderSize: 8192,
          headers: {Authorization: `Bearer ${client._token}`, 'Content-Type': 'application/json',
            'Content-Length': body.length, Connection: 'Upgrade', Upgrade: 'osv-port/1'}
        });
        const handshakeTimer = setTimeout(() => {
          fail(new TimeoutException('port open deadline elapsed; query known ID'));
        }, Math.min(client._timeout, requestTimeoutMs ?? client._timeout, limits.timeout_ms));
        handshakeTimer.unref?.();
        req.on('error', () => fail(this._expired ? new TimeoutException('port connection deadline elapsed; query known ID') :
          new TransportError('port open transport failed')));
        req.on('response', response => {
          if (response.statusCode >= 300 && response.statusCode < 400) {
            response.destroy(); fail(new ProtocolError('server redirected a port request')); return;
          }
          const chunks = []; let size = 0;
          response.on('data', chunk => {
            size += chunk.length;
            if (size > MAX_ERROR) { response.destroy(); fail(new ProtocolError('port error response exceeds limit')); }
            else chunks.push(chunk);
          });
          response.on('error', () => fail(new TransportError('port open response failed')));
          response.on('end', () => {
            let code = 'api_error';
            try { const value = JSON.parse(Buffer.concat(chunks).toString('utf8')); if (/^[a-z0-9_]{1,64}$/.test(value.code)) code = value.code; } catch {}
            fail(new APIError(response.statusCode ?? 0, code, 'port open rejected'));
          });
        });
        req.on('upgrade', (response, socket, head) => {
          this._socket = socket;
          // An error listener remains for the entire lifetime, including periods
          // without a pending read/write. No data listener or unbounded queue.
          socket.on('error', () => { this._socketFailed = true; });
          const expected = {'upgrade': 'osv-port/1', 'x-osv-session-id': this._session.id,
            'x-osv-connection-id': this.id, 'x-osv-port': String(this.port)};
          const valid = response.statusCode === 101 && response.httpVersion === '1.1' &&
            String(response.headers.connection ?? '').split(',').some(value => value.trim().toLowerCase() === 'upgrade') &&
            Object.entries(expected).every(([key, value]) => response.headers[key] === value &&
              response.rawHeaders.filter((item, index) => index % 2 === 0 && item.toLowerCase() === key).length === 1);
          if (settled || this._closed || !valid) {
            socket.destroy();
            fail(new ProtocolError('invalid port upgrade binding')); return;
          }
          socket.setTimeout(0);
          if (head.length) socket.unshift(head);
          settled = true; clearTimeout(handshakeTimer); resolve();
        });
        req.end(body);
      });
    } catch (error) { this.close(); throw error; }
  }
  close() {
    this._closed = true;
    clearTimeout(this._timer);
    this._socket?.destroy();
    this._request?.destroy();
  }
  _checkStream() {
    if (this._expired) throw new TimeoutException('port connection deadline elapsed; query known ID');
    if (this._closed || !this._socket || this._socketFailed || this._socket.destroyed) {
      throw new TransportError('port transport is closed; query known ID');
    }
  }
  async write(data) {
    if (!(data instanceof Uint8Array) || data.length < 1 || data.length > PORT_FRAME_BYTES) {
      throw new ConfigurationError('port DATA must be 1..16384 bytes');
    }
    await this._send(1, data);
  }
  async closeWrite() { await this._send(2, new Uint8Array()); }
  async _send(kind, data) {
    if (this._writing) throw new ConfigurationError('port write already in progress');
    this._writing = true;
    try {
      this._checkStream();
      if (this._writeEOF || data.length > this._maximum - this._written) {
        throw new ConfigurationError('port write is closed or exceeds byte limit');
      }
      this._written += data.length;
      this._writeEOF = kind === 2;
      const frame = Buffer.alloc(5 + data.length);
      frame[0] = kind; frame.writeUInt32BE(data.length, 1); frame.set(data, 5);
      try {
        await new Promise((resolve, reject) => {
          const socket = this._socket;
          const cleanup = () => { socket.off('error', failed); socket.off('close', failed); };
          const failed = () => { cleanup(); reject(new TransportError('port write outcome unknown; query known ID')); };
          socket.once('error', failed); socket.once('close', failed);
          socket.write(frame, error => { cleanup(); if (error) reject(new TransportError('port write outcome unknown; query known ID')); else resolve(); });
        });
      } catch (error) { this.close(); if (this._expired) throw new TimeoutException('port connection deadline elapsed; query known ID'); throw error; }
    } finally { this._writing = false; }
  }
  async _exact(size) {
    const chunks = []; let total = 0;
    while (total < size) {
      const socket = this._socket;
      // Read buffered bytes before inspecting end/close, retaining a FINISHED
      // coalesced with TLS EOF. At most one frame is allocated by this reader.
      const chunk = socket.read(Math.min(size - total, socket.readableLength || size - total));
      if (chunk !== null) { chunks.push(chunk); total += chunk.length; continue; }
      if (socket.readableEnded || socket.destroyed || this._socketFailed || this._closed) {
        this._checkStream(); throw new TransportError('port ended without complete terminal proof; query known ID');
      }
      await new Promise(resolve => {
        const wake = () => { for (const event of ['readable', 'end', 'close', 'error']) socket.off(event, wake); resolve(); };
        for (const event of ['readable', 'end', 'close', 'error']) socket.once(event, wake);
        if (socket.readableLength || socket.readableEnded || socket.destroyed || this._closed) wake();
      });
    }
    return Buffer.concat(chunks, size);
  }
  async readFrame() {
    if (this._reading) throw new ConfigurationError('port read already in progress');
    this._reading = true;
    try {
      if (this._closed || !this._socket) this._checkStream();
      const header = await this._exact(5), kind = header[0], size = header.readUInt32BE(1);
      if (kind === 1 && !this._readEOF && size >= 1 && size <= Math.min(PORT_FRAME_BYTES, this._maximum - this._received)) {
        const data = await this._exact(size); this._received += size; return {kind: 'data', data};
      }
      if (kind === 2 && size === 0 && !this._readEOF) { this._readEOF = true; return {kind: 'eof'}; }
      if (kind === 4 && size >= 1 && size <= 4096) {
        const bytes = await this._exact(size); let value;
        try { value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)); }
        catch { throw new ProtocolError('invalid port terminal JSON'); }
        const info = portInfo(value, this.id, this.port, this._maximum);
        if (!['completed', 'cancelled', 'failed'].includes(info.status) || info.received_bytes !== this._received ||
            info.sent_bytes > this._written || (info.status === 'completed' &&
              (!this._readEOF || !this._writeEOF || info.sent_bytes !== this._written))) {
          throw new ProtocolError('invalid port terminal proof');
        }
        this.close(); return {kind: 'finished', info};
      }
      throw new ProtocolError('invalid port frame');
    } catch (error) { this.close(); if (this._expired) throw new TimeoutException('port connection deadline elapsed; query known ID'); throw error; }
    finally { this._reading = false; }
  }
  async _control(method, {requestTimeoutMs} = {}) {
    codeRequestTimeout(requestTimeoutMs);
    const value = await this._session._client._exchange(method, this._path, undefined, method === 'DELETE' ? [202] : [200], requestTimeoutMs);
    if (value.session_id !== this._session.id) throw new ProtocolError('port control session mismatch');
    return portInfo(value.connection, this.id, this.port, this._maximum);
  }
  async info(options) { return this._control('GET', options); }
  async cancel(options) { return this._control('DELETE', options); }
}

function requireObject(value, message) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new ProtocolError(message);
  }
  return value;
}

function cleanPath(path) {
  return typeof path === 'string' && path.length > 0 && !path.startsWith('/') &&
    !path.includes('\\') && !/[\x00-\x1f\x7f]/.test(path) &&
    path.split('/').every(part => part !== '' && part !== '.' && part !== '..');
}

function cleanWorkspacePath(path, allowRoot = false) {
  if (allowRoot && path === '/workspace') return true;
  return typeof path === 'string' && path.startsWith('/workspace/') &&
    Buffer.byteLength(path, 'utf8') <= '/workspace/'.length + 1024 &&
    !path.includes('\\') && !/\p{Cc}/u.test(path) &&
    path.slice('/workspace/'.length).split('/').every(part =>
      part !== '' && part !== '.' && part !== '..' && Buffer.byteLength(part, 'utf8') <= 255);
}

function positiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new ConfigurationError(`${name} must be a positive integer`);
  }
}

function inputFilesPayload(files) {
  if (!Array.isArray(files) || files.length > 64) {
    throw new ConfigurationError('inputFiles exceed 64 files');
  }
  let total = 0;
  const seen = new Set();
  return files.map(file => {
    if (file === null || typeof file !== 'object' || !cleanPath(file.path) || seen.has(file.path)) {
      throw new ConfigurationError('input file path must be unique and relative');
    }
    seen.add(file.path);
    if (!(file.data instanceof Uint8Array)) {
      throw new ConfigurationError('input file data must be Uint8Array');
    }
    total += file.data.byteLength;
    if (total > 512 * 1024) throw new ConfigurationError('inputFiles exceed 512 KiB');
    const mode = file.mode ?? 0o444;
    if (mode !== 0 && mode !== 0o444) throw new ConfigurationError('input file mode must be 0 or 0444');
    return { path: file.path, data: Buffer.from(file.data).toString('base64'), mode };
  });
}

function commandFields(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      typeof value.entrypoint !== 'string' || !value.entrypoint) {
    throw new ConfigurationError('entrypoint is required');
  }
  const args = value.args ?? [];
  if (!Array.isArray(args) || args.length > 64 || args.some(arg => typeof arg !== 'string') ||
      Buffer.byteLength(args.join(''), 'utf8') > 32 * 1024) {
    throw new ConfigurationError('args must contain at most 64 strings and 32 KiB');
  }
  const payload = { entrypoint: value.entrypoint, args };
  if (value.timeoutMs !== undefined) {
    positiveInteger(value.timeoutMs, 'timeoutMs');
    payload.timeout_ms = value.timeoutMs;
  }
  if (value.environment !== undefined) {
    requireObject(value.environment, 'environment must be an object');
    let total = 0;
    const entries=Object.entries(value.environment);
    if(entries.length>32)throw new ConfigurationError('environment exceeds 32 entries');
    for(const [name,item] of entries){
      if(!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(name) || typeof item!=='string' || item.includes('\0') || Buffer.byteLength(item)>1024)throw new ConfigurationError('invalid environment name or value');
      total+=name.length+Buffer.byteLength(item);
    }
    if(total>8192)throw new ConfigurationError('environment exceeds 8 KiB');
    payload.environment=value.environment;
  }
  if(value.cwd!==undefined){
    if(typeof value.cwd!=='string' || !value.cwd.startsWith('/') || Buffer.byteLength(value.cwd)>1024 || /[\p{Cc}]/u.test(value.cwd))throw new ConfigurationError('cwd must be a guest absolute path');
    payload.cwd=value.cwd;
  }
  if(value.interactiveStdin!==undefined){
    if(typeof value.interactiveStdin!=="boolean")throw new ConfigurationError("interactiveStdin must be boolean");
    payload.interactive_stdin=value.interactiveStdin;
  }
  return payload;
}

function jobPayload(job) {
  if(job.interactiveStdin!==undefined)throw new UnsupportedCapability('interactive stdin is a session command option');
  const payload = { ...commandFields(job), network: job.network ?? 'none' };
  if (job.network !== undefined && !['none','proxy'].includes(job.network)) {
    throw new UnsupportedCapability('network must be none or proxy');
  }
  const inputFiles = inputFilesPayload(job.inputFiles ?? []);
  for (const [camel, wire] of [['memoryMiB', 'memory_mib'], ['vcpus', 'vcpus']]) {
    if (job[camel] !== undefined) {
      positiveInteger(job[camel], camel);
      payload[wire] = job[camel];
    }
  }
  if (inputFiles.length) payload.input_files = inputFiles;
  if (job.environment !== undefined) {
    if (job.environment === null || typeof job.environment !== 'object' || Array.isArray(job.environment)) {
      throw new ConfigurationError('environment must be an object');
    }
    const entries = Object.entries(job.environment);
    if (entries.length > 32) throw new ConfigurationError('environment exceeds 32 entries');
    let total = 0;
    for (const [name, value] of entries) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || Buffer.byteLength(name) > 64 ||
          typeof value !== 'string' || value.includes('\0')) {
        throw new ConfigurationError('invalid environment name or value');
      }
      const size = Buffer.byteLength(value, 'utf8');
      if (size > 1024) throw new ConfigurationError('environment value exceeds 1024 bytes');
      total += Buffer.byteLength(name) + size;
    }
    if (total > 8192) throw new ConfigurationError('environment exceeds 8192 bytes');
    if (entries.length) payload.environment = job.environment;
  }
  if (job.stdin !== undefined) {
    if (!(job.stdin instanceof Uint8Array) || job.stdin.byteLength > 16384) {
      throw new ConfigurationError('stdin must be at most 16 KiB of bytes');
    }
    payload.stdin = Buffer.from(job.stdin).toString('base64');
  }
  return payload;
}

function sessionPayload(session) {
  if (session === null || typeof session !== 'object' || Array.isArray(session)) {
    throw new ConfigurationError('session options must be an object');
  }
  if (session.network !== undefined && !['none','proxy'].includes(session.network)) {
    throw new UnsupportedCapability('network must be none or proxy');
  }
  const payload = { network: session.network ?? 'none' };
  for (const [camel, wire] of [['memoryMiB', 'memory_mib'], ['vcpus', 'vcpus']]) {
    if (session[camel] !== undefined) {
      positiveInteger(session[camel], camel);
      payload[wire] = session[camel];
    }
  }
  if (session.ttlMs !== undefined) {
    if (!Number.isSafeInteger(session.ttlMs) || session.ttlMs < 1000 || session.ttlMs > 300000) {
      throw new ConfigurationError('ttlMs must be in [1000,300000]');
    }
    payload.ttl_ms = session.ttlMs;
  }
  const files = inputFilesPayload(session.inputFiles ?? []);
  if (files.length) payload.input_files = files;
  return payload;
}

function selector(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      typeof value.backend !== 'string' || !value.backend ||
      typeof value.artifactManifestSha256 !== 'string' || !DIGEST.test(value.artifactManifestSha256)) {
    throw new ConfigurationError('template requires backend and lowercase SHA-256 digest');
  }
  return value;
}

function jobResult(value) {
  requireObject(value, 'job result is not an object');
  for (const key of ['id', 'state', 'backend', 'output']) {
    if (typeof value[key] !== 'string') throw new ProtocolError(`job result has invalid ${key}`);
  }
  for (const key of ['exit_code', 'duration_ms']) {
    if (!Number.isSafeInteger(value[key])) throw new ProtocolError(`job result has invalid ${key}`);
  }
  for (const key of ['timed_out', 'output_truncated', 'protocol_ok']) {
    if (typeof value[key] !== 'boolean') throw new ProtocolError(`job result has invalid ${key}`);
  }
  if (value.guest_result != null) requireObject(value.guest_result, 'job result has invalid guest_result');
  if(value.startup_mode!==undefined&&!['warm','cold'].includes(value.startup_mode))throw new ProtocolError('job result has invalid startup_mode');
  if(value.artifact_manifest_sha256!==undefined&&(typeof value.artifact_manifest_sha256!=='string'||!/^[0-9a-f]{64}$/.test(value.artifact_manifest_sha256)))throw new ProtocolError('job result has invalid template digest');
  if(value.template_id!==undefined&&(typeof value.template_id!=='string'||!/^[A-Za-z0-9_-]{1,32}$/.test(value.template_id)))throw new ProtocolError('job result has invalid template id');
  return {
    id: value.id, state: value.state, backend: value.backend,
    ...(value.startup_mode===undefined?{}:{startupMode:value.startup_mode}),
    ...(value.template_id===undefined?{}:{templateId:value.template_id}),
    ...(value.artifact_manifest_sha256===undefined?{}:{artifactManifestSha256:value.artifact_manifest_sha256}),
    exitCode: value.exit_code, timedOut: value.timed_out, durationMs: value.duration_ms,
    output: value.output, outputTruncated: value.output_truncated,
    protocolOk: value.protocol_ok, guestResult: value.guest_result ?? null,
    succeeded: value.state === 'succeeded' && value.protocol_ok === true
  };
}

function sessionInfo(value) {
  requireObject(value, 'session info is not an object');
  for (const key of ['id', 'state', 'backend', 'artifact_manifest_sha256', 'created_at', 'expires_at']) {
    if (typeof value[key] !== 'string' || !value[key]) throw new ProtocolError(`session info has invalid ${key}`);
  }
  if (!SESSION_ID.test(value.id) || value.state !== 'running' || value.backend !== 'firecracker-linux' ||
      !DIGEST.test(value.artifact_manifest_sha256)) {
    throw new ProtocolError('session info has invalid identity or template');
  }
  for(const key of ['memory_mib','vcpus'])if(value[key]!==undefined&&(!Number.isSafeInteger(value[key])||value[key]<=0))throw new ProtocolError('invalid session resource metadata');
  if(value.max_expires_at!==undefined&&typeof value.max_expires_at!=='string')throw new ProtocolError('invalid session lifetime bound');
  if(value.guest_protocol!==undefined&&!['fc-agent/v2','fc-agent/v3'].includes(value.guest_protocol))throw new ProtocolError('invalid session guest protocol');
  if(value.network!==undefined&&!['none','proxy'].includes(value.network))throw new ProtocolError('invalid session network');
  if(value.startup_mode!==undefined&&!['cold','warm'].includes(value.startup_mode))throw new ProtocolError('invalid session startup mode');
  return { id: value.id, state: value.state, backend: value.backend,
    artifactManifestSha256: value.artifact_manifest_sha256,
    createdAt: value.created_at, expiresAt: value.expires_at,
    network:value.network??'none',
    ...(value.startup_mode===undefined?{}:{startupMode:value.startup_mode}),
    ...(value.max_expires_at===undefined?{}:{maxExpiresAt:value.max_expires_at}),
    ...(value.memory_mib===undefined?{}:{memoryMiB:value.memory_mib}),
    ...(value.vcpus===undefined?{}:{vcpus:value.vcpus}),
    ...(value.guest_protocol===undefined?{}:{guestProtocol:value.guest_protocol}) };
}

function artifactInfo(value, sessionId) {
  requireObject(value, 'invalid artifact metadata');
  if (!cleanWorkspacePath(value.path, true) || Buffer.from(value.path).toString('utf8') !== value.path ||
      typeof value.id !== 'string' || !SESSION_ID.test(value.id) || value.session_id !== sessionId ||
      !cleanWorkspacePath(value.path, true) || !['file','directory'].includes(value.source_kind) || value.format !== 'tar' ||
      (value.path === '/workspace' && value.source_kind !== 'directory') ||
      !Number.isSafeInteger(value.size) || value.size < 2048 || value.size > (32 << 20) || value.size % 512 !== 0 ||
      typeof value.sha256 !== 'string' || !DIGEST.test(value.sha256) ||
      ['entries','files','payload_bytes'].some(key => !Number.isSafeInteger(value[key]) || value[key] < 0) ||
      value.files > value.entries || value.entries > 1024 || value.payload_bytes > value.size ||
      (value.files === 0 && value.payload_bytes !== 0) || (value.source_kind === 'file' && (value.files !== 1 || value.entries !== 1))) {
    throw new ProtocolError('invalid artifact metadata binding or limits');
  }
  return Object.freeze({...value});
}

function artifactChunk(value, sessionId, id, offset, length) {
  requireObject(value, 'invalid artifact chunk');
  if (value.id !== id || value.session_id !== sessionId || value.offset !== offset ||
      !Number.isSafeInteger(value.total_size) || value.total_size < 2048 || value.total_size > (32 << 20) || value.total_size % 512 !== 0 || offset > value.total_size ||
      typeof value.eof !== 'boolean' || ['data_sha256','archive_sha256'].some(key => typeof value[key] !== 'string' || !DIGEST.test(value[key])) ||
      typeof value.data_base64 !== 'string' || value.data_base64.length > 699052) {
    throw new ProtocolError('invalid artifact chunk binding or limits');
  }
  const data = Buffer.from(value.data_base64, 'base64');
  if (data.toString('base64') !== value.data_base64 || data.length !== Math.min(length, value.total_size-offset) ||
      value.eof !== (offset+data.length === value.total_size) || createHash('sha256').update(data).digest('hex') !== value.data_sha256) {
    throw new ProtocolError('artifact chunk integrity check failed');
  }
  return Object.freeze({...value});
}

export class Session {
  constructor(client, info) {
    this._client = client;
    this.id = info.id;
    this.created = info;
    this.code = new CodeContexts(this);
    this.ports = new SessionPorts(this);
    this.ml = new SessionML(this);
  }

  async capabilities(options = {}) {
    const {requestTimeoutMs, signal} = codeOptions(options, ['requestTimeoutMs', 'signal']);
    const report = await this._client._exchange('GET', `/v2/sessions/${this.id}/capabilities`, undefined, [200], codeRequestTimeout(requestTimeoutMs), signal);
    capabilityReport(report, {backend: this.created.backend, artifactManifestSha256: this.created.artifactManifestSha256});
    if (report.session_id !== this.id || report.artifact_authenticated !== true) throw new ProtocolError('session capabilities have invalid owner or authentication');
    return report;
  }

  async startFileWatch(path, options = {}) {
    if (!cleanWorkspacePath(path, true)) throw new ConfigurationError('watch directory must be a clean /workspace path');
    if (options == null || typeof options !== 'object' || Array.isArray(options) || Object.keys(options).some(k => !['recursive', 'includeEntry', 'timeoutMs'].includes(k))) throw new ConfigurationError('invalid watch options');
    const { recursive = false, includeEntry = false, timeoutMs = 0 } = options;
    if (typeof recursive !== 'boolean' || typeof includeEntry !== 'boolean' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 600000) throw new ConfigurationError('invalid watch options');
    const info = await this._client._exchange('POST', `/v2/sessions/${this.id}/watches`, { path, recursive, include_entry: includeEntry, timeout_ms: timeoutMs }, [201]);
    const handle = new FileWatchHandle(this, info);
    if (info.path !== path || info.recursive !== recursive || info.include_entry !== includeEntry) throw new ProtocolError('watch creation options differ from request');
    return handle;
  }

  async listFileWatches() {
    const value = await this._client._exchange('GET', `/v2/sessions/${this.id}/watches`);
    if (value.session_id !== this.id || !Array.isArray(value.watches) || value.watches.length > 16) throw new ProtocolError('invalid watch list');
    for (const info of value.watches) watchInfo(info, this.id);
    return value.watches;
  }

  async setTimeout(ttlMs){
    if(!Number.isSafeInteger(ttlMs)||ttlMs<1000||ttlMs>300000)throw new ConfigurationError('ttlMs must be in [1000,300000]');
    const info=sessionInfo(await this._client._exchange('POST',`/v2/sessions/${this.id}/timeout`,{ttl_ms:ttlMs}));
    if(info.id!==this.id)throw new ProtocolError('timeout response session mismatch');return info;
  }
  async startCommand(command) {
    const info = await this._client._exchange('POST', `/v2/sessions/${this.id}/commands/start`,
      commandFields(command), [202]);
    return new CommandHandle(this, info);
  }

  async listCommands() {
    const value = await this._client._exchange('GET', `/v2/sessions/${this.id}/commands`);
    if (value.session_id !== this.id || !Array.isArray(value.commands) || value.commands.length > 32) {
      throw new ProtocolError('command list has invalid session binding');
    }
    for (const info of value.commands) commandInfo(info, this.id);
    return value.commands;
  }

  async connectCommand(id) {
    if (typeof id !== 'string' || !SESSION_ID.test(id)) throw new ConfigurationError('invalid command ID');
    const value = await this._client._exchange('GET', `/v2/sessions/${this.id}/commands/${id}`);
    const handle = new CommandHandle(this, value.info);
    if (handle.id !== id) throw new ProtocolError('command query returned another ID');
    return handle;
  }

  async info() {
    const value = sessionInfo(await this._client._exchange('GET', `/v2/sessions/${this.id}`));
    if (value.id !== this.id) throw new ProtocolError('session query returned a different ID');
    return value;
  }

  async run(command) {
    const value = await this._client._exchange('POST', `/v2/sessions/${this.id}/commands`,
      commandFields(command));
    if (value.session_id !== this.id) throw new ProtocolError('session command result has invalid binding');
    return jobResult(value.result);
  }

  async close() {
    await this._client._exchange('DELETE', `/v2/sessions/${this.id}`, undefined, [204]);
  }

  async _file(action, path, data, metadata) {
    if (!cleanWorkspacePath(path)) {
      throw new ConfigurationError('file path must be a clean /workspace path');
    }
    const payload = { action, path };
    if (action === 'write') {
      if (!(data instanceof Uint8Array) || data.byteLength > SESSION_FILE_LIMIT) {
        throw new ConfigurationError('file data must be Uint8Array at most 512 KiB');
      }
      payload.data_base64 = Buffer.from(data).toString('base64');
      if (metadata !== undefined) {
        validateE2BMetadata(metadata);
        payload.metadata = metadata;
      }
    } else if (metadata !== undefined) {
      throw new ConfigurationError('metadata is only valid for file writes');
    }
    const value = await this._client._exchange('POST', `/v2/sessions/${this.id}/files`, payload);
    if (value.session_id !== this.id || value.action !== action || value.path !== path ||
        !Number.isSafeInteger(value.size) || value.size < 0 || value.size > SESSION_FILE_LIMIT ||
        Object.hasOwn(value, 'kind') || Object.hasOwn(value, 'entries') || Object.hasOwn(value, 'created')) {
      throw new ProtocolError('session file result has invalid binding');
    }
    if (action === 'write') {
      if (value.size !== data.byteLength || Object.hasOwn(value, 'data_base64')) {
        throw new ProtocolError('session file write result is invalid');
      }
      return value.size;
    }
    if (typeof value.data_base64 !== 'string') throw new ProtocolError('session file read has no data');
    const bytes = Buffer.from(value.data_base64, 'base64');
    if (bytes.toString('base64') !== value.data_base64 || bytes.byteLength !== value.size) {
      throw new ProtocolError('session file read has invalid bytes');
    }
    return bytes;
  }

  async readFile(path) {
    return this._file('read', path);
  }

  async createArtifact(path = '/workspace', options = {}) {
    if (!cleanWorkspacePath(path, true) || Buffer.from(path).toString('utf8') !== path) throw new ConfigurationError('artifact source must be a clean workspace path');
    const {requestTimeoutMs = 35000, signal} = codeOptions(options, ['requestTimeoutMs','signal']);
    const value = await this._client._exchange('POST', `/v2/sessions/${this.id}/artifacts`, {path}, [201], codeRequestTimeout(requestTimeoutMs), signal);
    const info = artifactInfo(value, this.id);
    if (info.path !== path) throw new ProtocolError('artifact response source differs from request');
    return info;
  }

  async readArtifact(id, offset = 0, length = 512 << 10, options = {}) {
    if (typeof id !== 'string' || !SESSION_ID.test(id)) throw new ConfigurationError('artifact ID must be 24 lowercase hex digits');
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > (32 << 20) || !Number.isSafeInteger(length) || length < 1 || length > (512 << 10)) throw new ConfigurationError('invalid artifact byte range');
    const {requestTimeoutMs, signal} = codeOptions(options, ['requestTimeoutMs','signal']);
    const value = await this._client._exchange('POST', `/v2/sessions/${this.id}/artifacts/${id}/read`, {offset,length}, [200], codeRequestTimeout(requestTimeoutMs), signal);
    return artifactChunk(value, this.id, id, offset, length);
  }

  async downloadArtifact(metadata, options = {}) {
    const info = artifactInfo(metadata, this.id);
    const {requestTimeoutMs, signal} = codeOptions(options, ['requestTimeoutMs','signal']);
    codeRequestTimeout(requestTimeoutMs);
    const content = Buffer.alloc(info.size);
    for (let offset = 0; offset < info.size;) {
      const chunk = await this.readArtifact(info.id, offset, Math.min(512 << 10, info.size-offset), {requestTimeoutMs,signal});
      if (chunk.total_size !== info.size || chunk.archive_sha256 !== info.sha256) throw new ProtocolError('artifact changed between create and download');
      const data = Buffer.from(chunk.data_base64, 'base64');
      data.copy(content, offset);
      offset += data.length;
    }
    if (createHash('sha256').update(content).digest('hex') !== info.sha256) throw new ProtocolError('complete artifact integrity check failed');
    return content;
  }

  async deleteArtifact(id, options = {}) {
    if (typeof id !== 'string' || !SESSION_ID.test(id)) throw new ConfigurationError('artifact ID must be 24 lowercase hex digits');
    const {requestTimeoutMs, signal} = codeOptions(options, ['requestTimeoutMs','signal']);
    await this._client._exchange('DELETE', `/v2/sessions/${this.id}/artifacts/${id}`, undefined, [204], codeRequestTimeout(requestTimeoutMs), signal);
  }

  async writeFile(path, data, metadata) {
    return this._file('write', path, data, metadata);
  }

  async _fileMetadata(action, path, destination) {
    if (!cleanWorkspacePath(path, action === 'list' || action === 'stat' || action === 'info')) {
      throw new ConfigurationError('file path must be a clean /workspace path');
    }
    if (destination !== undefined && !cleanWorkspacePath(destination)) {
      throw new ConfigurationError('destination must be a clean /workspace path');
    }
    const payload = { action, path };
    if (destination !== undefined) payload.destination = destination;
    const value = await this._client._exchange('POST', `/v2/sessions/${this.id}/files`, payload);
    if (value.session_id !== this.id || value.action !== action || value.path !== path ||
        !Number.isSafeInteger(value.size) || value.size < 0 || Object.hasOwn(value, 'data_base64') ||
        value.destination !== destination) {
      throw new ProtocolError('session file metadata result has invalid binding');
    }
    return value;
  }

  async listFiles(path = '/workspace') {
    const value = await this._fileMetadata('list', path);
    if (!Array.isArray(value.entries) || value.entries.length > SESSION_FILE_LIST_LIMIT ||
        value.size !== value.entries.length || Object.hasOwn(value, 'kind') || Object.hasOwn(value, 'created')) {
      throw new ProtocolError('session file list is invalid');
    }
    let total = 0;
    let previous = '';
    for (const name of value.entries) {
      if (typeof name !== 'string' || !name || name === '.' || name === '..' ||
          name.includes('/') || name.includes('\\') || /\p{Cc}/u.test(name) ||
          Buffer.byteLength(name, 'utf8') > 255 || (previous && previous >= name)) {
        throw new ProtocolError('session file list has invalid name');
      }
      total += Buffer.byteLength(name, 'utf8');
      if (total > SESSION_FILE_LIST_NAME_BYTES_LIMIT) throw new ProtocolError('session file list exceeds 64 KiB');
      previous = name;
    }
    return value.entries;
  }

  async statFile(path) {
    const value = await this._fileMetadata('stat', path);
    if (Object.hasOwn(value, 'entries') || Object.hasOwn(value, 'created') ||
        !((value.kind === 'file' && value.size <= 2 ** 40) ||
          (value.kind === 'directory' && value.size === 0))) {
      throw new ProtocolError('session file stat is invalid');
    }
    return { kind: value.kind, size: value.size };
  }

  async deleteFile(path) {
    const value = await this._fileMetadata('delete', path);
    if (value.size !== 0 || Object.hasOwn(value, 'kind') || Object.hasOwn(value, 'entries') ||
        Object.hasOwn(value, 'created')) {
      throw new ProtocolError('session file delete result is invalid');
    }
  }

  async makeDir(path) {
    if (!cleanWorkspacePath(path) || path.slice('/workspace/'.length).split('/').length > 16) {
      throw new ConfigurationError('directory path must be clean and at most 16 components');
    }
    const value = await this._fileMetadata('mkdir', path);
    if (value.size !== 0 || Object.hasOwn(value, 'kind') || Object.hasOwn(value, 'entries') ||
        typeof value.created !== 'boolean') {
      throw new ProtocolError('session directory result is invalid');
    }
    return value.created;
  }

  async renameFile(path, destination) {
    if (!cleanWorkspacePath(destination)) throw new ConfigurationError('destination must be a clean /workspace path');
    const value = await this._fileMetadata('rename', path, destination);
    e2bEntryInfo(value.info, destination);
    if (value.kind !== value.info.type || Object.hasOwn(value, 'entries') || Object.hasOwn(value, 'created') ||
        value.size !== (value.info.type === 'file' ? value.info.size : 0)) {
      throw new ProtocolError('rename result has invalid metadata');
    }
    return value.info;
  }

  async removePath(path) {
    const value = await this._fileMetadata('remove', path);
    if (value.size !== 0 || ['kind', 'entries', 'created', 'info', 'entry_infos'].some(key => Object.hasOwn(value, key))) {
      throw new ProtocolError('recursive remove result is invalid');
    }
  }
}

function commandInfo(value, sessionId) {
  requireObject(value, 'command info is not an object');
  if (value.session_id !== sessionId || typeof value.id !== 'string' || !SESSION_ID.test(value.id) ||
      !['running', 'succeeded', 'guest_error', 'timed_out', 'cancelled', 'failed'].includes(value.state)) {
    throw new ProtocolError('command metadata has invalid binding or state');
  }
  if(value.pid!==undefined && (!Number.isSafeInteger(value.pid)||value.pid<=1||value.pid>2**30))throw new ProtocolError('invalid guest command PID');
  return value;
}

export class CommandHandle {
  constructor(session, info) {
    this._session = session;
    this.created = commandInfo(info, session.id);
    this.id = info.id;
    this._path = `/v2/sessions/${session.id}/commands/${this.id}`;
  }

  _inputReceipt(value,sequence){
    if(!value || value.session_id!==this._session.id || value.command_id!==this.id || !Number.isSafeInteger(value.sequence) || value.sequence<1 || value.sequence>256 ||
      (sequence!==undefined && value.sequence!==sequence) || !['pending','delivered','closed','failed'].includes(value.state) || !Number.isSafeInteger(value.written_bytes) ||
      value.written_bytes<0 || value.written_bytes>16384 || typeof value.closed!=='boolean' || (value.state==='failed' && !['stdin_closed','stdin_io','command_exited'].includes(value.error_code)))throw new ProtocolError('invalid stdin receipt binding or result');
    return value;
  }
  async submitStdin(data=new Uint8Array(),{close=false,requestTimeoutMs}={}){
    if(requestTimeoutMs!==undefined&&(!Number.isSafeInteger(requestTimeoutMs)||requestTimeoutMs<=0))throw new ConfigurationError("stdin request timeout must be positive milliseconds");
    if(!(data instanceof Uint8Array) || data.length>16384 || typeof close!=='boolean' || (close && data.length))throw new ConfigurationError('stdin requires at most 16 KiB of bytes, or an empty close');
    return this._inputReceipt(await this._session._client._exchange('POST',this._path+'/stdin',{data_base64:Buffer.from(data).toString('base64'),close},[202],requestTimeoutMs));
  }
  async pollStdin(sequence,requestTimeoutMs){
    if(requestTimeoutMs!==undefined&&(!Number.isSafeInteger(requestTimeoutMs)||requestTimeoutMs<=0))throw new ConfigurationError("stdin request timeout must be positive milliseconds");
    if(!Number.isSafeInteger(sequence)||sequence<1||sequence>256)throw new ConfigurationError('invalid stdin sequence');
    return this._inputReceipt(await this._session._client._exchange('GET',this._path+'/stdin/'+sequence,undefined,[200],requestTimeoutMs),sequence);
  }
  async _sendInput(data,close,{requestTimeoutMs=this._session._client._timeout,...extra}={}){
    if(Object.keys(extra).length)throw new UnsupportedCapability('custom stdin request options are not available');
    if(!Number.isSafeInteger(requestTimeoutMs)||requestTimeoutMs<=0)throw new ConfigurationError('stdin request timeout must be positive milliseconds');
    const deadline=Date.now()+requestTimeoutMs;
    let value;
    try{value=await this.submitStdin(data,{close,requestTimeoutMs});}
    catch(error){if(error instanceof TransportError && Date.now()>=deadline)throw new TimeoutException('stdin submission timed out; delivery outcome uncertain; input was not retried');throw error;}
    const sequence=value.sequence;
    while(value.state==='pending'){
      if(Date.now()>=deadline)throw new TimeoutException(`stdin delivery observation timed out; query sequence ${sequence}; input was not retried`);
      await new Promise(resolve=>setTimeout(resolve,Math.min(10,Math.max(0,deadline-Date.now()))));
      if(Date.now()>=deadline)throw new TimeoutException(`stdin delivery observation timed out; query sequence ${sequence}; input was not retried`);
      try{value=await this.pollStdin(sequence,Math.max(1,deadline-Date.now()));}
      catch(error){if(error instanceof TransportError && Date.now()>=deadline)throw new TimeoutException(`stdin delivery observation timed out; query sequence ${sequence}; input was not retried`);throw error;}
    }
    if(value.state==='failed')throw new APIError(409,value.error_code,'command stdin delivery failed');
    if(value.written_bytes!==data.length || value.closed!==close)throw new ProtocolError('stdin confirmation differs from submitted input');
  }
  async sendStdin(data,options){await this._sendInput(data,false,options);}
  async closeStdin(options){await this._sendInput(new Uint8Array(),true,options);}

  async poll(after = 0) {
    if (!Number.isSafeInteger(after) || after < 0 || after > 256) throw new ConfigurationError('invalid command cursor');
    const value = await this._session._client._exchange('GET', `${this._path}?after=${after}`);
    if (commandInfo(value.info, this._session.id).id !== this.id) throw new ProtocolError('command ID mismatch');
    return value;
  }

  async kill() {
    const value = await this._session._client._exchange('DELETE', this._path);
    if (typeof value.killed !== 'boolean') throw new ProtocolError('command kill returned invalid result');
    return value.killed;
  }

  async *events(after = 0, { timeoutMs, signal } = {}) {
    if (!Number.isSafeInteger(after) || after < 0 || after > 256) throw new ConfigurationError('invalid command cursor');
    let query=`?after=${after}`;
    if(timeoutMs!==undefined){if(!Number.isSafeInteger(timeoutMs)||timeoutMs<0||timeoutMs>86400000)throw new ConfigurationError('invalid command observation timeout');query+=`&timeout_ms=${timeoutMs}`;}
    let sequence = after;
    let total = 0;
    for await (const { kind, value } of this._session._client._events(`${this._path}/events${query}`, { signal })) {
      if (kind === 'output') {
        requireObject(value, 'invalid command output event');
        if (value.session_id !== this._session.id || value.command_id !== this.id ||
            !Number.isSafeInteger(value.sequence) || value.sequence !== sequence + 1 || value.sequence > 256 ||
            !['stdout', 'stderr'].includes(value.stream) || typeof value.data_base64 !== 'string') {
          throw new ProtocolError('command output has invalid binding or sequence');
        }
        const data = Buffer.from(value.data_base64, 'base64');
        total += data.length;
        if (!data.length || data.length > 4096 || total > 65536 || data.toString('base64') !== value.data_base64) {
          throw new ProtocolError('command output exceeds budget or is noncanonical');
        }
        sequence += 1;
        yield { sequence, stream: value.stream, data: new Uint8Array(data) };
      } else if (kind === 'timeout') {
        if(value.session_id!==this._session.id || value.command_id!==this.id || value.next_sequence!==sequence)throw new ProtocolError('invalid command timeout binding');
        throw new TimeoutException('command observation timed out; process was not cancelled');
      } else if (kind === 'result') {
        if (commandInfo(value.info, this._session.id).id !== this.id || value.complete !== true ||
            value.next_sequence !== sequence || value.result?.session_id !== this._session.id) {
          throw new ProtocolError('command terminal result has invalid binding');
        }
        const result = jobResult(value.result.result);
        if (result.id !== this.id || !result.protocolOk) throw new ProtocolError('command terminal identity mismatch');
        yield { sequence, result };
        return;
      } else throw new ProtocolError('unsupported command stream event');
    }
    throw new TransportError('command stream ended without a terminal result');
  }

  async wait() {
    for await (const event of this.events()) if (event.result) return event.result;
    throw new TransportError('command has no terminal result');
  }
}

export class Client {
  constructor(baseUrl, { token, certFile, keyFile, caFile, requestTimeoutMs = 360000 } = {}) {
    let url;
    try { url = new URL(baseUrl); } catch { throw new ConfigurationError('baseUrl must be an HTTPS origin'); }
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password ||
        url.pathname !== '/' || url.search || url.hash || !Number.isSafeInteger(Number(url.port || 443))) {
      throw new ConfigurationError('baseUrl must be an HTTPS origin');
    }
    if (typeof token !== 'string' || !/^[\x21-\x7e]+$/.test(token)) {
      throw new ConfigurationError('a non-empty bearer token is required');
    }
    if (typeof certFile !== 'string' || !certFile || typeof keyFile !== 'string' || !keyFile) {
      throw new ConfigurationError('client certificate and key are required');
    }
    if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs <= 0) {
      throw new ConfigurationError('request timeout must be positive');
    }
    let cert, key, ca;
    try {
      cert = readFileSync(certFile);
      key = readFileSync(keyFile);
      if (caFile !== undefined) ca = readFileSync(caFile);
    } catch (error) {
      throw new ConfigurationError(`cannot load TLS credentials (${error.code ?? 'error'})`);
    }
    this._url = url;
    this._token = token;
    this._tls = { cert, key, ca, minVersion: 'TLSv1.3', rejectUnauthorized: true };
    this._timeout = requestTimeoutMs;
  }

  async getInferenceBill(taskId, options = {}) {
    inferenceId(taskId, 'task');
    const {requestTimeoutMs = 10000, signal} = codeOptions(options, ['requestTimeoutMs', 'signal']);
    return inferenceDeadline(requestTimeoutMs, signal, async bounded => inferenceBill(
      await this._exchange('GET', `/v2/ml/bills/${taskId}`, undefined, [200], requestTimeoutMs, bounded), taskId));
  }

  async capabilities({ template, requestTimeoutMs } = {}) {
    let path = '/v1/capabilities';
    if (template !== undefined) {
      selector(template);
      path += '?' + new URLSearchParams({backend: template.backend, artifact_manifest_sha256: template.artifactManifestSha256});
    }
    if (requestTimeoutMs !== undefined) codeRequestTimeout(requestTimeoutMs);
    const report = await this._exchange('GET', path, undefined, [200], requestTimeoutMs);
    capabilityReport(report, template);
    return report;
  }

  async templates() {
    const value = await this._exchange('GET', '/v2/templates');
    if (value.protocol !== 'osv-sandbox-template-catalog/v1' || !Array.isArray(value.templates) ||
        value.templates.length > 16 || typeof value.default_template_id !== 'string')throw new ProtocolError('invalid template catalog');
    const ids = new Set(), selectors = new Set();
    for (const entry of value.templates) {
      const cap = entry?.capabilities, id = entry?.id;
      if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,32}$/.test(id) || ids.has(id) ||
          typeof entry.available !== 'boolean' || cap === null || typeof cap !== 'object' ||
          cap.protocol !== 'osv-sandbox-capabilities/v1' || cap.artifact_authenticated !== true ||
          typeof cap.backend !== 'string' || !/^[0-9a-f]{64}$/.test(cap.artifact_manifest_sha256 ?? '') ||
          !Array.isArray(cap.methods) || !Array.isArray(cap.allowed_entrypoints))throw new ProtocolError('invalid authenticated template entry');
      const key = cap.backend + ':' + cap.artifact_manifest_sha256;
      if(selectors.has(key))throw new ProtocolError('duplicate template selector');
      ids.add(id); selectors.add(key);
    }
    if(value.default_template_id && !ids.has(value.default_template_id))throw new ProtocolError('template default is not visible');
    return value;
  }

  async doctor() {
    const report = await this._exchange('GET', '/v1/doctor', undefined, [200, 503]);
    if (typeof report.ready !== 'boolean' || !Array.isArray(report.checks)) {
      throw new ProtocolError('incomplete doctor response');
    }
    return report;
  }

  async fetchNetwork(url, { method = 'GET', body, headers = {}, followRedirects = false, timeoutMs } = {}) {
    if (typeof url !== 'string' || !url || Buffer.byteLength(url) > 8192 ||
        !['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'].includes(method) ||
        body !== undefined && !(body instanceof Uint8Array) || typeof followRedirects !== 'boolean' ||
        headers === null || typeof headers !== 'object' || Array.isArray(headers) || Object.keys(headers).length > 32 ||
        Object.values(headers).some(v => typeof v !== 'string') ||
        timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000)) {
      throw new ConfigurationError('invalid network fetch options');
    }
    const report = await this.capabilities();
    const policy = report.network_fetch_policy;
    if (report.features?.network_fetch !== true || !report.methods.includes('POST /v2/net/fetch') || !policy || typeof policy !== 'object') {
      throw new UnsupportedCapability('tenant network fetch is unavailable');
    }
    if (!Number.isSafeInteger(policy.max_request_bytes) || policy.max_request_bytes < 1 || policy.max_request_bytes > 262144 ||
        !Number.isSafeInteger(policy.timeout_ms) || policy.timeout_ms < 100 || policy.timeout_ms > 30000) {
      throw new ProtocolError('invalid tenant network fetch limits');
    }
    const bytes = Buffer.from(body ?? []);
    if (bytes.length > Math.min(262144, policy.max_request_bytes ?? 0) || timeoutMs !== undefined && timeoutMs > (policy.timeout_ms ?? 0)) {
      throw new ConfigurationError('network fetch exceeds tenant limits');
    }
    const value = await this._exchange('POST', '/v2/net/fetch', {url, method, headers, body_base64:bytes.toString('base64'), follow_redirects:followRedirects,
      ...(timeoutMs === undefined ? {} : {timeout_ms:timeoutMs})});
    if (value.protocol !== 'osv-sandbox-network-fetch/v1' || !SESSION_ID.test(value.request_id) || typeof value.url !== 'string' ||
        !Number.isSafeInteger(value.status) || value.status < 100 || value.status > 599 ||
        !value.headers || typeof value.headers !== 'object' || Array.isArray(value.headers) ||
        Object.values(value.headers).some(v => !Array.isArray(v) || v.some(x => typeof x !== 'string')) ||
        ['body_bytes','redirects','duration_ms','request_bytes','response_bytes'].some(k => !Number.isSafeInteger(value[k]) || value[k] < 0) ||
        typeof value.body_base64 !== 'string' || value.body_base64.length > 699052) {
      throw new ProtocolError('invalid network fetch response');
    }
    const data = Buffer.from(value.body_base64, 'base64');
    if (data.toString('base64') !== value.body_base64 || data.length !== value.body_bytes || data.length > 524288 || value.redirects > 5 ||
        value.response_bytes < data.length || value.response_bytes > 524288 || value.request_bytes > 6 * 262144) {
      throw new ProtocolError('inconsistent network fetch bounds');
    }
    return {requestId:value.request_id, url:value.url, status:value.status, headers:value.headers, body:data,
      redirects:value.redirects, durationMs:value.duration_ms, requestBytes:value.request_bytes, responseBytes:value.response_bytes};
  }

  async run(job, { template } = {}) {
    const payload = jobPayload(job);
    if(template !== undefined)selector(template);
    const proxyReport = payload.network === 'proxy' ? await this.capabilities({template}) : undefined;
    if(proxyReport && proxyReport.features?.network_egress !== true)throw new UnsupportedCapability('tenant guest proxy is unavailable');
    if (template === undefined) {
      const report = proxyReport ?? await this.capabilities();
      if (!report.methods.includes('POST /v2/jobs') || report.artifact_authenticated !== true) {
        throw new UnsupportedCapability('server does not advertise signed v2 jobs');
      }
      if (!report.allowed_entrypoints.includes(job.entrypoint)) {
        throw new UnsupportedCapability('entrypoint is not available to this tenant');
      }
      if (job.inputFiles?.length && report.features?.input_files !== true) {
        throw new UnsupportedCapability('input files are not available on this backend');
      }
      if (job.environment && Object.keys(job.environment).length && report.features?.environment !== true) {
        throw new UnsupportedCapability('environment is not available on this backend');
      }
      if (job.cwd !== undefined && report.features?.working_directory !== true) {
        throw new UnsupportedCapability('working directory is not available on this backend');
      }
      if (job.stdin !== undefined && report.features?.stdin !== true) {
        throw new UnsupportedCapability('stdin is not available on this backend');
      }
      template = { backend: report.backend, artifactManifestSha256: report.artifact_manifest_sha256 };
    }
    selector(template);
    if(proxyReport && (template.backend !== proxyReport.backend || template.artifactManifestSha256 !== proxyReport.artifact_manifest_sha256))throw new UnsupportedCapability('guest proxy requires the advertised signed template');
    if (template.backend === 'firecracker-osv' && Object.keys(job.environment??{}).some(name=>name.startsWith('LD_')||name.startsWith('OSV_'))) {
      throw new ConfigurationError('reserved OSv environment variable');
    }
    if (job.cwd !== undefined && template.backend !== 'firecracker-linux')throw new UnsupportedCapability('working directory requires firecracker-linux');
    payload.backend = template.backend;
    payload.artifact_manifest_sha256 = template.artifactManifestSha256;
    const value = jobResult(await this._exchange('POST', '/v2/jobs', payload));
    if(value.artifactManifestSha256!==undefined&&(value.backend!==template.backend||value.artifactManifestSha256!==template.artifactManifestSha256))throw new ProtocolError('job returned a different signed template');
    return value;
  }

  async runLegacy(job) {
    const payload=jobPayload(job);
    if(payload.network === 'proxy' && (await this.capabilities()).features?.network_egress !== true)throw new UnsupportedCapability('tenant guest proxy is unavailable');
    return jobResult(await this._exchange('POST', '/v1/jobs', payload));
  }

  async createSession(session = {}, { template } = {}) {
    const payload = sessionPayload(session);
    if(template !== undefined)selector(template);
    const proxyReport = payload.network === 'proxy' ? await this.capabilities({template}) : undefined;
    if(proxyReport && proxyReport.features?.network_egress !== true)throw new UnsupportedCapability('tenant guest proxy is unavailable');
    if (template === undefined) {
      const report = proxyReport ?? await this.capabilities();
      if (!report.methods.includes('POST /v2/sessions') || report.features?.sessions !== true ||
          report.artifact_authenticated !== true || report.backend !== 'firecracker-linux' ||
          report.allowed_entrypoints.length === 0) {
        throw new UnsupportedCapability('server does not advertise signed Linux sessions');
      }
      if (session.inputFiles?.length && report.features?.input_files !== true) {
        throw new UnsupportedCapability('input files are not available on this backend');
      }
      template = { backend: report.backend, artifactManifestSha256: report.artifact_manifest_sha256 };
    }
    selector(template);
    if(proxyReport && (template.backend !== proxyReport.backend || template.artifactManifestSha256 !== proxyReport.artifact_manifest_sha256))throw new UnsupportedCapability('guest proxy requires the advertised signed template');
    if (template.backend !== 'firecracker-linux') {
      throw new UnsupportedCapability('sessions require firecracker-linux');
    }
    payload.backend = template.backend;
    payload.artifact_manifest_sha256 = template.artifactManifestSha256;
    const info = sessionInfo(await this._exchange('POST', '/v2/sessions', payload, [201]));
    if (info.artifactManifestSha256 !== template.artifactManifestSha256) {
      throw new ProtocolError('session create returned a different template');
    }
    return new Session(this, info);
  }

  async listSessions({limit=20,cursor,order='desc',...options}={}){
    if(Object.keys(options).length)throw new ConfigurationError('unsupported session list option');
    if(!Number.isSafeInteger(limit)||limit<1||limit>100||!['asc','desc'].includes(order))throw new ConfigurationError('invalid pagination limit/order');
    if(cursor!==undefined && (typeof cursor!=='string'||! /^[A-Za-z0-9_-]{1,128}$/.test(cursor)))throw new ConfigurationError('invalid session cursor');
    const query=new URLSearchParams({limit:String(limit),order});if(cursor!==undefined)query.set('cursor',cursor);
    const value=await this._exchange('GET','/v2/sessions?'+query);
    if(!Array.isArray(value.sessions)||value.sessions.length>limit)throw new ProtocolError('invalid session list');
    const rows=value.sessions.map(sessionInfo);
    if(new Set(rows.map(row=>row.id)).size!==rows.length)throw new ProtocolError('duplicate session in page');
    if(value.next_cursor!==undefined && (typeof value.next_cursor!=='string'||! /^[A-Za-z0-9_-]{1,128}$/.test(value.next_cursor)))throw new ProtocolError('invalid next cursor');
    return {sessions:rows,...(value.next_cursor===undefined?{}:{nextCursor:value.next_cursor})};
  }
  async connectSession(id) {
    if (typeof id !== 'string' || !SESSION_ID.test(id)) {
      throw new ConfigurationError('session ID must be 24 lowercase hex digits');
    }
    const info = sessionInfo(await this._exchange('GET', `/v2/sessions/${id}`));
    if (info.id !== id) throw new ProtocolError('session query returned a different ID');
    return new Session(this, info);
  }

  async *_events(path, { signal } = {}) {
    let req;
    const response = await new Promise((resolve, reject) => {
      req = httpsRequest({ hostname: this._url.hostname, port: this._url.port || 443, path, method: 'GET', signal,
        headers: { Authorization: `Bearer ${this._token}`, Accept: 'text/event-stream' }, agent: false, ...this._tls }, resolve);
      req.setTimeout(this._timeout, () => req.destroy(new TransportError('command stream timed out')));
      req.on('error', () => reject(new TransportError('command event connection failed')));
      req.end();
    });
    try {
      if (response.statusCode !== 200) {
        let body = '';
        for await (const chunk of response) {
          body += chunk.toString('utf8');
          if (Buffer.byteLength(body) > MAX_ERROR) throw new ProtocolError('oversized stream error');
        }
        if (response.statusCode >= 300 && response.statusCode < 400) throw new ProtocolError('redirected command stream');
        let value;
        try { value = JSON.parse(body); } catch { throw new ProtocolError('invalid stream error'); }
        throw new APIError(response.statusCode ?? 0, String(value.code ?? 'http_error'),
          String(value.error ?? 'stream rejected').replaceAll(this._token, '[redacted]').slice(0, 4096));
      }
      if (response.headers['content-type']?.split(';')[0] !== 'text/event-stream') throw new ProtocolError('command events are not SSE');
      const decoder = new TextDecoder('utf-8', { fatal: true });
      let pending = '', kind, payload, size = 0;
      for await (const chunk of response) {
        size += chunk.length;
        if (size > MAX_RESPONSE) throw new ProtocolError('command stream exceeds 4 MiB');
        pending += decoder.decode(chunk, { stream: true });
        let end;
        while ((end = pending.indexOf('\n')) >= 0) {
          const line = pending.slice(0, end).replace(/\r$/, '');
          pending = pending.slice(end + 1);
          if (line === '') {
            if (kind !== undefined && payload !== undefined) {
              let value;
              try { value = JSON.parse(payload); } catch { throw new ProtocolError('invalid command event JSON'); }
              yield { kind, value };
            }
            kind = payload = undefined;
          } else if (line.startsWith('event: ')) kind = line.slice(7);
          else if (line.startsWith('data: ')) {
            if (payload !== undefined) throw new ProtocolError('duplicate command event data');
            payload = line.slice(6);
          }
        }
      }
      decoder.decode();
    } finally {
      response.destroy();
      req.destroy();
    }
  }

  async _exchange(method, path, payload, accepted = [200], requestTimeoutMs = this._timeout, signal) {
    const body = payload === undefined ? undefined : Buffer.from(JSON.stringify(payload), 'utf8');
    if (body && body.length > MAX_REQUEST) throw new ConfigurationError('JSON request exceeds 1 MiB');
    const statusAndData = await new Promise((resolve, reject) => {
      const req = httpsRequest({
        hostname: this._url.hostname, port: this._url.port || 443, path, method,
        headers: { Authorization: `Bearer ${this._token}`, Accept: 'application/json',
          ...(body ? { 'Content-Type': 'application/json', 'Content-Length': body.length } : {}) },
        agent: false, ...this._tls, signal
      }, response => {
        const status = response.statusCode ?? 0;
        if (status >= 300 && status < 400) {
          response.resume();
          reject(new ProtocolError('server redirected an API request'));
          return;
        }
        const limit = accepted.includes(status) ? MAX_RESPONSE : MAX_ERROR;
        const chunks = [];
        let size = 0;
        response.on('data', chunk => {
          size += chunk.length;
          if (size > limit) {
            response.destroy(new ProtocolError(`response exceeds ${limit} bytes`));
          } else chunks.push(chunk);
        });
        response.on('end', () => resolve({ status, data: Buffer.concat(chunks) }));
        response.on('error', reject);
      });
      req.setTimeout(Math.min(this._timeout,requestTimeoutMs), () => req.destroy(new TransportError('HTTPS exchange timed out')));
      req.on('error', error => reject(error instanceof ProtocolError || error instanceof TransportError ?
        error : new TransportError(`HTTPS exchange failed (${error.code ?? 'error'})`)));
      req.end(body);
    });
    if (statusAndData.status === 204 && accepted.includes(204)) {
      if (statusAndData.data.length) throw new ProtocolError('delete response must be empty');
      return {};
    }
    let value;
    try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(statusAndData.data)); }
    catch { throw new ProtocolError('server returned invalid JSON'); }
    requireObject(value, 'server returned a non-object JSON response');
    if (!accepted.includes(statusAndData.status)) {
      const code = typeof value.code === 'string' && value.code ? value.code : `http_${statusAndData.status}`;
      const message = typeof value.error === 'string' ? value.error.replaceAll(this._token, '[redacted]').slice(0, 4096) : 'request rejected';
      const ErrorClass = statusAndData.status === 409 && code === 'template_mismatch' ? TemplateMismatch : APIError;
      throw new ErrorClass(statusAndData.status, code, message);
    }
    return value;
  }
}

const INFERENCE_ENDPOINT = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const INFERENCE_U64 = (1n << 64n) - 1n;
function inferenceId(value, label = 'invocation') {
  if (typeof value !== 'string' || !SESSION_ID.test(value)) throw new ConfigurationError(`${label} ID must be 24 lowercase hex digits`);
  return value;
}

export class InferenceError extends SandboxError {
  constructor(taskId, invocationId, cause, attempted) {
    const code = cause instanceof APIError && /^[a-z0-9_]{1,64}$/.test(cause.code) ? cause.code : cause?.constructor?.name ?? 'inference_error';
    super(`inference ${code}; task=${taskId} invocation=${invocationId}`, {cause});
    this.taskId = taskId; this.invocationId = invocationId; this.cause = cause;
    this.deliveryUnknown = attempted; this.code = code;
    this.status = cause instanceof APIError ? cause.status : undefined;
  }
}

function inferenceUnits(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > INFERENCE_U64) throw new ProtocolError('invalid inference integer units');
  return BigInt(value);
}
function inferencePrice(value, input, output) {
  inferenceKeys(value, ['request_units', 'input_byte_units', 'output_byte_units']);
  const total = inferenceUnits(value.request_units) + inferenceUnits(value.input_byte_units) * BigInt(input) + inferenceUnits(value.output_byte_units) * BigInt(output);
  if (total > INFERENCE_U64) throw new ProtocolError('inference price overflow');
  return total;
}
function inferenceKeys(value, required, optional = []) {
  requireObject(value, 'invalid inference object');
  if (required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) throw new ProtocolError('invalid inference fields');
}
function inferenceInteger(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new ProtocolError('invalid inference byte/count limit');
  return value;
}
function inferenceJSON(value, limit, Problem = ConfigurationError) {
  const ancestors = new Set();
  function check(item, depth) {
    if (depth > 64) throw new Error();
    if (item === null || typeof item === 'boolean') return;
    if (typeof item === 'number') {
      if (!Number.isFinite(item) || Number.isInteger(item) && !Number.isSafeInteger(item)) throw new Error();
      return;
    }
    if (typeof item === 'string') {
      if (Buffer.from(item).toString('utf8') !== item) throw new Error();
      return;
    }
    if (typeof item !== 'object' || ancestors.has(item)) throw new Error();
    const array = Array.isArray(item), proto = Object.getPrototypeOf(item);
    if (array ? proto !== Array.prototype : proto !== Object.prototype && proto !== null) throw new Error();
    const keys = Reflect.ownKeys(item);
    if (array && keys.length !== item.length + 1) throw new Error();
    ancestors.add(item);
    try {
      for (const key of keys) {
        if (array && key === 'length') continue;
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (typeof key !== 'string' || !descriptor?.enumerable || !Object.hasOwn(descriptor, 'value') ||
            array && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= item.length)) throw new Error();
        check(key, depth + 1); check(descriptor.value, depth + 1);
      }
    } finally { ancestors.delete(item); }
  }
  try {
    check(value, 0);
    const encoded = JSON.stringify(value), size = Buffer.byteLength(encoded);
    if (size > limit) throw new Error();
    return {snapshot: JSON.parse(encoded), size};
  } catch { throw new Problem('inference data must be bounded plain JSON with finite, exact numbers'); }
}
function inferenceReceipt(value, closed = false) {
  inferenceKeys(value, ['id', 'endpoint', 'state', 'epoch', 'price', 'input_bytes', 'max_output_bytes', 'output_bytes',
    'dispatched', 'http_status', 'reserved_units', 'settled_units', 'started_at', 'duration_ms'], ['code', 'finished_at']);
  if (['id', 'epoch'].some(key => typeof value[key] !== 'string' || !SESSION_ID.test(value[key])) ||
      typeof value.endpoint !== 'string' || !INFERENCE_ENDPOINT.test(value.endpoint) || typeof value.dispatched !== 'boolean') throw new ProtocolError('invalid inference receipt binding');
  const input = inferenceInteger(value.input_bytes, 0, 256 << 10), maximum = inferenceInteger(value.max_output_bytes, 1, 512 << 10);
  const output = inferenceInteger(value.output_bytes, 0, maximum + 1), status = inferenceInteger(value.http_status, 0, 599);
  inferenceInteger(value.duration_ms, 0, 300000);
  const code = value.code ?? '', start = previewTimestamp(value.started_at);
  const finish = Object.hasOwn(value, 'finished_at') ? previewTimestamp(value.finished_at) : undefined;
  if (status > 0 && status < 100 || typeof code !== 'string' || code && !/^[a-z0-9_]{1,64}$/.test(code) ||
      start === undefined || start === -62135596800000000000n || Object.hasOwn(value, 'finished_at') && finish === undefined || finish !== undefined && finish < start) throw new ProtocolError('invalid inference status/timestamps');
  const reserved = inferenceUnits(value.reserved_units), settled = inferenceUnits(value.settled_units);
  if (reserved !== inferencePrice(value.price, input, maximum) || settled > reserved) throw new ProtocolError('invalid inference reservation');
  if (value.state === 'reserved') {
    if (closed || finish !== undefined || settled !== 0n || value.dispatched || status || output || code) throw new ProtocolError('invalid pending inference');
    return {settled: 0n, held: reserved};
  }
  if (value.state === 'uncertain') {
    if (finish === undefined || settled !== 0n || !code) throw new ProtocolError('invalid uncertain inference');
    return {settled: 0n, held: reserved};
  }
  if (!['succeeded', 'failed'].includes(value.state) || finish === undefined) throw new ProtocolError('invalid inference state');
  const expected = value.dispatched ? inferencePrice(value.price, input, Math.min(output, maximum)) : 0n;
  if (!value.dispatched && (output || status) || expected !== settled ||
      value.state === 'succeeded' && (!value.dispatched || output > maximum || status < 200 || status > 299 || code) || value.state === 'failed' && !code) throw new ProtocolError('invalid settled inference');
  return {settled, held: 0n};
}
function inferenceBill(value, taskId) {
  inferenceKeys(value, ['protocol', 'tenant', 'task_id', 'vm_id', 'lease_id', 'closed', 'unit', 'max_invocations', 'settled_units', 'held_units', 'invocations'], ['budget_units']);
  if (value.protocol !== 'osv-sandbox-inference-bill/v1' || value.unit !== 'microcredits' || value.task_id !== taskId ||
      ['task_id', 'vm_id', 'lease_id'].some(key => typeof value[key] !== 'string' || !SESSION_ID.test(value[key])) ||
      typeof value.tenant !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(value.tenant) || typeof value.closed !== 'boolean' ||
      !Array.isArray(value.invocations)) throw new ProtocolError('invalid inference bill binding');
  const maximum = inferenceInteger(value.max_invocations, 1, 256);
  if (value.invocations.length > maximum) throw new ProtocolError('inference bill exceeds invocation limit');
  let settled = 0n, held = 0n;
  const ids = new Set();
  for (const entry of value.invocations) {
    const meter = inferenceReceipt(entry, value.closed);
    if (ids.has(entry.id)) throw new ProtocolError('duplicate invocation in bill');
    ids.add(entry.id); settled += meter.settled; held += meter.held;
  }
  if (settled !== inferenceUnits(value.settled_units) || held !== inferenceUnits(value.held_units) || settled + held > INFERENCE_U64 ||
      Object.hasOwn(value, 'budget_units') && settled + held > inferenceUnits(value.budget_units)) throw new ProtocolError('invalid inference bill totals/budget');
  return value;
}
function inferencePolicy(report) {
  if ((report.artifact_manifest_protocol !== 'osv-sandbox-artifacts/v7' && !(report.backend === 'firecracker-linux' && report.artifact_manifest_protocol === 'osv-sandbox-artifacts/v8')) || !['firecracker-linux', 'firecracker-osv'].includes(report.backend) ||
      ['sessions', 'remote_inference', 'network_egress'].some(key => report.features?.[key] !== true) ||
      !report.methods?.includes('POST /v2/sessions/{id}/ml/invocations')) throw new UnsupportedCapability('selected session has no remote inference');
  const policy = report.remote_inference_policy;
  return inferencePolicyDocument(policy);
}
function inferencePolicyDocument(policy) {
  inferenceKeys(policy, ['protocol', 'endpoints', 'max_request_bytes', 'max_response_bytes', 'timeout_ms', 'max_invocations'], ['budget_units']);
  if (policy.protocol !== 'osv-sandbox-inference-capabilities/v1' || !Array.isArray(policy.endpoints) || policy.endpoints.length < 1 || policy.endpoints.length > 32) throw new ProtocolError('invalid inference policy');
  for (const [key, low, high] of [['max_request_bytes', 1, 256 << 10], ['max_response_bytes', 1, 512 << 10], ['timeout_ms', 100, 30000], ['max_invocations', 1, 256]]) inferenceInteger(policy[key], low, high);
  if (Object.hasOwn(policy, 'budget_units')) inferenceUnits(policy.budget_units);
  const names = new Set();
  for (const endpoint of policy.endpoints) {
    inferenceKeys(endpoint, ['name', 'price']);
    if (typeof endpoint.name !== 'string' || !INFERENCE_ENDPOINT.test(endpoint.name) || names.has(endpoint.name)) throw new ProtocolError('invalid inference endpoint policy');
    names.add(endpoint.name); inferencePrice(endpoint.price, policy.max_request_bytes, policy.max_response_bytes);
  }
  return policy;
}
async function inferenceDeadline(timeout, signal, action) {
  codeRequestTimeout(timeout);
  if (signal !== undefined && !(signal instanceof AbortSignal)) throw new ConfigurationError('inference signal must be an AbortSignal');
  const controller = new AbortController(), abort = () => controller.abort();
  const timer = setTimeout(abort, Math.min(timeout, 2147483647));
  timer.unref();
  if (signal?.aborted) abort();
  signal?.addEventListener('abort', abort, {once: true});
  try { return await action(controller.signal); }
  finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}

export class SessionML {
  constructor(session) { this._session = session; }
  bill(options = {}) { return this._session._client.getInferenceBill(this._session.id, options); }
  async invoke(endpoint, payload, options = {}) {
    const {invocationId = randomBytes(12).toString('hex'), timeoutMs = 0, requestTimeoutMs = 35000, signal} = codeOptions(options, ['invocationId', 'timeoutMs', 'requestTimeoutMs', 'signal']);
    inferenceId(invocationId);
    let attempted = false;
    try {
      if (typeof endpoint !== 'string' || !INFERENCE_ENDPOINT.test(endpoint) || !Number.isInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 30000) throw new ConfigurationError('invalid inference endpoint alias or timeout');
      const {snapshot, size} = inferenceJSON(payload, 256 << 10);
      if (this._session.created.network !== 'proxy') throw new UnsupportedCapability('inference requires a proxy-network session');
      return await inferenceDeadline(requestTimeoutMs, signal, async bounded => {
        const policy = inferencePolicy(await this._session.capabilities({requestTimeoutMs: Math.min(requestTimeoutMs, 10000), signal: bounded}));
        if (!policy.endpoints.some(item => item.name === endpoint)) throw new UnsupportedCapability('inference endpoint alias is not authorized');
        if (size > policy.max_request_bytes || timeoutMs > policy.timeout_ms) throw new ConfigurationError('inference payload or timeout exceeds tenant policy');
        attempted = true;
        const value = await this._session._client._exchange('POST', `/v2/sessions/${this._session.id}/ml/invocations`, {id: invocationId, endpoint, payload: snapshot, timeout_ms: timeoutMs}, [200], requestTimeoutMs, bounded);
        inferenceKeys(value, ['protocol', 'task_id', 'invocation', 'data']);
        if (value.protocol !== 'osv-sandbox-inference-invoke/v1' || value.task_id !== this._session.id) throw new ProtocolError('invalid inference result task/protocol');
        inferenceReceipt(value.invocation);
        if (value.invocation.id !== invocationId || value.invocation.endpoint !== endpoint || value.invocation.state !== 'succeeded') throw new ProtocolError('invalid inference result invocation');
        const data = inferenceJSON(value.data, MAX_RESPONSE, ProtocolError).snapshot;
        return Object.freeze({taskId: value.task_id, invocationId, invocation: Object.freeze(value.invocation), data});
      });
    } catch (cause) { throw new InferenceError(this._session.id, invocationId, cause, attempted); }
  }
}

function validateE2BMetadata(metadata) {
  if (metadata == null || typeof metadata !== 'object' || Array.isArray(metadata) ||
      Object.keys(metadata).length > 16) {
    throw new ConfigurationError('E2B metadata exceeds 16 entries');
  }
  let total = 0;
  for (const [key, value] of Object.entries(metadata)) {
    if (key.length > 246 || !/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(key) || typeof value !== 'string' ||
        !/^[\x20-\x7e]*$/.test(value)) {
      throw new ConfigurationError('E2B metadata requires token keys and printable ASCII values');
    }
    total += Buffer.byteLength(key) + Buffer.byteLength(value);
  }
  if (total > 16 * 1024) throw new ConfigurationError('E2B metadata exceeds 16 KiB');
}

function e2bEntryInfo(value, path) {
  if (value == null || typeof value !== 'object' || value.path !== path ||
      value.name !== path.slice(path.lastIndexOf('/') + 1) ||
      !['file', 'directory', 'symlink', 'other'].includes(value.type) ||
      !Number.isSafeInteger(value.size) || value.size < 0 || value.size > 2 ** 40 ||
      !Number.isSafeInteger(value.mode) || value.mode < 0 || value.mode > 0o177777 ||
      typeof value.permissions !== 'string' || value.permissions.length !== 9 ||
      typeof value.owner !== 'string' || !value.owner ||
      typeof value.group !== 'string' || !value.group ||
      !Number.isSafeInteger(value.modified_time_ms) ||
      value.modified_time_ms < 0 || value.modified_time_ms > 4102444800000) {
    throw new ProtocolError('file info has invalid fields or binding');
  }
  const typeBit = value.mode & 0o170000;
  if ((value.type === 'file' && typeBit !== 0o100000) ||
      (value.type === 'directory' && typeBit !== 0o040000) ||
      (value.type === 'symlink' && typeBit !== 0o120000) ||
      (value.type === 'other' && [0o100000, 0o040000, 0o120000].includes(typeBit))) {
    throw new ProtocolError('file info type differs from mode');
  }
  if (value.type === 'symlink') {
    if (typeof value.symlink_target !== 'string' || !value.symlink_target ||
        Buffer.byteLength(value.symlink_target, 'utf8') > 4096 ||
        value.symlink_target.includes('\0') ||
        value.size !== Buffer.byteLength(value.symlink_target, 'utf8') ||
        Object.hasOwn(value, 'metadata')) {
      throw new ProtocolError('file info has invalid symlink target');
    }
  } else if (Object.hasOwn(value, 'symlink_target')) {
    throw new ProtocolError('file info has unexpected symlink target');
  }
  if (value.metadata !== undefined) {
    try { validateE2BMetadata(value.metadata); }
    catch { throw new ProtocolError('file info metadata is invalid'); }
  }
  return { name: value.name, path,
    type: { file: 'file', directory: 'dir', symlink: 'symlink' }[value.type],
    size: value.size, mode: value.mode, permissions: value.permissions,
    owner: value.owner, group: value.group,
    modifiedTime: new Date(value.modified_time_ms),
    ...(value.type === 'symlink' ? { symlinkTarget: value.symlink_target } : {}),
    ...(value.metadata === undefined ? {} : { metadata: value.metadata }) };
}

function watchInfo(info, sessionId) {
  if (info == null || typeof info !== 'object' || info.session_id !== sessionId ||
      typeof info.id !== 'string' || !SESSION_ID.test(info.id) || !cleanWorkspacePath(info.path, true) ||
      typeof info.recursive !== 'boolean' || typeof info.include_entry !== 'boolean' ||
      !['starting', 'watching', 'closed', 'failed'].includes(info.state) ||
      (info.error_code !== undefined && (typeof info.error_code !== 'string' || info.error_code.length > 64))) throw new ProtocolError('invalid watch info or owner');
  return info;
}

const CODE_LANGUAGES = ['python', 'javascript', 'typescript'];
const CODE_TERMINAL = ['completed', 'cancelled', 'timed_out', 'failed'];
function capabilityReport(report, template) {
  if (report.protocol !== 'osv-sandbox-capabilities/v1' || !Array.isArray(report.methods) || report.methods.some(x => typeof x !== 'string') ||
      !Array.isArray(report.allowed_entrypoints) || report.allowed_entrypoints.some(x => typeof x !== 'string') || typeof report.backend !== 'string') throw new ProtocolError('incomplete capabilities response');
  if (template !== undefined && (report.backend !== template.backend || report.artifact_manifest_sha256 !== template.artifactManifestSha256)) throw new ProtocolError('selected capabilities returned a different template');
}
function codeId(value) {
  if (typeof value !== 'string' || !SESSION_ID.test(value)) throw new ConfigurationError('code ID must be 24 lowercase hex digits');
  return value;
}
function codeRequestTimeout(value = 10000) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) throw new ConfigurationError('code request timeout must be positive milliseconds');
  return value;
}
function codeOptions(value, allowed) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) throw new ConfigurationError('invalid code options');
  return value;
}
function codeInput(code, environment, timeoutMs) {
  if (typeof code !== 'string' || code.includes('\0') || Buffer.from(code).toString('utf8') !== code || Buffer.byteLength(code) > 65536 ||
      !Number.isInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 300000) throw new ConfigurationError('invalid code or execution timeout');
  if (environment === null || typeof environment !== 'object' || Array.isArray(environment) || Object.keys(environment).length > 64 ||
      Object.entries(environment).some(([k, v]) => !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(k) || typeof v !== 'string' || v.includes('\0') || Buffer.from(v).toString('utf8') !== v || Buffer.byteLength(v) > 8192) ||
      Object.entries(environment).reduce((total, [k, v]) => total + Buffer.byteLength(k) + Buffer.byteLength(v), 0) > 16384 ||
      Buffer.byteLength(JSON.stringify({code, env: environment})) > 96 * 1024) throw new ConfigurationError('invalid code environment or encoded frame budget');
  return {...environment};
}
function codeContext(value, sessionId) {
  requireObject(value, 'invalid code context');
  if (value.session_id !== sessionId || typeof value.id !== 'string' || !SESSION_ID.test(value.id) ||
      !Number.isSafeInteger(value.generation) || value.generation < 1 || !CODE_LANGUAGES.includes(value.language) ||
      !cleanWorkspacePath(value.cwd, true) || !['starting', 'idle', 'running', 'interrupting', 'stopping', 'failed'].includes(value.state) ||
      !(value.pid === null || Number.isInteger(value.pid) && value.pid >= 2 && value.pid < 2 ** 31) ||
      !(value.failure === null || typeof value.failure === 'string' && value.failure.length <= 4096) ||
      !Number.isInteger(value.discarded_late_events) || value.discarded_late_events < 0 || value.discarded_late_events > 1024 ||
      !Number.isInteger(value.discarded_late_bytes) || value.discarded_late_bytes < 0 || value.discarded_late_bytes > 256 * 1024) {
    throw new ProtocolError('invalid code context or owner');
  }
  return Object.freeze({...value});
}

/** Native asynchronous code control. No request loss replays submitted code. */
export class CodeContexts {
  constructor(session) {
    this._session = session;
    this._path = `/v2/sessions/${session.id}`;
  }
  async _check(language, requestTimeoutMs) {
    codeRequestTimeout(requestTimeoutMs);
    if (language !== undefined && !CODE_LANGUAGES.includes(language)) throw new UnsupportedCapability('only python/javascript/typescript code is available');
    if (!this._capabilities) {
      this._capabilities = this._session.capabilities({requestTimeoutMs: codeRequestTimeout(requestTimeoutMs)}).then(report => {
        if (report.artifact_authenticated !== true || report.backend !== 'firecracker-linux' ||
            report.features?.code_contexts !== true || !['osv-sandbox-artifacts/v5', 'osv-sandbox-artifacts/v6', 'osv-sandbox-artifacts/v7', 'osv-sandbox-artifacts/v8'].includes(report.artifact_manifest_protocol) ||
            report.code_runtime?.kernel_protocol !== 'osv-code-kernel/v2' || !Array.isArray(report.code_languages) ||
            report.code_languages.some(item => !CODE_LANGUAGES.includes(item))) throw new UnsupportedCapability('selected signed template has no code contexts');
        return report;
      }).catch(error => { this._capabilities = undefined; throw error; });
    }
    const report = await this._capabilities;
    if (language !== undefined && !report.code_languages.includes(language)) throw new UnsupportedCapability('code interpreter is not authorized on selected template');
  }
  _rpc(method, path, payload, status = 200, requestTimeoutMs) {
    return this._session._client._exchange(method, this._path + path, payload, [status], codeRequestTimeout(requestTimeoutMs));
  }
  _context(context) {
    if (context?.session_id !== this._session.id) throw new ConfigurationError('context belongs to another session');
    return codeContext(context, this._session.id);
  }
  async get(id, options = {}) {
    const {requestTimeoutMs} = codeOptions(options, ['requestTimeoutMs']);
    codeId(id);
    await this._check(undefined, requestTimeoutMs);
    const value = codeContext(await this._rpc('GET', `/contexts/${id}`, undefined, 200, requestTimeoutMs), this._session.id);
    if (value.id !== id) throw new ProtocolError('code context ID changed');
    return value;
  }
  async default(language = 'python', options = {}) {
    const {requestTimeoutMs} = codeOptions(options, ['requestTimeoutMs']);
    await this._check(language, requestTimeoutMs);
    const value = codeContext(await this._rpc('POST', '/contexts/default', {language}, 200, requestTimeoutMs), this._session.id);
    if (value.language !== language) throw new ProtocolError('default context language changed');
    return value;
  }
  async create(options = {}) {
    const {language = 'python', cwd = '/workspace', contextId = randomBytes(12).toString('hex'), requestTimeoutMs} = codeOptions(options, ['language', 'cwd', 'contextId', 'requestTimeoutMs']);
    codeId(contextId);
    if (!cleanWorkspacePath(cwd, true)) throw new ConfigurationError('code cwd must be a clean /workspace path');
    await this._check(language, requestTimeoutMs);
    try {
      const value = codeContext(await this._rpc('POST', '/contexts', {context_id: contextId, language, cwd}, 201, requestTimeoutMs), this._session.id);
      if (value.id !== contextId || value.language !== language || value.cwd !== cwd) throw new ProtocolError('created context binding changed');
      return value;
    } catch (error) {
      error.contextId = contextId;
      error.sessionId = this._session.id;
      throw error;
    }
  }
  async list(options = {}) {
    const {requestTimeoutMs} = codeOptions(options, ['requestTimeoutMs']);
    await this._check(undefined, requestTimeoutMs);
    const value = await this._rpc('GET', '/contexts', undefined, 200, requestTimeoutMs);
    if (value.session_id !== this._session.id || !Array.isArray(value.contexts) || value.contexts.length > 4) throw new ProtocolError('invalid code context list');
    const contexts = value.contexts.map(row => codeContext(row, this._session.id));
    if (new Set(contexts.map(row => row.id)).size !== contexts.length) throw new ProtocolError('duplicate code contexts');
    return contexts;
  }
  async restart(context, options = {}) {
    const {requestTimeoutMs} = codeOptions(options, ['requestTimeoutMs']);
    context = this._context(context);
    await this._check(context.language, requestTimeoutMs);
    const value = codeContext(await this._rpc('POST', `/contexts/${context.id}/restart`, {generation: context.generation}, 202, requestTimeoutMs), this._session.id);
    if (value.id !== context.id || value.language !== context.language || ![context.generation, context.generation + 1].includes(value.generation)) throw new ProtocolError('restart changed context identity');
    return value;
  }
  async remove(context, options = {}) {
    const {requestTimeoutMs} = codeOptions(options, ['requestTimeoutMs']);
    context = this._context(context);
    await this._check(undefined, requestTimeoutMs);
    const value = await this._rpc('DELETE', `/contexts/${context.id}?generation=${context.generation}`, undefined, 202, requestTimeoutMs);
    if (value.session_id !== context.session_id || value.context_id !== context.id || value.removed !== true) throw new ProtocolError('invalid code removal acknowledgment');
  }
  connectExecution(context, executionId) {
    return new CodeExecution(this, this._context(context), codeId(executionId));
  }
  async execute(context, code, options = {}) {
    const {executionId = randomBytes(12).toString('hex'), environment = {}, timeoutMs = 60000, requestTimeoutMs} = codeOptions(options, ['executionId', 'environment', 'timeoutMs', 'requestTimeoutMs']);
    context = this._context(context);
    codeId(executionId);
    codeRequestTimeout(requestTimeoutMs);
    const env = codeInput(code, environment, timeoutMs);
    await this._check(context.language, requestTimeoutMs);
    const handle = this.connectExecution(context, executionId);
    try {
      const value = await this._rpc('POST', '/code-executions', {context_id: context.id, generation: context.generation,
        execution_id: executionId, code, environment: env, timeout_ms: timeoutMs}, 202, requestTimeoutMs);
      if (value.session_id !== context.session_id || value.execution_id !== executionId || value.accepted !== true) throw new ProtocolError('invalid code submission acknowledgment');
    } catch (error) {
      error.execution = handle;
      throw error;
    }
    return handle;
  }
}

/** A fixed owner/context/generation/language execution journal. */
export class CodeExecution {
  constructor(controller, context, executionId) {
    this._controller = controller;
    this._context = controller._context(context);
    this._id = codeId(executionId);
    this._path = `/code-executions/${this._id}`;
  }
  get id() { return this._id; }
  get context() { return this._context; }
  async poll(after = 0, options = {}) {
    const {requestTimeoutMs} = codeOptions(options, ['requestTimeoutMs']);
    if (!Number.isInteger(after) || after < 0 || after > 256) throw new ConfigurationError('code cursor must be in [0,256]');
    const page = await this._controller._rpc('GET', `${this._path}?after=${after}`, undefined, 200, requestTimeoutMs);
    const c = this.context;
    if (page.session_id !== c.session_id || page.id !== this.id || page.context_id !== c.id || page.generation !== c.generation || page.language !== c.language) throw new ProtocolError('code execution binding changed');
    if (!['running', ...CODE_TERMINAL].includes(page.status) || !Array.isArray(page.events) || page.events.length > 64 ||
        typeof page.events_evicted !== 'boolean' || !Number.isInteger(page.last_sequence) || page.last_sequence < 1 || page.last_sequence > 256 ||
        !Number.isInteger(page.next_sequence) || page.next_sequence !== after + page.events.length ||
        after > page.next_sequence || page.next_sequence > page.last_sequence ||
        !(page.failure === null || typeof page.failure === 'string' && page.failure.length <= 4096)) throw new ProtocolError('invalid code event page');
    if (page.events_evicted) {
      if (page.events.length || page.status === 'running' || after >= page.last_sequence) throw new ProtocolError('invalid evicted code page');
      return page;
    }
    if (!page.events.length && after < page.last_sequence) throw new ProtocolError('code event page omitted output');
    const preempted = page.status === 'cancelled' && page.failure === 'cancelled_before_submit';
    if (preempted && page.last_sequence !== 1) throw new ProtocolError('invalid cancellation placeholder');
    const fields = {started: ['type'], stdout: ['type', 'data'], stderr: ['type', 'data'], result: ['type', 'data', 'is_main_result'],
      error: ['type', 'name', 'value', 'traceback'], finished: ['type', 'status', 'context_usable']};
    let size = 0;
    for (let index = 0; index < page.events.length; index++) {
      const row = requireObject(page.events[index], 'invalid sequenced code event'), event = requireObject(row.event, 'invalid code event');
      const sequence = after + index + 1;
      if (!Number.isInteger(row.sequence) || row.sequence !== sequence || !Object.hasOwn(fields, event.type) ||
          Object.keys(event).length !== fields[event.type].length || fields[event.type].some(key => !Object.hasOwn(event, key)) ||
          (!preempted && (event.type === 'started') !== (sequence === 1)) || preempted && event.type !== 'finished') throw new ProtocolError('invalid code event kind or sequence');
      if (event.type === 'stdout' || event.type === 'stderr') {
        if (typeof event.data !== 'string' || event.data.length > 87384) throw new ProtocolError('invalid code output encoding');
        const data = Buffer.from(event.data, 'base64');
        if (data.toString('base64') !== event.data) throw new ProtocolError('invalid code output encoding');
        size += data.length;
      } else if (event.type === 'result') {
        const data = requireObject(event.data, 'invalid code rich result'), entries = Object.entries(data);
        const count = Buffer.byteLength(JSON.stringify(data));
        if (typeof event.is_main_result !== 'boolean' || !entries.length || entries.length > 16 || count > 32768 ||
            entries.some(([mime, value]) => mime.length > 128 || !mime.includes('/') || mime !== 'application/json' && typeof value !== 'string')) throw new ProtocolError('invalid code rich result');
        size += count;
      } else if (event.type === 'error') {
        for (const [key, limit] of [['name', 512], ['value', 16384], ['traceback', 32768]]) {
          if (typeof event[key] !== 'string' || Buffer.byteLength(event[key]) > limit || key === 'name' && !event[key]) throw new ProtocolError('invalid code error');
          size += Buffer.byteLength(event[key]);
        }
      } else if (event.type === 'finished' && (sequence !== page.last_sequence || event.status !== page.status || !CODE_TERMINAL.includes(event.status) || typeof event.context_usable !== 'boolean')) throw new ProtocolError('invalid code terminal event');
    }
    if (size > 65536 || CODE_TERMINAL.includes(page.status) && page.events.length && page.next_sequence === page.last_sequence && page.events.at(-1).event.type !== 'finished') throw new ProtocolError('code output budget or terminal event violated');
    return page;
  }
  async cancel(options = {}) {
    const {requestTimeoutMs} = codeOptions(options, ['requestTimeoutMs']);
    const value = await this._controller._rpc('DELETE', `${this._path}?context_id=${this.context.id}&generation=${this.context.generation}`, undefined, 202, requestTimeoutMs);
    if (value.session_id !== this.context.session_id || value.execution_id !== this.id || value.accepted !== true) throw new ProtocolError('invalid code cancellation acknowledgment');
  }
}

export class FileWatchHandle {
  constructor(session, info) {
    watchInfo(info, session.id);
    this._session = session;
    this.created = { ...info };
    this.id = info.id;
    this._path = `/v2/sessions/${session.id}/watches/${this.id}`;
  }
  async poll(after = 0) {
    if (!Number.isSafeInteger(after) || after < 0 || after > 2147483647) throw new ConfigurationError('invalid watch cursor');
    const page = await this._session._client._exchange('GET', `${this._path}?after=${after}`);
    const info = watchInfo(page.info, this._session.id);
    if (['id', 'path', 'recursive', 'include_entry'].some(k => info[k] !== this.created[k]) ||
        !Array.isArray(page.events) || page.events.length > 64 || !Number.isSafeInteger(page.next_sequence) ||
        page.next_sequence !== after + page.events.length || page.next_sequence > 2147483647 ||
        typeof page.complete !== 'boolean' || page.complete && ['starting', 'watching'].includes(info.state)) throw new ProtocolError('invalid watch page');
    for (const [n, event] of page.events.entries()) {
      if (event == null || typeof event !== 'object' || event.sequence !== after + n + 1 ||
          !['create', 'write', 'chmod', 'rename', 'remove'].includes(event.type) || typeof event.name !== 'string') throw new ProtocolError('invalid watch event');
      const full = event.name === '.' ? info.path : `${info.path}/${event.name}`;
      if (!cleanWorkspacePath(full, true) || event.name === '.' && event.type !== 'chmod' ||
          event.name !== '.' && (event.name.startsWith('/') || !info.recursive && event.name.includes('/'))) throw new ProtocolError('invalid relative watch name');
      if (event.entry != null) {
        if (!info.include_entry || ['remove', 'rename'].includes(event.type)) throw new ProtocolError('unexpected watch entry');
        e2bEntryInfo(event.entry, full);
      }
    }
    return page;
  }
  async stop() {
    const value = await this._session._client._exchange('DELETE', this._path);
    if (typeof value.stopped !== 'boolean') throw new ProtocolError('invalid watch stop response');
    return value.stopped;
  }
}

export const FilesystemEventType = Object.freeze({ CHMOD: 'chmod', CREATE: 'create', REMOVE: 'remove', RENAME: 'rename', WRITE: 'write' });

export class WatchHandle {
  constructor(native, onEvent, onExit) {
    this._native = native;
    this._stopped = false;
    this._stopTask = undefined;
    this._wake = undefined;
    this._task = this._consume(onEvent, onExit);
  }
  async stop() {
    this._stopped = true;
    this._wake?.();
    this._stopTask ??= this._native.stop();
    await this._stopTask;
  }
  async _consume(onEvent, onExit) {
    let failure;
    try {
      let after = 0;
      while (!this._stopped) {
        const page = await this._native.poll(after);
        for (const event of page.events) {
          if (this._stopped) break;
          const full = event.name === '.' ? page.info.path : `${page.info.path}/${event.name}`;
          await onEvent({ name: event.name, type: event.type, ...(event.entry == null ? {} : { entry: e2bEntryInfo(event.entry, full) }) });
          after = event.sequence;
        }
        if (this._stopped) break;
        if (page.complete) {
          if (page.info.state === 'failed') throw new SandboxError(`directory watch failed: ${page.info.error_code ?? 'unknown'}`);
          break;
        }
        if (page.events.length < 64) await new Promise(resolve => {
          const timer = setTimeout(() => { this._wake = undefined; resolve(); }, 25);
          this._wake = () => { clearTimeout(timer); this._wake = undefined; resolve(); };
        });
      }
    } catch (error) { if (!this._stopped) failure = error; }
    try { await this.stop(); } catch (error) { failure ??= error; }
    try { await onExit?.(failure); } catch { /* A terminal callback has no detached error recipient. */ }
  }
}

class E2BFilesystem {
  constructor(session) {
    this._session = session;
  }

  async read(path, opts = {}) {
    if (Object.keys(opts).some(key => key !== 'format')) {
      throw new UnsupportedCapability('E2B file read options are not supported');
    }
    const format = opts.format ?? 'text';
    if (format !== 'text' && format !== 'bytes') {
      throw new UnsupportedCapability('E2B file stream format is not supported');
    }
    const data = await this._session.readFile(path);
    if (format === 'bytes') return data;
    try { return new TextDecoder('utf-8', { fatal: true }).decode(data); }
    catch { throw new ProtocolError('file is not valid UTF-8 text; use format=bytes'); }
  }

  async exists(path, opts = {}) {
    if (Object.keys(opts).length) {
      throw new UnsupportedCapability('E2B file exists options are not supported');
    }
    try {
      await this._session.statFile(path);
    } catch (error) {
      if (error instanceof APIError && error.status === 404 && error.code === 'file_not_found') return false;
      throw error;
    }
    return true;
  }

  async write(pathOrFiles, dataOrOptions, options = {}) {
    if (Array.isArray(pathOrFiles)) return this.writeFiles(pathOrFiles, dataOrOptions ?? {});
    const results = await this.writeFiles([{ path: pathOrFiles, data: dataOrOptions }], options);
    return results[0];
  }

  async writeFiles(files, options = {}) {
    if (options == null || typeof options !== 'object' ||
        Object.keys(options).some(key => key !== 'metadata')) {
      throw new UnsupportedCapability('E2B write options are not supported');
    }
    const metadata = options.metadata;
    if (metadata !== undefined) validateE2BMetadata(metadata);
    if (!Array.isArray(files) || files.length > 16) {
      throw new ConfigurationError('E2B batch requires at most 16 files');
    }
    let total = 0;
    const prepared = files.map(entry => {
      if (entry == null || typeof entry !== 'object' ||
          Object.keys(entry).sort().join(',') !== 'data,path' || !cleanWorkspacePath(entry.path)) {
        throw new ConfigurationError('E2B write entry requires a clean path and data');
      }
      const parent = entry.path.slice(0, entry.path.lastIndexOf('/'));
      if (parent !== '/workspace' && parent.slice('/workspace/'.length).split('/').length > 16) {
        throw new ConfigurationError('directory depth exceeds 16 components');
      }
      let bytes;
      if (typeof entry.data === 'string') bytes = new TextEncoder().encode(entry.data);
      else if (entry.data instanceof Uint8Array) bytes = entry.data;
      else if (entry.data instanceof ArrayBuffer) bytes = new Uint8Array(entry.data);
      else throw new UnsupportedCapability('E2B streamed file input is not supported');
      total += bytes.byteLength;
      if (total > SESSION_FILE_LIMIT) throw new ConfigurationError('E2B batch bytes exceed 512 KiB');
      return { path: entry.path, parent, bytes };
    });
    const results = [];
    for (const entry of prepared) {
      if (entry.parent !== '/workspace') await this._session.makeDir(entry.parent);
      await this._session.writeFile(entry.path, entry.bytes, metadata);
      results.push({ name: entry.path.slice(entry.path.lastIndexOf('/') + 1),
        path: entry.path, type: 'file',
        ...(metadata && Object.keys(metadata).length ? { metadata } : {}) });
    }
    return results;
  }
  async list(path, options = {}) {
    if (options == null || typeof options !== 'object' ||
        Object.keys(options).some(key => key !== 'depth') ||
        (options.depth !== undefined && options.depth !== 1)) {
      throw new UnsupportedCapability('E2B list supports only default one-level directory options');
    }
    const value = await this._session._fileMetadata('list', path);
    if (!Array.isArray(value.entry_infos)) {
      throw new UnsupportedCapability('signed guest does not provide complete file info');
    }
    if (!Array.isArray(value.entries) || value.entries.length > SESSION_FILE_LIST_LIMIT ||
        value.size !== value.entries.length || value.entry_infos.length !== value.entries.length ||
        Object.hasOwn(value, 'info')) {
      throw new ProtocolError('file info list has invalid shape');
    }
    let totalNames = 0;
    let previousName = '';
    for (const name of value.entries) {
      if (typeof name !== 'string' || !name || name === '.' || name === '..' ||
          name.includes('/') || name.includes('\\') || /\p{Cc}/u.test(name) ||
          (previousName && name <= previousName) || Buffer.byteLength(name, 'utf8') > 255) {
        throw new ProtocolError('file info list has invalid name');
      }
      totalNames += Buffer.byteLength(name, 'utf8');
      if (totalNames > SESSION_FILE_LIST_NAME_BYTES_LIMIT) {
        throw new ProtocolError('file info list exceeds name budget');
      }
      previousName = name;
    }
    return value.entry_infos.map((info, index) => {
      if (info == null || info.name !== value.entries[index]) {
        throw new ProtocolError('file info list has an unbound entry');
      }
      return e2bEntryInfo(info, `${path}/${info.name}`);
    });
  }
  async getInfo(path, options = {}) {
    if (options == null || typeof options !== 'object' || Object.keys(options).length) {
      throw new UnsupportedCapability('E2B getInfo options are not supported');
    }
    const value = await this._session._fileMetadata('info', path);
    if (value.info == null) {
      throw new UnsupportedCapability('signed guest does not provide complete file info');
    }
    const info = e2bEntryInfo(value.info, path);
    if (!['directory', 'file', 'symlink', 'other'].includes(value.kind) ||
        info.type !== ({ directory: 'dir', file: 'file', symlink: 'symlink', other: undefined }[value.kind]) ||
        (info.type === 'file' && info.size !== value.size)) {
      throw new ProtocolError('file info differs from stat');
    }
    return info;
  }
  async makeDir(path, options = {}) {
    if (options == null || typeof options !== 'object' || Object.keys(options).length) {
      throw new UnsupportedCapability('E2B directory options are not supported');
    }
    if (path === '/workspace') return false;
    return this._session.makeDir(path);
  }
  async rename(oldPath, newPath, options = {}) {
    if (options == null || typeof options !== 'object' || Object.keys(options).length) {
      throw new UnsupportedCapability('E2B rename options are not supported');
    }
    return e2bEntryInfo(await this._session.renameFile(oldPath, newPath), newPath);
  }
  async remove(path, options = {}) {
    if (options == null || typeof options !== 'object' || Object.keys(options).length) {
      throw new UnsupportedCapability('E2B remove options are not supported');
    }
    await this._session.removePath(path);
  }
  async watchDir(path, onEvent, options = {}) {
    if (typeof onEvent !== 'function') throw new ConfigurationError('watchDir requires an event callback');
    if (options == null || typeof options !== 'object' || Array.isArray(options) ||
        Object.keys(options).some(k => !['recursive', 'includeEntry', 'timeoutMs', 'onExit', 'allowNetworkMounts'].includes(k)) || options.allowNetworkMounts) throw new UnsupportedCapability('unsupported directory watch options');
    if (options.onExit !== undefined && typeof options.onExit !== 'function') throw new ConfigurationError('onExit must be a function');
    const native = await this._session.startFileWatch(path, { recursive: options.recursive ?? false, includeEntry: options.includeEntry ?? false, timeoutMs: options.timeoutMs ?? 60000 });
    return new WatchHandle(native, onEvent, options.onExit);
  }
}

export class CommandExitError extends SandboxError {
  constructor(result) { super(result.error ?? `command exited with code ${result.exitCode}`);this.name='CommandExitError';Object.assign(this,result); }
}

function e2bCommandTimeout(value=60000){
  if(!Number.isSafeInteger(value)||value<0||value>86400000)throw new ConfigurationError('command timeout must be milliseconds in [0,86400000]');
  return value;
}

export class E2BCommandHandle {
  constructor(native,pid,deadline,options={}){
    this._native=native;this.pid=pid;this._deadline=deadline;this._options=options;
    this._disconnected=false;this._controller=new AbortController();this._stdout='';this._stderr='';
    this._task=this._consume();
  }
  get stdout(){return this._stdout;}
  get stderr(){return this._stderr;}
  async _consume(){
    const decoders={stdout:new TextDecoder(),stderr:new TextDecoder()};
    const append=(stream,text)=>{
      this[stream==='stdout'?'_stdout':'_stderr']+=text;
      const callback=stream==='stdout'?this._options.onStdout:this._options.onStderr;
      if(text && callback && !this._disconnected)callback(text);
    };
    try{
      const remaining=this._deadline===null?0:Math.ceil(this._deadline-Date.now());
      if(this._deadline!==null && remaining<=0)throw new TimeoutException('command observation timed out; process may still run');
      for await(const event of this._native.events(0,{timeoutMs:remaining,signal:this._controller.signal})){
        if(this._disconnected)break;
        if(event.stream)append(event.stream,decoders[event.stream].decode(event.data,{stream:true}));
        else if(event.result){
          for(const name of ['stdout','stderr'])append(name,decoders[name].decode());
          this._result={stdout:this._stdout,stderr:this._stderr,exitCode:event.result.exitCode,
            ...(event.result.guestResult?.error ? {error:event.result.guestResult.error}: {})};
        }
      }
    }catch(error){if(!this._disconnected)this._error=error;}
  }
  async wait(){
    await this._task;
    if(this._error)throw this._error;
    if(!this._result)throw new TransportError('command ended without a result; reconnect to observe it');
    if(this._result.exitCode!==0)throw new CommandExitError(this._result);
    return this._result;
  }
  async disconnect(){this._disconnected=true;this._controller.abort();}
  async kill(){return this._native.kill();}
  async sendStdin(data,options){await this._native.sendStdin(typeof data==='string'?new TextEncoder().encode(data):data,options);}
  async closeStdin(options){await this._native.closeStdin(options);}
}

class E2BCommands {
  constructor(session){this._session=session;}
  _options(options){if(options==null||typeof options!=='object'||Object.keys(options).length)throw new UnsupportedCapability('custom command request options are not available');}
  async list(options={}){
    this._options(options);
    return (await this._session.listCommands()).filter(info=>info.state==='running'&&info.pid>1).map(info=>({
      pid:info.pid,cmd:info.entrypoint,args:info.args,envs:info.environment??{},...(info.cwd?{cwd:info.cwd}:{})}));
  }
  async _find(pid,live=false){
    if(!Number.isSafeInteger(pid)||pid<=1||pid>2**30)throw new ConfigurationError('invalid guest command PID');
    return (await this._session.listCommands()).reverse().find(info=>info.pid===pid&&(!live||info.state==='running'));
  }
  async kill(pid,options={}){
    this._options(options);
    const info=await this._find(pid,true);
    return info?new CommandHandle(this._session,info).kill():false;
  }
  async connect(pid,options={}){
    const {timeoutMs=60000,onStdout,onStderr,...extra}=options;
    this._options(extra);const duration=e2bCommandTimeout(timeoutMs);
    for(const callback of [onStdout,onStderr])if(callback!==undefined&&typeof callback!=='function')throw new ConfigurationError('output callback must be a function');
    const info=await this._find(pid);
    if(!info)throw new APIError(404,'command_not_found','command not found');
    return new E2BCommandHandle(new CommandHandle(this._session,info),pid,duration===0?null:Date.now()+duration,{onStdout,onStderr});
  }
  async run(cmd,options={}){
    const {background=false,envs,cwd,onStdout,onStderr,timeoutMs=60000,stdin=false,user,...extra}=options;
    this._options(extra);
    if(user!==undefined)throw new UnsupportedCapability('custom users are not available yet');
    if(typeof stdin!=='boolean')throw new ConfigurationError('stdin must be boolean');
    if(typeof background!=='boolean' || typeof cmd!=='string' || !cmd || cmd.includes('\0') || Buffer.byteLength(cmd)>4096)throw new ConfigurationError('invalid command or background flag');
    for(const callback of [onStdout,onStderr])if(callback!==undefined&&typeof callback!=='function')throw new ConfigurationError('output callback must be a function');
    const duration=e2bCommandTimeout(timeoutMs),deadline=duration===0?null:Date.now()+duration;
    const caps=await this._session._client.capabilities({template:{backend:this._session.created.backend,artifactManifestSha256:this._session.created.artifactManifestSha256}});
    if(stdin && !caps.features?.interactive_stdin)throw new UnsupportedCapability('interactive stdin is not available on this template');
    if(!caps.allowed_entrypoints.includes('/bin/bash'))throw new UnsupportedCapability('template has no authorized Bash entrypoint');
    const native=await this._session.startCommand({entrypoint:'/bin/bash',args:['-l','-c',cmd],timeoutMs:caps.limits.max_timeout_ms,interactiveStdin:stdin,
      ...(envs===undefined?{}:{environment:envs}),...(cwd===undefined?{}:{cwd})});
    let info;
    while(true){
      const page=await native.poll();info=page.info;
      if(Number.isSafeInteger(info.pid)&&info.pid>1)break;
      if(page.complete)throw new TransportError('command failed before a guest PID was created');
      if(deadline!==null&&Date.now()>=deadline)throw new TimeoutException('command start observation timed out');
      await new Promise(resolve=>setTimeout(resolve,10));
    }
    const handle=new E2BCommandHandle(native,info.pid,deadline,{onStdout,onStderr});
    return background?handle:handle.wait();
  }
  async sendStdin(pid,data,options){
    const info=await this._find(pid,true);if(!info)throw new APIError(404,'command_not_found','command not found');
    await new CommandHandle(this._session,info).sendStdin(typeof data==='string'?new TextEncoder().encode(data):data,options);
  }
  async closeStdin(pid,options){
    const info=await this._find(pid,true);if(!info)throw new APIError(404,'command_not_found','command not found');
    await new CommandHandle(this._session,info).closeStdin(options);
  }
}

function e2bSandboxInfo(info){
  const startedAt=new Date(info.createdAt),endAt=new Date(info.expiresAt),maxEndAt=new Date(info.maxExpiresAt);
  if(!Number.isSafeInteger(info.memoryMiB)||info.memoryMiB<1||!Number.isSafeInteger(info.vcpus)||info.vcpus<1||!['fc-agent/v2','fc-agent/v3'].includes(info.guestProtocol)||
    [startedAt,endAt,maxEndAt].some(date=>!Number.isFinite(date.getTime()))||startedAt>endAt||endAt>maxEndAt)throw new ProtocolError('invalid real sandbox metadata');
  return {sandboxId:info.id,templateId:info.backend,metadata:{},startedAt,endAt,maxEndAt,state:info.state,cpuCount:info.vcpus,memoryMB:info.memoryMiB,
    envdVersion:info.guestProtocol,allowInternetAccess:false,lifecycle:{onTimeout:'kill',autoResume:false},volumeMounts:[]};
}
export class E2BSandboxPaginator{
  constructor(client,{limit=20,nextToken,order='desc'}={}){
    if(!Number.isSafeInteger(limit)||limit<1||limit>100||!['asc','desc'].includes(order))throw new ConfigurationError('invalid pagination limit/order');
    if(nextToken!==undefined&&(typeof nextToken!=='string'||! /^[A-Za-z0-9_-]{1,128}$/.test(nextToken)))throw new ConfigurationError('invalid session cursor');
    this._client=client;this._limit=limit;this._order=order;this.nextToken=nextToken;this.hasNext=true;this._busy=false;
  }
  async nextItems(options={}){
    if(Object.keys(options).length)throw new UnsupportedCapability('custom pagination request options are not available');
    if(this._busy)throw new ConfigurationError('pagination request already active');
    if(!this.hasNext)throw new SandboxError('No more items to fetch');
    this._busy=true;
    try{
      const page=await this._client.listSessions({limit:this._limit,cursor:this.nextToken,order:this._order});
      const items=page.sessions.map(e2bSandboxInfo);this.nextToken=page.nextCursor;this.hasNext=this.nextToken!==undefined;return items;
    }finally{this._busy=false;}
  }
}

export class CodeCleanupError extends TransportError {
  constructor(execution, originalError, cleanupError) {
    super('code termination could not be confirmed; owner close requested', {cause: originalError});
    Object.assign(this, {execution, originalError, cleanupError, ownerCloseRequested: true});
  }
}
export class CodeExecutionFailed extends SandboxError {
  constructor(execution, status, failure) {
    super(`code execution ${status}: ${failure ?? 'no runtime detail'}`);
    Object.assign(this, {execution, status, failure});
  }
}
export class OutputMessage {
  constructor(line, timestamp, error = false) { Object.assign(this, {line, timestamp, error}); }
  toString() { return this.line; }
}
export class ExecutionError {
  constructor(name, value, traceback) { Object.assign(this, {name, value, traceback}); }
}
const RESULT_MIME = {'text/plain':'text', 'text/html':'html', 'text/markdown':'markdown', 'image/svg+xml':'svg',
  'image/png':'png', 'image/jpeg':'jpeg', 'application/pdf':'pdf', 'text/latex':'latex',
  'application/json':'json', 'application/javascript':'javascript'};
export class Result {
  constructor(data, isMainResult) {
    this.mimeData = {...data}; this.raw = {}; this.isMainResult = isMainResult; this.extra = {};
    for (const [mime, value] of Object.entries(data)) {
      if (Object.hasOwn(RESULT_MIME, mime)) this[RESULT_MIME[mime]] = value;
      else Object.defineProperty(this.extra, mime, {value, enumerable: true, configurable: true, writable: true});
      Object.defineProperty(this.raw, Object.hasOwn(RESULT_MIME, mime) ? RESULT_MIME[mime] : mime, {value, enumerable: true, configurable: true, writable: true});
    }
  }
  formats() { return [...Object.values(RESULT_MIME).filter(name => this[name] !== undefined), ...Object.keys(this.extra)]; }
  toJSON() { return {...Object.fromEntries(Object.values(RESULT_MIME).filter(name => this[name] !== undefined).map(name => [name, this[name]])), is_main_result: this.isMainResult, extra: this.extra}; }
}
export class Execution {
  constructor(results = [], logs = {stdout: [], stderr: []}, error, executionCount) {
    Object.assign(this, {results, logs, error, executionCount});
  }
  get text() { return this.results.find(result => result.isMainResult)?.text; }
  toJSON() { return {results: this.results, logs: this.logs, error: this.error}; }
}
const codeContextOwners = new WeakMap();
function compatibleCodeContext(context) {
  const value = Object.freeze({id: context.id, language: context.language, cwd: context.cwd});
  codeContextOwners.set(value, context.session_id);
  return value;
}
function codeContextRef(controller, context) {
  if (typeof context === 'string') return codeId(context);
  if (context === null || typeof context !== 'object') throw new ConfigurationError('context must be a Context or context ID');
  const owner = codeContextOwners.get(context) ?? context.session_id;
  if (owner !== undefined && owner !== controller._session.id) throw new ConfigurationError('context belongs to another session');
  return codeId(context.id);
}
function codeRemaining(deadline, requestTimeoutMs) {
  const remaining = deadline === undefined ? Infinity : deadline - performance.now();
  if (remaining <= 0) throw new TimeoutException('code execution observation timed out');
  return Math.min(codeRequestTimeout(requestTimeoutMs), remaining);
}
function codeObserve(action, deadline, signal) {
  return new Promise((resolve, reject) => {
    let done = false, timer;
    const finish = (error, value) => {
      if (done) return;
      done = true; clearTimeout(timer); signal?.removeEventListener('abort', onAbort);
      if (error) reject(error); else resolve(value);
    };
    const onAbort = () => finish(signal.reason instanceof Error ? signal.reason : new SandboxError('code observation cancelled'));
    if (signal?.aborted) { onAbort(); return; }
    signal?.addEventListener('abort', onAbort, {once: true});
    if (deadline !== undefined) {
      const remaining = deadline - performance.now();
      if (remaining <= 0) { finish(new TimeoutException('code execution observation timed out')); return; }
      timer = setTimeout(() => finish(new TimeoutException('code execution observation timed out')), remaining);
    }
    Promise.resolve().then(() => {
      if (done) return;
      return action();
    }).then(value => {
      if (deadline !== undefined && performance.now() >= deadline) finish(new TimeoutException('code execution observation timed out'));
      else finish(undefined, value);
    }, error => finish(error));
  });
}
async function codeRpcObserve(action, deadline, signal) {
  try { return await codeObserve(action, deadline, signal); }
  catch (error) {
    // Preserve callback and abort errors; classify RPC failures before cleanup.
    if (error instanceof TransportError && !(error instanceof TimeoutException) &&
        !(error instanceof CodeCleanupError) && !signal?.aborted &&
        deadline !== undefined && performance.now() >= deadline) {
      throw new TimeoutException('code execution observation timed out', {cause: error});
    }
    throw error;
  }
}
const codePause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function codeReady(controller, current, {requestTimeoutMs, expectedGeneration, missingId, signal} = {}) {
  const deadline = performance.now() + 40000, id = missingId ?? current.id;
  while (true) {
    if (current) {
      if (expectedGeneration !== undefined && current.generation > expectedGeneration) throw new APIError(409, 'stale_context', 'context restarted concurrently');
      if (current.state === 'failed') throw new CodeExecutionFailed(undefined, 'context_failed', current.failure);
      if (current.state === 'idle' && (expectedGeneration === undefined || current.generation === expectedGeneration)) return current;
      if (['running', 'interrupting'].includes(current.state)) throw new APIError(409, 'context_busy', 'context is executing another cell');
    }
    await codeObserve(() => codePause(Math.min(20, codeRemaining(deadline, requestTimeoutMs))), deadline, signal);
    try { current = await codeObserve(() => controller.get(id, {requestTimeoutMs: codeRemaining(deadline, requestTimeoutMs)}), deadline, signal); }
    catch (error) { if (!missingId || !(error instanceof APIError) || error.status !== 404 || error.code !== 'code_not_found') throw error; }
  }
}
async function codeStopConfirm(execution) {
  const deadline = performance.now() + 8000;
  let cursor = 0, nextCancel = 0, lastError = new TransportError('no terminal journal confirmation');
  while (performance.now() < deadline) {
    if (performance.now() >= nextCancel) {
      try { await execution.cancel({requestTimeoutMs: Math.min(2000, Math.max(1, deadline - performance.now()))}); }
      catch (error) { lastError = error; }
      nextCancel = performance.now() + 250;
    }
    try {
      const page = await execution.poll(cursor, {requestTimeoutMs: Math.min(2000, Math.max(1, deadline - performance.now()))});
      if (CODE_TERMINAL.includes(page.status) && (page.events_evicted || page.next_sequence === page.last_sequence)) return;
      cursor = page.next_sequence;
    } catch (error) { if (error instanceof ProtocolError) throw error; lastError = error; }
    await codePause(Math.min(20, Math.max(0, deadline - performance.now())));
  }
  throw lastError;
}
async function codeStopOrClose(execution, originalError) {
  try { await codeStopConfirm(execution); }
  catch (error) {
    const controller = execution._controller;
    try { await controller._session._client._exchange('DELETE', controller._path, undefined, [204], 6000); } catch {}
    throw new CodeCleanupError(execution, originalError, error);
  }
}
async function compatibleRunCode(controller, code, options = {}) {
  codeOptions(options, ['language', 'context', 'envs', 'timeoutMs', 'requestTimeoutMs', 'signal', 'onStdout', 'onStderr', 'onResult', 'onError']);
  const {language, context, timeoutMs = 60000, requestTimeoutMs, signal, onStdout, onStderr, onResult, onError} = options;
  if (language !== undefined && context !== undefined) throw new ConfigurationError('provide language or context, not both');
  if (context !== undefined && (context === null || typeof context !== 'object')) throw new ConfigurationError('runCode context must be a Context');
  for (const callback of [onStdout, onStderr, onResult, onError]) if (callback !== undefined && typeof callback !== 'function') throw new ConfigurationError('invalid code callback');
  if (signal !== undefined && (typeof signal?.aborted !== 'boolean' || typeof signal.addEventListener !== 'function')) throw new ConfigurationError('invalid code AbortSignal');
  if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new SandboxError('code observation cancelled');
  const env = codeInput(code, options.envs ?? {}, timeoutMs);
  codeRequestTimeout(requestTimeoutMs);
  let current = await codeObserve(() => context === undefined ? controller.default(language ?? 'python', {requestTimeoutMs}) : controller.get(codeContextRef(controller, context), {requestTimeoutMs}), undefined, signal);
  current = await codeReady(controller, current, {requestTimeoutMs, expectedGeneration: current.generation, signal});
  const deadline = timeoutMs === 0 ? undefined : performance.now() + timeoutMs;
  const executionId = randomBytes(12).toString('hex'), handle = controller.connectExecution(current, executionId);
  const result = new Execution(); result.executionId = executionId;
  const decoders = {stdout: new TextDecoder(), stderr: new TextDecoder()}, callbacks = {stdout: onStdout, stderr: onStderr};
  let needsCleanup = true, attempted = false, cursor = 0;
  const output = async (stream, text) => {
    if (!text) return;
    result.logs[stream].push(text);
    if (callbacks[stream]) await codeObserve(() => callbacks[stream](new OutputMessage(text, Date.now() * 1e6, stream === 'stderr')), deadline, signal);
  };
  try {
    try {
      await codeRpcObserve(() => {
        const bounded = codeRemaining(deadline, requestTimeoutMs);
        attempted = true;
        return controller.execute(current, code, {executionId, environment: env, timeoutMs, requestTimeoutMs: bounded});
      }, deadline, signal);
    } catch (error) {
      if (error instanceof APIError && [400, 403, 404, 409, 429, 501].includes(error.status)) needsCleanup = false;
      throw error;
    }
    while (true) {
      const page = await codeRpcObserve(() => handle.poll(cursor, {requestTimeoutMs: codeRemaining(deadline, requestTimeoutMs)}), deadline, signal);
      if (page.events_evicted) throw new ProtocolError('code output was evicted before delivery');
      for (const {event} of page.events) {
        codeRemaining(deadline, requestTimeoutMs);
        if (Object.hasOwn(decoders, event.type)) await output(event.type, decoders[event.type].decode(Buffer.from(event.data, 'base64'), {stream: true}));
        else if (event.type === 'result') {
          const item = new Result(event.data, event.is_main_result); result.results.push(item);
          if (onResult) await codeObserve(() => onResult(item), deadline, signal);
        } else if (event.type === 'error') {
          result.error = new ExecutionError(event.name, event.value, event.traceback);
          if (onError) await codeObserve(() => onError(result.error), deadline, signal);
        }
      }
      cursor = page.next_sequence;
      if (CODE_TERMINAL.includes(page.status) && cursor === page.last_sequence) {
        for (const stream of Object.keys(decoders)) await output(stream, decoders[stream].decode());
        codeRemaining(deadline, requestTimeoutMs);
        if (page.status === 'timed_out') throw new TimeoutException('guest code execution timed out');
        if (page.status !== 'completed') throw new CodeExecutionFailed(handle, page.status, page.failure);
        return result;
      }
      await codeObserve(() => codePause(20), deadline, signal);
    }
  } catch (error) {
    if (error instanceof Error && Object.isExtensible(error) && !Object.hasOwn(error, 'execution')) error.execution = handle;
    if (needsCleanup && attempted) await codeStopOrClose(handle, error);
    throw error;
  }
}
async function compatibleCreateCodeContext(controller, options = {}) {
  const {language = 'python', cwd = '/workspace', requestTimeoutMs} = codeOptions(options, ['language', 'cwd', 'requestTimeoutMs']);
  const contextId = randomBytes(12).toString('hex');
  let current;
  try {
    try { current = await controller.create({language, cwd, contextId, requestTimeoutMs}); }
    catch (error) { if (!error.contextId || error instanceof APIError && error.status < 500) throw error; }
    return compatibleCodeContext(await codeReady(controller, current, {requestTimeoutMs, expectedGeneration: 1, missingId: current ? undefined : contextId}));
  } catch (error) { error.contextId = contextId; error.sessionId = controller._session.id; throw error; }
}
async function compatibleCodeMutation(controller, context, restart) {
  const id = codeContextRef(controller, context), current = await controller.get(id);
  try {
    if (restart) {
      const starting = await controller.restart(current);
      await codeReady(controller, starting, {expectedGeneration: current.generation + 1});
    } else {
      await controller.remove(current);
      const deadline = performance.now() + 40000;
      while (true) {
        let observed;
        try { observed = await controller.get(id, {requestTimeoutMs: codeRemaining(deadline)}); }
        catch (error) { if (error instanceof APIError && error.status === 404 && error.code === 'code_not_found') return; throw error; }
        if (observed.generation !== current.generation) throw new APIError(409, 'stale_context', 'context restarted concurrently');
        await codePause(Math.min(20, codeRemaining(deadline)));
      }
    }
  } catch (error) { error.contextId = id; error.sessionId = controller._session.id; throw error; }
}

export class Sandbox {
  constructor(session) {
    this._session = session;
    this.sandboxId = session.id;
    this.files = new E2BFilesystem(session);
    this.commands = new E2BCommands(session);
  }

  static async create(template, { client, timeoutMs, ...options } = {}) {
    if (!(client instanceof Client)) throw new ConfigurationError('E2B facade requires a native Client');
    if (template !== 'firecracker-linux' || Object.keys(options).length) {
      throw new UnsupportedCapability('E2B facade requires the signed firecracker-linux template without extra options');
    }
    if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 300000)) {
      throw new ConfigurationError('timeoutMs must be in [1000,300000]');
    }
    return new this(await client.createSession(timeoutMs === undefined ? {} : { ttlMs: timeoutMs }));
  }

  static async connect(sandboxId, { client, timeoutMs, onResume = 'restore', ...options } = {}) {
    if (!(client instanceof Client)) throw new ConfigurationError('E2B facade requires a native Client');
    if (timeoutMs !== undefined || onResume !== 'restore' || Object.keys(options).length) {
      throw new UnsupportedCapability('paused resume and live timeout update are not available');
    }
    return new this(await client.connectSession(sandboxId));
  }

  async isRunning(options = {}) {
    if (Object.keys(options).length) throw new UnsupportedCapability('per-call E2B request options are not available');
    try {
      await this._session.info();
    } catch (error) {
      if (error instanceof APIError && error.status === 404 && error.code === 'not_found') return false;
      throw error;
    }
    return true;
  }

  async kill(options = {}) {
    if (Object.keys(options).length) throw new UnsupportedCapability('per-call E2B request options are not available');
    try {
      await this._session.close();
    } catch (error) {
      if (error instanceof APIError && error.status === 404 && error.code === 'not_found') return false;
      throw error;
    }
    return true;
  }

  static list({client,limit,nextToken,order,query,...options}={}){
    if(!(client instanceof Client))throw new ConfigurationError('E2B facade requires a native Client');
    if(Object.keys(options).length||query!==undefined&&JSON.stringify(query)!=='{}'&&JSON.stringify(query)!=='{"state":["running"]}')throw new UnsupportedCapability('custom session query options are not available');
    return new E2BSandboxPaginator(client,{...(limit===undefined?{}:{limit}),nextToken,...(order===undefined?{}:{order})});
  }
  async getInfo(options={}){if(Object.keys(options).length)throw new UnsupportedCapability('custom info request options are not available');return e2bSandboxInfo(await this._session.info());}
  async setTimeout(timeoutMs,options={}){if(Object.keys(options).length)throw new UnsupportedCapability('custom timeout request options are not available');await this._session.setTimeout(timeoutMs);}
  pause() { throw new UnsupportedCapability('E2B pause is not available'); }
  fork() { throw new UnsupportedCapability('E2B stateful fork is not available'); }
  getHost() { throw new UnsupportedCapability('E2B port tunnels are not available'); }
  uploadUrl() { throw new UnsupportedCapability('E2B upload URLs are not available'); }
  downloadUrl() { throw new UnsupportedCapability('E2B download URLs are not available'); }
  runCode(code, options) { return compatibleRunCode(this._session.code, code, options); }
  createCodeContext(options) { return compatibleCreateCodeContext(this._session.code, options); }
  async listCodeContexts() { return (await this._session.code.list()).map(compatibleCodeContext); }
  restartCodeContext(context) { return compatibleCodeMutation(this._session.code, context, true); }
  removeCodeContext(context) { return compatibleCodeMutation(this._session.code, context, false); }
}
