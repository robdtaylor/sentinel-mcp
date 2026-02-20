/**
 * Sentinel MCP - Lightweight MCP Protocol Client
 *
 * Connects to MCP servers via stdio or HTTP transport,
 * performs the initialization handshake, and queries
 * tools/list, resources/list, prompts/list.
 *
 * Uses JSON-RPC 2.0 over newline-delimited JSON (stdio)
 * or HTTP POST (streamable-http / SSE).
 */

import { spawn, type Subprocess } from 'bun';
import type { MCPServerConfig } from './types';

// ============================================================================
// MCP Protocol Types
// ============================================================================

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export interface MCPTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface MCPResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

export interface MCPPrompt {
  name: string;
  description?: string;
  arguments?: Array<{ name: string; description?: string; required?: boolean }>;
}

export interface MCPServerInfo {
  name?: string;
  version?: string;
  protocolVersion?: string;
  capabilities?: Record<string, unknown>;
  tools: MCPTool[];
  resources: MCPResource[];
  prompts: MCPPrompt[];
  error?: string;
  connectTimeMs?: number;
}

// ============================================================================
// Stdio Transport
// ============================================================================

const CONNECT_TIMEOUT = 10_000; // 10s to connect + initialize
const REQUEST_TIMEOUT = 5_000;  // 5s per request

/**
 * Connect to an MCP server via stdio transport
 */
export async function connectStdio(
  config: MCPServerConfig,
  serverName: string
): Promise<MCPServerInfo> {
  const startTime = Date.now();

  if (!config.command) {
    return { tools: [], resources: [], prompts: [], error: 'No command specified' };
  }

  // Parse command - first word is the binary, rest are initial args
  const parts = config.command.split(/\s+/);
  const cmd = parts[0];
  const cmdArgs = [...parts.slice(1), ...(config.args || [])];

  let proc: Subprocess | null = null;

  try {
    // Spawn the server process
    proc = spawn({
      cmd: [cmd, ...cmdArgs],
      env: { ...process.env, ...(config.env || {}) },
      stdin: 'pipe',
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const stdin = proc.stdin as import('bun').FileSink;
    const reader = new StdioReader(proc);
    let messageId = 0;

    // Helper: send JSON-RPC and wait for response
    const sendRequest = async (method: string, params?: Record<string, unknown>): Promise<unknown> => {
      const id = ++messageId;
      const request: JsonRpcRequest = {
        jsonrpc: '2.0',
        id,
        method,
        params,
      };

      const line = JSON.stringify(request) + '\n';
      stdin.write(line);
      stdin.flush();

      const response = await reader.waitForResponse(id, REQUEST_TIMEOUT);
      if (response.error) {
        throw new Error(`${method} failed: ${response.error.message}`);
      }
      return response.result;
    };

    // Helper: send notification (no response expected)
    const sendNotification = (method: string, params?: Record<string, unknown>) => {
      const notification = {
        jsonrpc: '2.0' as const,
        method,
        params,
      };
      stdin.write(JSON.stringify(notification) + '\n');
      stdin.flush();
    };

    // Step 1: Initialize
    const initResult = await sendRequest('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: {
        name: 'sentinel-mcp',
        version: '0.1.0',
      },
    }) as Record<string, unknown>;

    // Step 2: Send initialized notification
    sendNotification('notifications/initialized');

    // Step 3: Query tools, resources, prompts in parallel
    const info: MCPServerInfo = {
      name: (initResult?.serverInfo as Record<string, string>)?.name,
      version: (initResult?.serverInfo as Record<string, string>)?.version,
      protocolVersion: initResult?.protocolVersion as string,
      capabilities: initResult?.capabilities as Record<string, unknown>,
      tools: [],
      resources: [],
      prompts: [],
      connectTimeMs: Date.now() - startTime,
    };

    // Query tools
    try {
      const toolsResult = await sendRequest('tools/list') as { tools?: MCPTool[] };
      info.tools = toolsResult?.tools || [];
    } catch {
      // Server may not support tools
    }

    // Query resources
    try {
      const resourcesResult = await sendRequest('resources/list') as { resources?: MCPResource[] };
      info.resources = resourcesResult?.resources || [];
    } catch {
      // Server may not support resources
    }

    // Query prompts
    try {
      const promptsResult = await sendRequest('prompts/list') as { prompts?: MCPPrompt[] };
      info.prompts = promptsResult?.prompts || [];
    } catch {
      // Server may not support prompts
    }

    return info;
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    return {
      tools: [],
      resources: [],
      prompts: [],
      error: `Failed to connect to "${serverName}": ${error}`,
      connectTimeMs: Date.now() - startTime,
    };
  } finally {
    // Clean up the process
    if (proc) {
      try {
        (proc.stdin as import('bun').FileSink).end();
        proc.kill();
      } catch {
        // Process may have already exited
      }
    }
  }
}

// ============================================================================
// Stdio Reader - Parses newline-delimited JSON-RPC from stdout
// ============================================================================

class StdioReader {
  private buffer = '';
  private pendingResponses = new Map<number, {
    resolve: (r: JsonRpcResponse) => void;
    reject: (e: Error) => void;
  }>();
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private decoder = new TextDecoder();
  private reading = false;

  constructor(proc: Subprocess) {
    this.reader = (proc.stdout as ReadableStream<Uint8Array>).getReader();
    this.startReading();
  }

  private async startReading() {
    if (this.reading) return;
    this.reading = true;

    try {
      while (true) {
        const { done, value } = await this.reader.read();
        if (done) break;

        this.buffer += this.decoder.decode(value, { stream: true });
        this.processBuffer();
      }
    } catch {
      // Stream closed
    }
  }

  private processBuffer() {
    const lines = this.buffer.split('\n');
    // Keep the last incomplete line in the buffer
    this.buffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      try {
        const msg = JSON.parse(trimmed);
        if (msg.id !== undefined && this.pendingResponses.has(msg.id)) {
          const pending = this.pendingResponses.get(msg.id)!;
          this.pendingResponses.delete(msg.id);
          pending.resolve(msg as JsonRpcResponse);
        }
        // Ignore notifications from server (no id)
      } catch {
        // Skip non-JSON lines (server logs, etc.)
      }
    }
  }

  async waitForResponse(id: number, timeoutMs: number): Promise<JsonRpcResponse> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingResponses.delete(id);
        reject(new Error(`Request ${id} timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pendingResponses.set(id, {
        resolve: (r) => {
          clearTimeout(timer);
          resolve(r);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
    });
  }
}

// ============================================================================
// HTTP Transport
// ============================================================================

/**
 * Connect to an MCP server via HTTP transport (SSE / streamable-http)
 */
export async function connectHTTP(
  config: MCPServerConfig,
  serverName: string
): Promise<MCPServerInfo> {
  const startTime = Date.now();

  if (!config.url) {
    return { tools: [], resources: [], prompts: [], error: 'No URL specified' };
  }

  try {
    let messageId = 0;

    const sendRequest = async (method: string, params?: Record<string, unknown>): Promise<unknown> => {
      const request: JsonRpcRequest = {
        jsonrpc: '2.0',
        id: ++messageId,
        method,
        params,
      };

      const response = await fetch(config.url!, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(config.env?.AUTHORIZATION ? { Authorization: config.env.AUTHORIZATION } : {}),
        },
        body: JSON.stringify(request),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json() as JsonRpcResponse;
      if (result.error) {
        throw new Error(`${method} failed: ${result.error.message}`);
      }
      return result.result;
    };

    // Initialize
    const initResult = await sendRequest('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'sentinel-mcp', version: '0.1.0' },
    }) as Record<string, unknown>;

    const info: MCPServerInfo = {
      name: (initResult?.serverInfo as Record<string, string>)?.name,
      version: (initResult?.serverInfo as Record<string, string>)?.version,
      protocolVersion: initResult?.protocolVersion as string,
      capabilities: initResult?.capabilities as Record<string, unknown>,
      tools: [],
      resources: [],
      prompts: [],
      connectTimeMs: Date.now() - startTime,
    };

    // Query tools
    try {
      const toolsResult = await sendRequest('tools/list') as { tools?: MCPTool[] };
      info.tools = toolsResult?.tools || [];
    } catch { /* not supported */ }

    // Query resources
    try {
      const resourcesResult = await sendRequest('resources/list') as { resources?: MCPResource[] };
      info.resources = resourcesResult?.resources || [];
    } catch { /* not supported */ }

    // Query prompts
    try {
      const promptsResult = await sendRequest('prompts/list') as { prompts?: MCPPrompt[] };
      info.prompts = promptsResult?.prompts || [];
    } catch { /* not supported */ }

    return info;
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    return {
      tools: [],
      resources: [],
      prompts: [],
      error: `Failed to connect to "${serverName}" at ${config.url}: ${error}`,
      connectTimeMs: Date.now() - startTime,
    };
  }
}
