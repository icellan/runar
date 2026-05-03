/**
 * JavaDaemon — long-lived JVM compile server for the conformance runner.
 *
 * Replaces N × `java -jar runar-java.jar` (N × ~1.5s JVM cold-start) with
 * a single persistent JVM that reads line-delimited JSON RPC on stdin and
 * writes line-delimited JSON responses on stdout.
 *
 * Wire protocol (each direction is one JSON object per line):
 *
 *   request:  {"id": 7, "source": "/tmp/foo.runar.ts", "emitIr": true,
 *              "hex": true, "disableConstantFolding": true}
 *   response: {"id": 7, "ok": true, "ir": "<canonical-anf-json>",
 *              "hex": "<bitcoin-script-hex>"}
 *   error:    {"id": 7, "ok": false, "error": "<message>"}
 *
 * Disable with `RUNAR_JAVA_DAEMON=0`. Enabled by default whenever a runar-java
 * jar is on disk.
 */

import { spawn, ChildProcessWithoutNullStreams } from 'child_process';

export interface JavaCompileResponse {
  ok: boolean;
  ir?: string;
  hex?: string;
  error?: string;
}

interface PendingRequest {
  resolve: (resp: JavaCompileResponse) => void;
  reject: (err: Error) => void;
}

export class JavaDaemon {
  private proc: ChildProcessWithoutNullStreams;
  private nextId = 1;
  private pending = new Map<number, PendingRequest>();
  private buffer = '';
  private stderrBuffer = '';
  private stopped = false;
  private banner: Promise<void>;

  static start(jarPath: string): JavaDaemon {
    return new JavaDaemon(jarPath);
  }

  private constructor(jarPath: string) {
    this.proc = spawn('java', ['-jar', jarPath, '--daemon'], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    this.proc.stdout.setEncoding('utf-8');
    this.proc.stderr.setEncoding('utf-8');

    this.proc.stdout.on('data', (chunk: string) => this.onStdout(chunk));
    this.proc.stderr.on('data', (chunk: string) => {
      // Capture stderr for diagnostics on unexpected exits.
      this.stderrBuffer += chunk;
      if (this.stderrBuffer.length > 64 * 1024) {
        this.stderrBuffer = this.stderrBuffer.slice(-32 * 1024);
      }
    });

    this.proc.on('error', (err) => this.failAll(err));
    this.proc.on('close', (code) => {
      if (!this.stopped) {
        this.failAll(new Error(`Java daemon exited unexpectedly with code ${code}: ${this.stderrBuffer}`));
      }
    });

    // Wait for the banner line so we know the JVM is ready before we send
    // the first compile request. Without this the first compile occasionally
    // races against JVM bootstrap on slow hosts.
    this.banner = new Promise<void>((resolveBanner, rejectBanner) => {
      const timer = setTimeout(() => {
        rejectBanner(new Error('Java daemon banner timeout (10s)'));
      }, 10_000);
      this.bannerResolve = () => {
        clearTimeout(timer);
        resolveBanner();
      };
      this.bannerReject = (err: Error) => {
        clearTimeout(timer);
        rejectBanner(err);
      };
    });
  }

  private bannerResolve: (() => void) | null = null;
  private bannerReject: ((err: Error) => void) | null = null;
  private bannerSeen = false;

  private onStdout(chunk: string): void {
    this.buffer += chunk;
    let nl: number;
    while ((nl = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (!line) continue;
      if (!this.bannerSeen) {
        this.bannerSeen = true;
        if (this.bannerResolve) this.bannerResolve();
        // The banner line is a one-shot announcement. Don't try to parse it
        // as a response.
        if (line.includes('"daemon"')) continue;
      }
      this.handleLine(line);
    }
  }

  private handleLine(line: string): void {
    let parsed: { id?: number; ok?: boolean; ir?: string; hex?: string; error?: string };
    try {
      parsed = JSON.parse(line);
    } catch {
      // Probably a stray log line — ignore.
      return;
    }
    const id = parsed.id;
    if (typeof id !== 'number') return;
    const pending = this.pending.get(id);
    if (!pending) return;
    this.pending.delete(id);
    pending.resolve({
      ok: parsed.ok === true,
      ir: typeof parsed.ir === 'string' ? parsed.ir : undefined,
      hex: typeof parsed.hex === 'string' ? parsed.hex : undefined,
      error: typeof parsed.error === 'string' ? parsed.error : undefined,
    });
  }

  private failAll(err: Error): void {
    for (const [, pending] of this.pending) {
      pending.reject(err);
    }
    this.pending.clear();
    if (!this.bannerSeen && this.bannerReject) {
      this.bannerReject(err);
    }
  }

  /**
   * Send a compile request to the daemon and await the response.
   *
   * Both IR and hex are returned in a single round-trip (the daemon does not
   * pay startup twice for the same source). We always pass
   * `disableConstantFolding: true` for conformance parity.
   */
  async compile(sourcePath: string): Promise<JavaCompileResponse> {
    if (this.stopped) {
      return { ok: false, error: 'daemon already stopped' };
    }
    await this.banner;
    const id = this.nextId++;
    const req = {
      id,
      source: sourcePath,
      emitIr: true,
      hex: true,
      disableConstantFolding: true,
    };
    // Per-request timeout. The daemon itself only takes ~0.5–1s per compile,
    // but on a saturated host (9 parallel `tsx` cold-starts at ~150 MB each)
    // the Node event loop can be starved long enough for a 60 s deadline to
    // expire while the response is sitting in the daemon's stdout pipe. Bump
    // the limit to 180 s so we ride out short scheduling stalls instead of
    // turning a flake into a conformance failure.
    const TIMEOUT_MS = 180_000;
    return new Promise<JavaCompileResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) {
          reject(new Error(`Java daemon timeout after ${Math.round(TIMEOUT_MS / 1000)}s on ${sourcePath}`));
        }
      }, TIMEOUT_MS);
      this.pending.set(id, {
        resolve: (resp) => {
          clearTimeout(timer);
          resolve(resp);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });
      try {
        this.proc.stdin.write(JSON.stringify(req) + '\n');
      } catch (err) {
        this.pending.delete(id);
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  /** Stop the daemon process and reject any in-flight requests. */
  async stop(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    try {
      this.proc.stdin.write(JSON.stringify({ id: 0, shutdown: true }) + '\n');
      this.proc.stdin.end();
    } catch {
      // ignore
    }
    return new Promise<void>((resolveExit) => {
      const timer = setTimeout(() => {
        try { this.proc.kill('SIGKILL'); } catch { /* ignore */ }
        resolveExit();
      }, 5_000);
      this.proc.on('close', () => {
        clearTimeout(timer);
        resolveExit();
      });
    });
  }
}
