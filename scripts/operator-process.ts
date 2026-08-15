import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";

export async function findLoopbackPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, () => resolve());
  });
  const address = server.address();
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  if (!address || typeof address === "string") throw new Error("loopback port allocation failed");
  return address.port;
}

export type OwnedWorker = {
  child: ChildProcess;
  port: number;
  waitForReady: (signal?: AbortSignal) => Promise<void>;
  stop: () => Promise<void>;
};

const GROUP_TERM_GRACE_MS = 5_000;
const GROUP_DISAPPEAR_TIMEOUT_MS = 5_000;

function errorCode(error: unknown): string | undefined {
  return error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
}

async function waitForProcessGroupGone(processId: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (true) {
    try {
      process.kill(-processId, 0);
    } catch (error) {
      if (errorCode(error) === "ESRCH") return;
      if (errorCode(error) !== "EPERM") throw error;
    }
    if (Date.now() >= deadline) throw new Error("operator worker process group did not exit");
    await new Promise<void>((resolve) => setTimeout(resolve, 50));
  }
}

function signalProcessGroup(processId: number, signal: NodeJS.Signals): void {
  try {
    process.kill(-processId, signal);
  } catch (error) {
    if (errorCode(error) !== "ESRCH") throw error;
  }
}

export async function spawnOwnedWorker(
  arguments_: string[],
  environment: NodeJS.ProcessEnv,
  port: number,
): Promise<OwnedWorker> {
  const child = spawn("pnpm", arguments_, {
    env: environment,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  let resolveReady: (() => void) | undefined;
  let rejectReady: ((error: Error) => void) | undefined;
  let stopPromise: Promise<void> | undefined;
  const ready = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  const onOutput = (chunk: Buffer): void => {
    output = `${output}${chunk.toString()}`.slice(-16_384);
    if (new RegExp(`Ready on https?://127\\.0\\.0\\.1:${port}(?:/|\\s|$)`, "u").test(output)) {
      resolveReady?.();
      resolveReady = undefined;
      rejectReady = undefined;
    }
  };
  child.stdout?.on("data", onOutput);
  child.stderr?.on("data", onOutput);
  child.once("error", (error) => rejectReady?.(error));
  child.once("exit", (code, signal) => {
    if (rejectReady) rejectReady(new Error(`operator worker exited before ready (${code ?? signal ?? "unknown"})`));
  });
  const waitForReady = async (signal?: AbortSignal): Promise<void> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    try {
      await Promise.race([
        ready,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error("operator worker did not become ready")), 30_000);
        }),
        ...(signal
          ? [
              new Promise<never>((_, reject) => {
                onAbort = () => reject(new Error("operator worker readiness was interrupted"));
                if (signal.aborted) onAbort();
                else signal.addEventListener("abort", onAbort, { once: true });
              }),
            ]
          : []),
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (signal && onAbort) signal.removeEventListener("abort", onAbort);
    }
  };
  const stop = (): Promise<void> => {
    if (stopPromise) return stopPromise;
    stopPromise = (async () => {
      const processId = child.pid;
      if (!processId) return;
      try {
        signalProcessGroup(processId, "SIGTERM");
        try {
          await waitForProcessGroupGone(processId, GROUP_TERM_GRACE_MS);
        } catch (error) {
          if (!(error instanceof Error) || error.message !== "operator worker process group did not exit") throw error;
          signalProcessGroup(processId, "SIGKILL");
          await waitForProcessGroupGone(processId, GROUP_DISAPPEAR_TIMEOUT_MS);
        }
      } finally {
        child.stdout?.removeListener("data", onOutput);
        child.stderr?.removeListener("data", onOutput);
        child.stdout?.destroy();
        child.stderr?.destroy();
      }
    })();
    return stopPromise;
  };
  return { child, port, waitForReady, stop };
}
