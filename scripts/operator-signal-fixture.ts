import { writeFile } from "node:fs/promises";
import { registerOperatorLifecycle, withOperatorEnvFile } from "./operator-env";
import { findLoopbackPort, spawnOwnedWorker } from "./operator-process";

const resultPath = process.env.SIGNAL_FIXTURE_RESULT_PATH;
const descendantPath = process.env.SIGNAL_FIXTURE_DESCENDANT_PATH;
const readyPath = process.env.SIGNAL_FIXTURE_READY_PATH;
if (!resultPath || !descendantPath || !readyPath) throw new Error("signal fixture paths are required");

const port = await findLoopbackPort();
await withOperatorEnvFile("n".repeat(43), "jwk-rotate", async (envFile, childEnvironment, signal) => {
  await writeFile(resultPath, envFile, { encoding: "utf8", mode: 0o600 });
  const workerScript = [
    'const { spawn } = require("node:child_process");',
    'const descendant = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });',
    `require("node:fs").writeFileSync(${JSON.stringify(descendantPath)}, String(descendant.pid), { encoding: "utf8", mode: 0o600 });`,
    `console.log(${JSON.stringify(`Ready on http://127.0.0.1:${port}`)});`,
    "setInterval(() => {}, 1000);",
  ].join("\n");
  const worker = await spawnOwnedWorker(["exec", "node", "-e", workerScript], childEnvironment, port);
  const unregister = registerOperatorLifecycle(worker);
  try {
    try {
      await worker.waitForReady(signal);
      await writeFile(readyPath, "ready\n", { encoding: "utf8", mode: 0o600 });
      await new Promise<void>((resolve) => {
        if (signal.aborted) resolve();
        else signal.addEventListener("abort", () => resolve(), { once: true });
      });
    } catch (error) {
      if (!signal.aborted) throw error;
    }
  } finally {
    unregister();
    await worker.stop();
  }
});
