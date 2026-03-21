import { spawn, ChildProcess } from "child_process";
import * as net from "net";
import * as path from "path";
import { app } from "electron";

const BASE_PORT = 17432;
const HEALTH_PATH = "/api/health";

function findFreePort(start: number): Promise<number> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(start, () => {
      const port = (server.address() as net.AddressInfo).port;
      server.close(() => resolve(port));
    });
    server.on("error", () => resolve(findFreePort(start + 1)));
  });
}

export class BackendManager {
  private process: ChildProcess | null = null;
  private port: number = 0;
  private baseUrl: string = "";

  async start(): Promise<string> {
    this.port = await findFreePort(BASE_PORT);
    const dataDir = app.getPath("userData");
    const enginePath = path.join(__dirname, "../../../engine");
    const isDev = process.env.NODE_ENV === "development";

    const args = [
      "-m", "uvicorn",
      "medusa.engine.main:app",
      "--host", "127.0.0.1",
      "--port", String(this.port),
    ];
    const projectRoot = path.resolve(__dirname, "../../../..");
    const env = {
      ...process.env,
      MEDUSA_PORT: String(this.port),
      MEDUSA_DATA_DIR: dataDir,
      PYTHONPATH: projectRoot,
    };

    this.process = spawn("python", args, {
      cwd: projectRoot,
      env,
      stdio: "pipe",
    });

    this.process.stderr?.on("data", (d) => console.error("[engine]", d.toString()));
    this.process.on("exit", (code) => {
      if (code !== 0) console.error("[engine] exited", code);
    });

    this.baseUrl = `http://127.0.0.1:${this.port}`;
    for (let i = 0; i < 75; i++) {
      try {
        const r = await fetch(`${this.baseUrl}${HEALTH_PATH}`);
        if (r.ok) return this.baseUrl;
      } catch {}
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error("Engine failed to start");
  }

  async stop(): Promise<void> {
    if (!this.process) return;
    try {
      await fetch(`${this.baseUrl}/api/health`, { method: "GET" });
    } catch {}
    this.process.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 3000));
    if (this.process.exitCode === null) this.process.kill("SIGKILL");
    this.process = null;
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }
}
