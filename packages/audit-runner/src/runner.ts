// packages/audit-runner/src/runner.ts
// AuditRunner: executes SecureClaw + custom checks in parallel

import { spawn } from "child_process";
import { readdir } from "fs/promises";
import { join, resolve, dirname } from "path";
import { fileURLToPath } from "url";
import {
  AuditConfig,
  AuditType,
  CustomCheckResult,
  NormalizedFinding,
  RawAuditOutput,
  SecureClawFinding,
  SecureClawOutput,
} from "./types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function getDefaultChecksDir(): string {
  // Resolve from packages/audit-runner/src → ../../scripts/checks
  return resolve(__dirname, "../../../scripts/checks");
}

async function runProcess(
  cmd: string,
  args: string[],
  env: NodeJS.ProcessEnv = process.env,
  verbose = false
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolvePromise) => {
    const proc = spawn(cmd, args, { env });
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    proc.stdout.on("data", (chunk: Buffer) => {
      stdoutChunks.push(chunk);
      if (verbose) process.stdout.write(chunk);
    });
    proc.stderr.on("data", (chunk: Buffer) => {
      stderrChunks.push(chunk);
      if (verbose) process.stderr.write(chunk);
    });

    proc.on("close", (code) => {
      resolvePromise({
        stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
        stderr: Buffer.concat(stderrChunks).toString("utf-8"),
        code: code ?? 0,
      });
    });

    proc.on("error", (err) => {
      stderrChunks.push(Buffer.from(err.message));
      resolvePromise({
        stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
        stderr: Buffer.concat(stderrChunks).toString("utf-8"),
        code: 1,
      });
    });
  });
}

function buildSecureClawArgs(config: AuditConfig): string[] {
  const base = ["secureclaw", "audit", "--output", "json"];

  switch (config.type) {
    case "full":
      base.push("--full");
      break;
    case "supply-chain":
      base.push("--modules", "supply-chain");
      break;
    case "quick":
      base.push("--modules", "permissions,gateway,config");
      break;
    case "custom":
      if (config.modules && config.modules.length > 0) {
        base.push("--modules", config.modules.join(","));
      }
      break;
  }

  return base;
}

function mockSecureClawOutput(type: AuditType): SecureClawOutput {
  // Used in dry-run mode or when SecureClaw is not installed
  return {
    version: "2.1",
    timestamp: new Date().toISOString(),
    hostname: process.env.HOSTNAME ?? "localhost",
    checksRun: type === "quick" ? 12 : 55,
    checksPassed: type === "quick" ? 12 : 50,
    checksFailed: 0,
    findings: [],
    riskScore: 0,
  };
}

export class AuditRunner {
  private readonly bin: string;
  private readonly checksDir: string;
  private readonly verbose: boolean;

  constructor(config: Partial<AuditConfig> = {}) {
    this.bin = config.secureclawBin ?? "openclaw";
    this.checksDir = config.checksDir ?? getDefaultChecksDir();
    this.verbose = config.verbose ?? false;
  }

  async run(config: AuditConfig): Promise<RawAuditOutput> {
    if (this.verbose) {
      console.error(`[AuditRunner] Starting ${config.type} audit (dryRun=${config.dryRun ?? false})`);
    }

    const [upstreamResult, customResults] = await Promise.all([
      this.runSecureClaw(config),
      this.runCustomChecks(config),
    ]);

    return {
      secureclaw: upstreamResult.output,
      customChecks: customResults.results,
      errors: [...upstreamResult.errors, ...customResults.errors],
    };
  }

  private async runSecureClaw(
    config: AuditConfig
  ): Promise<{ output: SecureClawOutput | null; errors: string[] }> {
    if (config.dryRun) {
      if (this.verbose) console.error("[AuditRunner] Dry run — using mock SecureClaw output");
      return { output: mockSecureClawOutput(config.type), errors: [] };
    }

    const args = buildSecureClawArgs(config);
    if (this.verbose) {
      console.error(`[AuditRunner] Running: ${this.bin} ${args.join(" ")}`);
    }

    const result = await runProcess(this.bin, args, process.env, this.verbose);

    if (result.code !== 0) {
      // SecureClaw exits non-zero when findings are found — that's normal
      // Only treat as error if stdout is empty/invalid
      if (!result.stdout.trim()) {
        const errMsg = `SecureClaw exited ${result.code}: ${result.stderr.slice(0, 200)}`;
        return { output: null, errors: [errMsg] };
      }
    }

    try {
      const parsed = JSON.parse(result.stdout) as SecureClawOutput;
      return { output: parsed, errors: [] };
    } catch {
      // Try to extract JSON from mixed output (SecureClaw may print progress lines)
      const lines = result.stdout.split("\n");
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = (lines[i] ?? "").trim();
        if (line.startsWith("{")) {
          try {
            const parsed = JSON.parse(line) as SecureClawOutput;
            return { output: parsed, errors: [] };
          } catch {
            // continue
          }
        }
      }
      return {
        output: null,
        errors: [`Failed to parse SecureClaw output: ${result.stdout.slice(0, 300)}`],
      };
    }
  }

  private async runCustomChecks(
    config: AuditConfig
  ): Promise<{ results: CustomCheckResult[]; errors: string[] }> {
    const results: CustomCheckResult[] = [];
    const errors: string[] = [];

    let scripts: string[];
    try {
      const files = await readdir(this.checksDir);
      scripts = files.filter((f) => f.endsWith(".sh")).sort();
    } catch (err) {
      const msg = `Cannot read checks directory ${this.checksDir}: ${String(err)}`;
      errors.push(msg);
      return { results, errors };
    }

    // Filter scripts for supply-chain type
    const filteredScripts =
      config.type === "supply-chain"
        ? scripts.filter((s) => s.includes("supply-chain") || s.includes("git"))
        : scripts;

    await Promise.all(
      filteredScripts.map(async (script) => {
        const scriptPath = join(this.checksDir, script);
        if (config.dryRun) {
          if (this.verbose) console.error(`[AuditRunner] Dry run — skipping ${script}`);
          return;
        }

        if (this.verbose) console.error(`[AuditRunner] Running check: ${script}`);

        const { stdout, stderr, code } = await runProcess(
          "bash",
          [scriptPath],
          process.env,
          false
        );

        if (code !== 0) {
          errors.push(`Check script ${script} exited with code ${code}: ${stderr.slice(0, 200)}`);
          return;
        }

        const jsonOutput = stdout.trim();
        if (!jsonOutput) {
          errors.push(`Check script ${script} produced no output`);
          return;
        }

        try {
          const parsed = JSON.parse(jsonOutput) as CustomCheckResult;
          results.push(parsed);
        } catch {
          errors.push(
            `Check script ${script} produced invalid JSON: ${jsonOutput.slice(0, 200)}`
          );
        }
      })
    );

    return { results, errors };
  }

  async getSecureClawVersion(): Promise<string> {
    const { stdout, code } = await runProcess(this.bin, ["secureclaw", "--version"]);
    if (code !== 0 || !stdout.trim()) return "unknown";
    return stdout.trim().split("\n")[0] ?? "unknown";
  }

  async isSecureClawAvailable(): Promise<boolean> {
    const { code } = await runProcess(this.bin, ["secureclaw", "--help"]);
    return code === 0;
  }
}

// Re-export for convenience
export type { SecureClawFinding, SecureClawOutput, CustomCheckResult, RawAuditOutput };
