/**
 * TruffleHog subprocess client for comprehensive secrets detection
 *
 * Spawns `trufflehog stdin --no-verification --json` and pipes text via stdin.
 * Parses NDJSON output and maps results to SecretLocation[] by finding
 * raw values in the original text.
 */

import { getConfig } from "../config";
import { HEALTH_CHECK_TIMEOUT_MS } from "../constants/timeouts";
import type { SecretLocation, SecretsDetectionResult, SecretsMatch } from "./patterns/types";

export interface TruffleHogResult {
  DetectorName: string;
  Raw: string;
  RawV2?: string;
  Redacted?: string;
}

/**
 * Parse TruffleHog NDJSON output into structured results
 */
export function parseNDJSON(output: string): TruffleHogResult[] {
  const results: TruffleHogResult[] = [];

  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    try {
      const parsed = JSON.parse(trimmed);
      if (parsed.DetectorName && (parsed.Raw || parsed.RawV2)) {
        results.push({
          DetectorName: parsed.DetectorName,
          Raw: parsed.Raw || "",
          RawV2: parsed.RawV2,
          Redacted: parsed.Redacted,
        });
      }
    } catch {
      // Skip malformed lines
    }
  }

  return results;
}

/**
 * Map TruffleHog results to SecretLocation[] by finding raw values in text
 */
export function mapToLocations(text: string, results: TruffleHogResult[]): SecretLocation[] {
  const locations: SecretLocation[] = [];

  for (const result of results) {
    // Prefer RawV2 (more specific/processed form) over Raw when available.
    // Note: if the chosen value appears multiple times in text, indexOf may produce
    // spurious matches — an inherent limitation of TruffleHog's offset-free output.
    const rawValue = result.RawV2 || result.Raw;
    if (!rawValue) continue;

    const entityType = `TRUFFLEHOG_${result.DetectorName}` as const;

    // Find all occurrences of the raw value in text
    let searchFrom = 0;
    while (searchFrom < text.length) {
      const idx = text.indexOf(rawValue, searchFrom);
      if (idx === -1) break;

      locations.push({
        start: idx,
        end: idx + rawValue.length,
        type: entityType,
      });

      searchFrom = idx + rawValue.length;
    }
  }

  return locations;
}

export class TruffleHogDetector {
  private binaryPath: string;
  private timeoutMs: number;

  constructor() {
    const config = getConfig();
    this.binaryPath = config.secrets_detection.trufflehog.binary_path;
    this.timeoutMs = config.secrets_detection.trufflehog.timeout * 1000;
  }

  /**
   * Detect secrets in text using TruffleHog subprocess
   */
  async detect(text: string): Promise<SecretsDetectionResult> {
    if (!text) {
      return { detected: false, matches: [] };
    }

    try {
      const output = await this.runSubprocess(text);
      const results = parseNDJSON(output);

      if (results.length === 0) {
        return { detected: false, matches: [] };
      }

      const locations = mapToLocations(text, results);

      // Build matches from locations
      const matchCounts = new Map<string, number>();
      for (const loc of locations) {
        matchCounts.set(loc.type, (matchCounts.get(loc.type) || 0) + 1);
      }

      const matches: SecretsMatch[] = [];
      for (const [type, count] of matchCounts) {
        matches.push({ type: type as SecretLocation["type"], count });
      }

      // Sort locations by start position descending (for safe replacement)
      locations.sort((a, b) => b.start - a.start);

      return {
        detected: locations.length > 0,
        matches,
        locations: locations.length > 0 ? locations : undefined,
      };
    } catch (error) {
      console.warn(
        `[TruffleHog] Detection failed (binary: ${this.binaryPath}): ${error instanceof Error ? error.message : error}`,
      );
      return { detected: false, matches: [] };
    }
  }

  /**
   * Check if TruffleHog binary is available
   */
  async healthCheck(): Promise<boolean> {
    try {
      const proc = Bun.spawn([this.binaryPath, "--version"], {
        stdout: "pipe",
        stderr: "pipe",
      });

      // Manual setTimeout used because Bun.spawn does not support AbortSignal
      const timeout = setTimeout(() => proc.kill(), HEALTH_CHECK_TIMEOUT_MS);
      const exitCode = await proc.exited;
      clearTimeout(timeout);

      return exitCode === 0;
    } catch {
      return false;
    }
  }

  private async runSubprocess(text: string): Promise<string> {
    const proc = Bun.spawn([this.binaryPath, "stdin", "--no-verification", "--json"], {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    });

    // Write text to stdin and close
    await proc.stdin.write(text);
    proc.stdin.end();

    // Manual setTimeout used because Bun.spawn does not support AbortSignal
    const timeout = setTimeout(() => {
      proc.kill();
    }, this.timeoutMs);

    try {
      // Drain stdout and stderr concurrently with proc.exited to prevent stderr
      // pipe buffer from filling and deadlocking the subprocess
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ]);

      clearTimeout(timeout);

      // TruffleHog exits with 0 on success (regardless of findings)
      if (exitCode !== 0) {
        throw new Error(`TruffleHog exited with code ${exitCode}: ${stderr.slice(0, 200)}`);
      }

      return stdout;
    } catch (error) {
      clearTimeout(timeout);
      throw error;
    }
  }
}

let detectorInstance: TruffleHogDetector | null = null;

export function getTruffleHogDetector(): TruffleHogDetector {
  if (!detectorInstance) {
    detectorInstance = new TruffleHogDetector();
  }
  return detectorInstance;
}
