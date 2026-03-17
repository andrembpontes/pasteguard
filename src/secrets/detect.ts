import type { SecretsDetectionConfig } from "../config";
import type { RequestExtractor, TextSpan } from "../masking/types";
import { patternDetectors } from "./patterns";
import type {
  MessageSecretsResult,
  SecretLocation,
  SecretsDetectionResult,
  SecretsMatch,
} from "./patterns/types";
import { getTruffleHogDetector } from "./trufflehog";

export type {
  MessageSecretsResult,
  SecretEntityType,
  SecretLocation,
  SecretsDetectionResult,
  SecretsMatch,
} from "./patterns/types";

/**
 * Detects secret material (e.g. private keys, API keys, tokens) in text
 * using built-in pattern detectors.
 *
 * Uses the pattern registry to scan for various secret types:
 * - Private keys: OpenSSH, PEM (RSA, generic, encrypted)
 * - API keys: OpenAI, AWS, GitHub
 * - Tokens: JWT, Bearer
 * - Environment variables: Passwords, secrets, connection strings
 *
 * Respects max_scan_chars limit for performance.
 */
export function detectSecretsBuiltin(
  text: string,
  config: SecretsDetectionConfig,
): SecretsDetectionResult {
  if (!config.enabled) {
    return { detected: false, matches: [] };
  }

  // Apply max_scan_chars limit
  const textToScan = config.max_scan_chars > 0 ? text.slice(0, config.max_scan_chars) : text;

  // Track which entities to detect based on config
  const enabledTypes = new Set<string>(config.entities);

  // Aggregate results from all pattern detectors
  const allMatches: SecretsMatch[] = [];
  const allLocations: SecretLocation[] = [];

  for (const detector of patternDetectors) {
    // Skip detectors that don't handle any enabled types
    const hasEnabledPattern = detector.patterns.some((p) => enabledTypes.has(p));
    if (!hasEnabledPattern) continue;

    const result = detector.detect(textToScan, enabledTypes);
    allMatches.push(...result.matches);
    if (result.locations) {
      allLocations.push(...result.locations);
    }
  }

  // Sort locations by start position (descending) for safe replacement
  allLocations.sort((a, b) => b.start - a.start);

  return {
    detected: allMatches.length > 0,
    matches: allMatches,
    locations: allLocations.length > 0 ? allLocations : undefined,
  };
}

/**
 * Detects secrets in text using built-in detectors and optionally TruffleHog.
 * Returns merged, deduplicated results.
 */
export async function detectSecrets(
  text: string,
  config: SecretsDetectionConfig,
): Promise<SecretsDetectionResult> {
  if (!config.enabled) {
    return { detected: false, matches: [] };
  }

  // Slice once here; pass pre-sliced text to both detectors
  const textToScan = config.max_scan_chars > 0 ? text.slice(0, config.max_scan_chars) : text;
  const noLimitConfig = { ...config, max_scan_chars: 0 };

  // If TruffleHog is not enabled, return built-in results only
  if (!config.trufflehog.enabled) {
    return detectSecretsBuiltin(textToScan, noLimitConfig);
  }

  // Run built-in and TruffleHog detection in parallel
  const [builtinResult, truffleHogResult] = await Promise.all([
    Promise.resolve(detectSecretsBuiltin(textToScan, noLimitConfig)),
    getTruffleHogDetector().detect(textToScan),
  ]);

  // Merge results, deduplicating overlapping locations
  return mergeResults(builtinResult, truffleHogResult);
}

/**
 * Merge built-in and TruffleHog results, deduplicating overlapping locations.
 * Built-in results take priority at overlapping positions (more specific type names).
 */
export function mergeResults(
  builtin: SecretsDetectionResult,
  trufflehog: SecretsDetectionResult,
): SecretsDetectionResult {
  if (!trufflehog.detected) return builtin;
  if (!builtin.detected) return trufflehog;

  const builtinLocations = builtin.locations || [];
  const trufflehogLocations = trufflehog.locations || [];

  // Filter out TruffleHog locations that overlap with built-in locations
  const filteredTHLocations = trufflehogLocations.filter((thLoc) => {
    return !builtinLocations.some((bLoc) => thLoc.start < bLoc.end && thLoc.end > bLoc.start);
  });

  const allLocations = [...builtinLocations, ...filteredTHLocations];
  allLocations.sort((a, b) => b.start - a.start);

  // Rebuild matches from merged locations
  const matchCounts = new Map<string, number>();
  for (const loc of allLocations) {
    matchCounts.set(loc.type, (matchCounts.get(loc.type) || 0) + 1);
  }

  // Preserve builtin matches for types that have no corresponding location
  // (e.g. detectors that report counts without offsets)
  for (const m of builtin.matches) {
    if (!allLocations.some((l) => l.type === m.type)) {
      matchCounts.set(m.type, (matchCounts.get(m.type) || 0) + m.count);
    }
  }

  const matches: SecretsMatch[] = [];
  for (const [type, count] of matchCounts) {
    matches.push({ type: type as SecretLocation["type"], count });
  }

  return {
    detected: allLocations.length > 0,
    matches,
    locations: allLocations.length > 0 ? allLocations : undefined,
  };
}

/**
 * Detects secrets in a request using an extractor
 */
export async function detectSecretsInRequest<TRequest, TResponse>(
  request: TRequest,
  config: SecretsDetectionConfig,
  extractor: RequestExtractor<TRequest, TResponse>,
): Promise<MessageSecretsResult> {
  const spans = extractor.extractTexts(request);
  return detectSecretsInSpans(spans, config);
}

/**
 * Detects secrets in text spans (low-level)
 */
export async function detectSecretsInSpans(
  spans: TextSpan[],
  config: SecretsDetectionConfig,
): Promise<MessageSecretsResult> {
  if (!config.enabled) {
    return {
      detected: false,
      matches: [],
      spanLocations: spans.map(() => []),
    };
  }

  // Detect secrets in each span
  const scanRoles = config.scan_roles ? new Set(config.scan_roles) : null;

  const matchCounts = new Map<string, number>();
  const spanLocations: SecretLocation[][] = await Promise.all(
    spans.map(async (span) => {
      if (scanRoles && span.role && !scanRoles.has(span.role)) {
        return [];
      }
      const result = await detectSecrets(span.text, config);
      for (const match of result.matches) {
        matchCounts.set(match.type, (matchCounts.get(match.type) || 0) + match.count);
      }
      return result.locations || [];
    }),
  );

  // Build matches array
  const allMatches: SecretsMatch[] = [];
  for (const [type, count] of matchCounts) {
    allMatches.push({ type: type as SecretLocation["type"], count });
  }

  const hasLocations = spanLocations.some((locs) => locs.length > 0);

  return {
    detected: hasLocations,
    matches: allMatches,
    spanLocations,
  };
}
