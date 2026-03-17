import { describe, expect, test } from "bun:test";
import { mapToLocations, parseNDJSON } from "./trufflehog";

describe("parseNDJSON", () => {
  test("parses single result", () => {
    const output = JSON.stringify({
      DetectorName: "AWS",
      Raw: "AKIAIOSFODNN7EXAMPLE",
      Redacted: "AKIA***",
    });

    const results = parseNDJSON(output);
    expect(results).toHaveLength(1);
    expect(results[0].DetectorName).toBe("AWS");
    expect(results[0].Raw).toBe("AKIAIOSFODNN7EXAMPLE");
    expect(results[0].Redacted).toBe("AKIA***");
  });

  test("parses multiple results (NDJSON)", () => {
    const lines = [
      JSON.stringify({ DetectorName: "AWS", Raw: "AKIAIOSFODNN7EXAMPLE" }),
      JSON.stringify({ DetectorName: "Slack", Raw: "xoxb-fake-token-here" }),
    ].join("\n");

    const results = parseNDJSON(lines);
    expect(results).toHaveLength(2);
    expect(results[0].DetectorName).toBe("AWS");
    expect(results[1].DetectorName).toBe("Slack");
  });

  test("skips empty lines", () => {
    const output = `${JSON.stringify({ DetectorName: "AWS", Raw: "key123" })}\n\n\n`;
    const results = parseNDJSON(output);
    expect(results).toHaveLength(1);
  });

  test("skips malformed JSON lines", () => {
    const output = `not json\n${JSON.stringify({ DetectorName: "AWS", Raw: "key123" })}\n{bad`;
    const results = parseNDJSON(output);
    expect(results).toHaveLength(1);
    expect(results[0].DetectorName).toBe("AWS");
  });

  test("skips lines missing DetectorName", () => {
    const output = JSON.stringify({ Raw: "some-value" });
    const results = parseNDJSON(output);
    expect(results).toHaveLength(0);
  });

  test("skips lines missing both Raw and RawV2", () => {
    const output = JSON.stringify({ DetectorName: "AWS" });
    const results = parseNDJSON(output);
    expect(results).toHaveLength(0);
  });

  test("accepts RawV2 without Raw", () => {
    const output = JSON.stringify({ DetectorName: "AWS", RawV2: "secret-v2" });
    const results = parseNDJSON(output);
    expect(results).toHaveLength(1);
    expect(results[0].RawV2).toBe("secret-v2");
  });

  test("returns empty for empty input", () => {
    expect(parseNDJSON("")).toHaveLength(0);
    expect(parseNDJSON("  \n  ")).toHaveLength(0);
  });
});

describe("mapToLocations", () => {
  test("maps single result to location", () => {
    const text = "My AWS key is AKIAIOSFODNN7EXAMPLE in this text";
    const results = [{ DetectorName: "AWS", Raw: "AKIAIOSFODNN7EXAMPLE" }];

    const locations = mapToLocations(text, results);
    expect(locations).toHaveLength(1);
    expect(locations[0].type).toBe("TRUFFLEHOG_AWS");
    expect(locations[0].start).toBe(14);
    expect(locations[0].end).toBe(34);
    expect(text.slice(locations[0].start, locations[0].end)).toBe("AKIAIOSFODNN7EXAMPLE");
  });

  test("prefers RawV2 over Raw for matching", () => {
    const text = "token: xoxb-full-secret-token-value";
    const results = [
      {
        DetectorName: "Slack",
        Raw: "xoxb-full",
        RawV2: "xoxb-full-secret-token-value",
      },
    ];

    const locations = mapToLocations(text, results);
    expect(locations).toHaveLength(1);
    expect(text.slice(locations[0].start, locations[0].end)).toBe(
      "xoxb-full-secret-token-value",
    );
  });

  test("finds multiple occurrences of same value", () => {
    const text = "key: SECRET123 and again SECRET123";
    const results = [{ DetectorName: "Generic", Raw: "SECRET123" }];

    const locations = mapToLocations(text, results);
    expect(locations).toHaveLength(2);
    expect(locations[0].start).toBe(5);
    expect(locations[1].start).toBe(25);
  });

  test("maps multiple different results", () => {
    const text = "AWS: AKIAEXAMPLE Slack: xoxb-token";
    const results = [
      { DetectorName: "AWS", Raw: "AKIAEXAMPLE" },
      { DetectorName: "Slack", Raw: "xoxb-token" },
    ];

    const locations = mapToLocations(text, results);
    expect(locations).toHaveLength(2);
    expect(locations[0].type).toBe("TRUFFLEHOG_AWS");
    expect(locations[1].type).toBe("TRUFFLEHOG_Slack");
  });

  test("returns empty when raw value not found in text", () => {
    const text = "This text contains no secrets";
    const results = [{ DetectorName: "AWS", Raw: "AKIAIOSFODNN7EXAMPLE" }];

    const locations = mapToLocations(text, results);
    expect(locations).toHaveLength(0);
  });

  test("returns empty for empty results", () => {
    const locations = mapToLocations("some text", []);
    expect(locations).toHaveLength(0);
  });

  test("skips results with no raw value", () => {
    const text = "some text";
    const results = [{ DetectorName: "AWS", Raw: "" }];

    const locations = mapToLocations(text, results);
    expect(locations).toHaveLength(0);
  });

  test("prefixes entity type with TRUFFLEHOG_", () => {
    const text = "secret: my-api-key-value";
    const results = [{ DetectorName: "CustomDetector", Raw: "my-api-key-value" }];

    const locations = mapToLocations(text, results);
    expect(locations).toHaveLength(1);
    expect(locations[0].type).toBe("TRUFFLEHOG_CustomDetector");
  });
});
