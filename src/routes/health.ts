import { Hono } from "hono";
import { getConfig } from "../config";
import { checkLocalHealth } from "../providers/local";
import { getTruffleHogDetector } from "../secrets/trufflehog";
import { healthCheck as checkPresidio } from "../services/pii";

export const healthRoutes = new Hono();

healthRoutes.get("/health", async (c) => {
  const config = getConfig();
  const piiEnabled = config.pii_detection.enabled;
  const truffleHogEnabled = config.secrets_detection.trufflehog?.enabled ?? false;

  const [presidioHealth, localHealth, truffleHogHealth] = await Promise.all([
    piiEnabled ? checkPresidio() : Promise.resolve(true),
    config.mode === "route" && config.local
      ? checkLocalHealth(config.local)
      : Promise.resolve(true),
    truffleHogEnabled
      ? getTruffleHogDetector(config.secrets_detection.trufflehog).healthCheck()
      : Promise.resolve(true),
  ]);

  const isHealthy = piiEnabled ? presidioHealth : true;

  const services: Record<string, string> = {};
  if (piiEnabled) {
    services.presidio = presidioHealth ? "up" : "down";
  }

  if (config.mode === "route" && config.local) {
    services.local_llm = localHealth ? "up" : "down";
  }

  if (truffleHogEnabled) {
    services.trufflehog = truffleHogHealth ? "up" : "down";
  }

  return c.json(
    {
      status: isHealthy ? "healthy" : "degraded",
      services,
      timestamp: new Date().toISOString(),
    },
    isHealthy ? 200 : 503,
  );
});
