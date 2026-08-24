import { scrub, scrubString } from "./redact";

/**
 * A very small logger. Every message and every context object is scrubbed before it
 * is written, so a caller cannot leak a token by forgetting to think about it.
 *
 * Deliberately dependency-free: the redaction guarantee is the point, and a logging
 * library would only add a second place for unscrubbed output to escape.
 */

type Level = "debug" | "info" | "warn" | "error";

const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

function threshold(): number {
  const configured = (process.env.LOG_LEVEL ?? "info") as Level;
  return ORDER[configured] ?? ORDER.info;
}

function emit(level: Level, message: string, context?: Record<string, unknown>): void {
  if (ORDER[level] < threshold()) return;
  const line = {
    level,
    time: new Date().toISOString(),
    msg: scrubString(message),
    ...(context ? (scrub(context) as Record<string, unknown>) : {}),
  };
  const sink = level === "error" || level === "warn" ? console.error : console.log;
  sink(JSON.stringify(line));
}

export const logger = {
  debug: (message: string, context?: Record<string, unknown>) => emit("debug", message, context),
  info: (message: string, context?: Record<string, unknown>) => emit("info", message, context),
  warn: (message: string, context?: Record<string, unknown>) => emit("warn", message, context),
  error: (message: string, context?: Record<string, unknown>) => emit("error", message, context),
};
