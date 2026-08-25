import { createAnthropic } from "@ai-sdk/anthropic";
import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import type { LanguageModel } from "ai";

/**
 * The model the assistant and the batch agent share.
 *
 * Either provider works, chosen by the key's own prefix so there is no second config
 * variable to keep in sync: `sk-ant-` goes direct to Anthropic, `sk-or-` routes via
 * OpenRouter. Same model either way.
 *
 * Worth knowing when choosing: the assistant sends resource inventory — names, IPs,
 * VPC topology, firewall rules — to whichever provider serves it. Going direct keeps
 * that to one party.
 *
 * This is our key, unrelated to DIGITALOCEAN_TOKEN.
 */

const MODEL = "claude-opus-5";

export function agentApiKey(): string | undefined {
  return process.env.ANTHROPIC_API_KEY?.trim() || process.env.AI_API_KEY?.trim() || undefined;
}

export const MISSING_KEY_MESSAGE =
  "No model API key is set. Add ANTHROPIC_API_KEY or AI_API_KEY to .env and restart. " +
  "The scanner and its rules work without it — only the assistant needs a key.";

/** Which service a key belongs to, by prefix. */
export function providerFor(apiKey: string): "anthropic" | "openrouter" {
  return apiKey.startsWith("sk-or-") ? "openrouter" : "anthropic";
}

export function agentModel(): LanguageModel {
  const apiKey = agentApiKey();
  if (!apiKey) throw new Error(MISSING_KEY_MESSAGE);

  return providerFor(apiKey) === "openrouter"
    ? createOpenRouter({ apiKey })(`anthropic/${MODEL}`)
    : createAnthropic({ apiKey })(MODEL);
}
