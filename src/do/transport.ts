import { dataSource } from "../lib/env";
import { FixtureDoHttp } from "./fixtures";
import { LiveDoHttp } from "./http";
import type { DoHttp } from "./http";

/**
 * Chooses the transport, and nothing else.
 *
 * Fixture mode swaps only this: collectors, pagination, normalization and every rule
 * run identically either way, so the token-free demo exercises the real logic.
 */
export function createTransport(): DoHttp {
  return dataSource() === "fixtures" ? new FixtureDoHttp() : new LiveDoHttp();
}
