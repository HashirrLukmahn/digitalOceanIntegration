import type { DoHttp, QueryParams } from "./http";
import type { DoPaginated } from "./types";

/**
 * Pagination for DigitalOcean list endpoints.
 *
 * DigitalOcean paginates with `links.pages.next`, an absolute URL that is simply
 * absent on the final page. Three things make this worth its own module rather than a
 * loop inlined into each collector:
 *
 *   1. Every collector must follow it, and a collector that silently returns only the
 *      first page produces an inventory that looks complete and is not -- the worst
 *      possible failure for this product.
 *   2. A malformed or self-referential `next` would spin forever. We keep a set of
 *      visited URLs and stop on a repeat.
 *   3. A runaway account still needs a hard bound, so there is a page cap that
 *      *throws* rather than truncating silently. Silent truncation would again mean
 *      an inventory that lies about being complete.
 */

export interface PaginateOptions {
  perPage?: number;
  maxPages?: number;
  query?: QueryParams;
}

export class PaginationLimitError extends Error {
  constructor(path: string, maxPages: number) {
    super(
      `Pagination for ${path} exceeded ${maxPages} pages. Refusing to return a truncated ` +
        `inventory; raise maxPages if this account is genuinely this large.`,
    );
    this.name = "PaginationLimitError";
  }
}

/**
 * Follow every page of a list endpoint and return the concatenated items.
 *
 * `pick` pulls the array out of the response envelope, since DigitalOcean names it
 * differently per resource (`droplets`, `firewalls`, `databases`, ...).
 */
export async function collectPaged<T>(
  http: DoHttp,
  path: string,
  pick: (body: unknown) => T[] | undefined,
  options: PaginateOptions = {},
): Promise<T[]> {
  const perPage = options.perPage ?? 200;
  const maxPages = options.maxPages ?? 100;

  const items: T[] = [];
  const visited = new Set<string>();

  let next: string | undefined = path;
  let isFirstRequest = true;
  let pages = 0;

  while (next) {
    if (visited.has(next)) break; // self-referential or cyclic `next`
    visited.add(next);

    if (pages >= maxPages) throw new PaginationLimitError(path, maxPages);
    pages += 1;

    // Only the first request needs query parameters; DigitalOcean's `next` URL already
    // carries page and per_page, and re-applying ours would fight it.
    const body: unknown = isFirstRequest
      ? await http.get(next, { per_page: perPage, ...options.query })
      : await http.get(next);
    isFirstRequest = false;

    const page = pick(body);
    if (page?.length) items.push(...page);

    next = (body as DoPaginated)?.links?.pages?.next;
  }

  return items;
}
