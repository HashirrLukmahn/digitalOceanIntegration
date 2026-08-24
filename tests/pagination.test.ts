import { describe, expect, it } from "vitest";
import type { DoHttp, QueryParams } from "../src/do/http";
import { PaginationLimitError, collectPaged } from "../src/do/paginate";

/**
 * A collector that returns only the first page produces an inventory that looks
 * complete and is not. These tests pin the follow behaviour, the termination
 * conditions, and the refusal to truncate silently.
 */

interface RecordedCall {
  url: string;
  query?: QueryParams;
}

/** Serves canned pages and records exactly what was requested. */
function fakeHttp(pages: Record<string, unknown>): DoHttp & { calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  return {
    calls,
    async get<T>(url: string, query?: QueryParams): Promise<T> {
      calls.push({ url, query });
      if (!(url in pages)) throw new Error(`unexpected request: ${url}`);
      return pages[url] as T;
    },
  };
}

const droplets = (body: unknown) => (body as { droplets?: unknown[] }).droplets as never[];

describe("collectPaged", () => {
  it("returns a single page when there is no next link", async () => {
    const http = fakeHttp({
      "/v2/droplets": { droplets: [{ id: 1 }, { id: 2 }], links: { pages: {} } },
    });

    const items = await collectPaged(http, "/v2/droplets", droplets);

    expect(items).toHaveLength(2);
    expect(http.calls).toHaveLength(1);
  });

  it("follows next across multiple pages and concatenates in order", async () => {
    const http = fakeHttp({
      "/v2/droplets": {
        droplets: [{ id: 1 }],
        links: { pages: { next: "https://api.digitalocean.com/v2/droplets?page=2&per_page=200" } },
      },
      "https://api.digitalocean.com/v2/droplets?page=2&per_page=200": {
        droplets: [{ id: 2 }],
        links: { pages: { next: "https://api.digitalocean.com/v2/droplets?page=3&per_page=200" } },
      },
      "https://api.digitalocean.com/v2/droplets?page=3&per_page=200": {
        droplets: [{ id: 3 }],
        links: { pages: { first: "https://api.digitalocean.com/v2/droplets?page=1" } },
      },
    });

    const items = await collectPaged<{ id: number }>(http, "/v2/droplets", droplets);

    expect(items.map((d) => d.id)).toEqual([1, 2, 3]);
    expect(http.calls).toHaveLength(3);
  });

  it("applies per_page only to the first request", async () => {
    const http = fakeHttp({
      "/v2/droplets": {
        droplets: [{ id: 1 }],
        links: { pages: { next: "https://api.digitalocean.com/v2/droplets?page=2&per_page=200" } },
      },
      "https://api.digitalocean.com/v2/droplets?page=2&per_page=200": { droplets: [{ id: 2 }] },
    });

    await collectPaged(http, "/v2/droplets", droplets, { perPage: 200 });

    // The `next` URL already encodes page and per_page; re-applying ours would fight it.
    expect(http.calls[0]!.query).toMatchObject({ per_page: 200 });
    expect(http.calls[1]!.query).toBeUndefined();
  });

  it("passes extra query parameters through on the first request", async () => {
    const http = fakeHttp({ "/v2/droplets": { droplets: [] } });

    await collectPaged(http, "/v2/droplets", droplets, { query: { tag_name: "prod" } });

    expect(http.calls[0]!.query).toMatchObject({ tag_name: "prod", per_page: 200 });
  });

  it("stops when next points back at a page already visited", async () => {
    const http = fakeHttp({
      "/v2/droplets": {
        droplets: [{ id: 1 }],
        links: { pages: { next: "https://api.digitalocean.com/v2/droplets?page=2" } },
      },
      // Page 2 points at itself -- without a cycle guard this never terminates.
      "https://api.digitalocean.com/v2/droplets?page=2": {
        droplets: [{ id: 2 }],
        links: { pages: { next: "https://api.digitalocean.com/v2/droplets?page=2" } },
      },
    });

    const items = await collectPaged<{ id: number }>(http, "/v2/droplets", droplets);

    expect(items.map((d) => d.id)).toEqual([1, 2]);
    expect(http.calls).toHaveLength(2);
  });

  it("throws rather than silently truncating when the page cap is reached", async () => {
    // Every page links to a fresh next, so only the cap can stop it.
    const http: DoHttp = {
      async get<T>(url: string): Promise<T> {
        const page = Number(new URL(url, "https://api.digitalocean.com").searchParams.get("page") ?? 1);
        return {
          droplets: [{ id: page }],
          links: { pages: { next: `https://api.digitalocean.com/v2/droplets?page=${page + 1}` } },
        } as T;
      },
    };

    await expect(collectPaged(http, "/v2/droplets", droplets, { maxPages: 5 })).rejects.toThrow(
      PaginationLimitError,
    );
  });

  it("tolerates a page whose collection key is missing", async () => {
    const http = fakeHttp({
      "/v2/droplets": {
        links: { pages: { next: "https://api.digitalocean.com/v2/droplets?page=2" } },
      },
      "https://api.digitalocean.com/v2/droplets?page=2": { droplets: [{ id: 7 }] },
    });

    const items = await collectPaged<{ id: number }>(http, "/v2/droplets", droplets);

    expect(items.map((d) => d.id)).toEqual([7]);
  });

  it("returns an empty array for an empty collection", async () => {
    const http = fakeHttp({ "/v2/droplets": { droplets: [], links: { pages: {} } } });
    expect(await collectPaged(http, "/v2/droplets", droplets)).toEqual([]);
  });
});
