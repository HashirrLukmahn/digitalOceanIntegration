import { requireConnection } from "../../src/connection/state";
import Link from "next/link";
import { Empty, Exposed, Sensitivity, Urn } from "../components";
import { label } from "../labels";
import {
  counts,
  getAccount,
  inventoryFacets,
  listResources,
} from "../../src/data/queries";

export const dynamic = "force-dynamic";

export default async function InventoryPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  requireConnection();

  const params = await searchParams;
  const account = getAccount();

  if (!account) {
    return (
      <Empty
        title="Nothing has been synced yet"
        hint="Connect a DigitalOcean account and run a sync to build the inventory."
      />
    );
  }

  const facets = inventoryFacets(account.id);
  const summary = counts(account.id);
  const resources = listResources(account.id, {
    type: params.type,
    region: params.region,
    sensitivity: params.sensitivity,
    exposure: params.exposure as "exposed" | "not_exposed" | undefined,
    q: params.q,
  });

  const filtering = Boolean(
    params.type || params.region || params.sensitivity || params.exposure || params.q,
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Inventory</h1>
          <p className="mt-1 text-sm text-muted">
            {summary.resources} resources from the last sync. Internet-facing resources are listed
            first.
          </p>
        </div>
        {/* The frozen v1 JSON export -- the same file the evaluator integration and the agents
            consume. Served by /api/export with a download filename. */}
        <a href="/api/export" className="btn-quiet shrink-0" download>
          Export JSON
        </a>
      </div>

      <form className="panel flex flex-wrap items-end gap-3 px-4 py-3" action="/inventory">
        <div className="flex flex-col gap-1">
          <label htmlFor="q" className="eyebrow">
            Search
          </label>
          <input
            id="q"
            name="q"
            defaultValue={params.q ?? ""}
            placeholder="Name, URN, or region"
            className="field w-56"
          />
        </div>

        <div className="flex flex-col gap-1">
          <label htmlFor="type" className="eyebrow">
            Type
          </label>
          <select id="type" name="type" defaultValue={params.type ?? ""} className="field">
            <option value="">All</option>
            {facets.types.map((type) => (
              <option key={type} value={type}>
                {label(type)}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1">
          <label htmlFor="region" className="eyebrow">
            Region
          </label>
          <select id="region" name="region" defaultValue={params.region ?? ""} className="field">
            <option value="">All</option>
            {facets.regions.map((region) => (
              <option key={region} value={region}>
                {region}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1">
          <label htmlFor="sensitivity" className="eyebrow">
            Sensitivity
          </label>
          <select
            id="sensitivity"
            name="sensitivity"
            defaultValue={params.sensitivity ?? ""}
            className="field"
          >
            <option value="">All</option>
            {facets.sensitivities.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1">
          <label htmlFor="exposure" className="eyebrow">
            Exposure
          </label>
          <select id="exposure" name="exposure" defaultValue={params.exposure ?? ""} className="field">
            <option value="">All</option>
            <option value="exposed">Internet-facing</option>
            <option value="not_exposed">Not reachable</option>
          </select>
        </div>

        <button type="submit" className="btn-quiet">
          Apply
        </button>
        {filtering && (
          <Link href="/inventory" className="text-[0.8rem] text-accent hover:underline">
            Clear
          </Link>
        )}
      </form>

      {resources.length === 0 ? (
        <Empty
          title="No resources match this filter"
          hint="Clear the filters to see the whole inventory."
        />
      ) : (
        <div className="panel overflow-x-auto">
          <table className="w-full min-w-[64rem] border-collapse text-sm">
            <thead className="table-head">
              <tr>
                <th>Identifier</th>
                <th>Name</th>
                <th>Type</th>
                <th>Region</th>
                <th>State</th>
                <th>Sensitivity</th>
                <th>Exposure</th>
              </tr>
            </thead>
            <tbody>
              {resources.map((resource) => (
                <tr key={resource.id} className="row-link">
                  <td className="cell">
                    <Urn
                      id={resource.externalId}
                      href={`/inventory/${encodeURIComponent(resource.externalId)}`}
                    />
                  </td>
                  <td className="cell font-medium">{resource.name}</td>
                  <td className="cell text-muted">{label(resource.resourceType)}</td>
                  <td className="cell font-mono text-[0.78rem] text-muted">
                    {resource.region ?? "—"}
                  </td>
                  <td className="cell font-mono text-[0.78rem] text-muted">
                    {resource.state ?? "—"}
                  </td>
                  <td className="cell">
                    <Sensitivity value={resource.sensitivity} />
                  </td>
                  <td className="cell">
                    <Exposed value={resource.isInternetExposed} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
