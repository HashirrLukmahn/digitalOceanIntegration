/**
 * Display names for normalized resource types.
 *
 * In its own module because a Next page may only export the framework's reserved
 * names, so shared helpers cannot live alongside a route.
 */
const TYPE_LABELS: Record<string, string> = {
  "digitalocean.project": "Project",
  "digitalocean.droplet": "Droplet",
  "digitalocean.firewall": "Firewall",
  "digitalocean.load_balancer": "Load balancer",
  "digitalocean.vpc": "VPC",
  "digitalocean.kubernetes_cluster": "Kubernetes",
  "digitalocean.database_cluster": "Database",
  "digitalocean.app": "App",
  "digitalocean.container_registry": "Registry",
  "digitalocean.volume": "Volume",
  "digitalocean.space": "Space",
};

export function label(type: string): string {
  return TYPE_LABELS[type] ?? type;
}
