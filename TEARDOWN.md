# Test resources — teardown and running cost

Created for scanner testing on the `hashirr work trial` account. **All billed hourly.**
Delete when done; the database is the only one that costs real money if forgotten.

| Resource | ID | $/hr |
|---|---|---|
| Droplet `web-01` (no firewall) | `595135348` | 0.00595 |
| Droplet `api-01` | `595135351` | 0.00595 |
| Postgres `scanner-test-pg` | `fa974059-fc39-424f-9bcc-086c588d3aeb` | ~0.022 |

**Total ≈ $0.034/hr — about $0.82/day, $5.70/week.**

Everything is tagged `scanner-test`.

## Teardown

```bash
WT=$(grep -oP '(?<=^DIGITALOCEAN_WRITE_TOKEN=).*' .env | tr -d '\r')
curl -s -X DELETE "https://api.digitalocean.com/v2/droplets?tag_name=scanner-test" -H "Authorization: Bearer $WT"
curl -s -X DELETE "https://api.digitalocean.com/v2/databases/fa974059-fc39-424f-9bcc-086c588d3aeb" -H "Authorization: Bearer $WT"
```

Then confirm nothing is left:

```bash
curl -s "https://api.digitalocean.com/v2/droplets?tag_name=scanner-test" -H "Authorization: Bearer $WT" | grep -o '"total":[0-9]*'
```

## Afterwards

Delete `DIGITALOCEAN_WRITE_TOKEN` from `.env` and revoke it in the DigitalOcean console.
The scanner only ever reads `DIGITALOCEAN_TOKEN`; the write token exists solely for
this test and should not outlive it.
