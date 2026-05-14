# Deployment

Aura-Guard is a single statically linked Rust binary plus a directory of
signed policies and an append-only audit log. Run it next to (not in
front of) your AI workload; in production keep it behind your existing
reverse proxy / WAF.

## Topology

```
client ─▶ reverse proxy (TLS, mTLS, rate-limit, IP allow-list)
              │
              └─▶ aura-guard (HTTP, API-key auth)
                     │
                     ├─ policies/   (read-only, signed)
                     ├─ logs/       (append-only JSONL audit log)
                     └─ /metrics    (Prometheus)
```

The runtime intentionally does **not** terminate TLS itself in v1.3 —
delegate that to your existing edge (nginx, Envoy, Caddy, AWS ALB,
Cloudflare). mTLS termination inside the runtime is roadmap v1.4.

## Docker

The shipped `deploy/Dockerfile` is a distroless multi-stage build (Rust
builder + `gcr.io/distroless/cc-debian12` runtime). No shell, no
package manager, no setuid binaries.

```bash
docker build -f deploy/Dockerfile -t aura-guard:1.3 .
docker run --rm -p 8080:8080 \
    -e AURA_API_KEY=changeme \
    -v $PWD/policies:/app/policies:ro \
    -v $PWD/logs:/app/logs \
    aura-guard:1.3
```

`deploy/docker-compose.yml` is the same thing as a one-liner with the
bind mounts already wired up:

```bash
export AURA_API_KEY=changeme
docker compose -f deploy/docker-compose.yml up --build
```

## systemd

A hardened unit file ships in
[`deploy/systemd/aura-guard.service`](../deploy/systemd/aura-guard.service):

```ini
[Service]
Type=exec
User=aura-guard
EnvironmentFile=/etc/aura-guard/env
ExecStart=/usr/local/bin/aura-guard
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
Restart=on-failure
RestartPreventExitStatus=78
```

`RestartPreventExitStatus=78` is critical: it prevents systemd from
restarting the service on a fail-closed boot (which would mask the
underlying integrity failure). Pair with `OnFailure=` to page the
on-call.

## Kubernetes

There is no Helm chart yet (planned for v1.5). For a starter `Deployment`:

- Treat the container as stateless. Mount `policies/` from a `ConfigMap`
  or a read-only volume. Mount `logs/` as a `PersistentVolumeClaim` or
  ship the JSONL out via a sidecar.
- `livenessProbe` → `GET /health` (returns `200` while the process is
  up).
- `readinessProbe` → `GET /ready` (returns `503` when the audit log is
  halted).
- Surface `/metrics` to your Prometheus scrape target.
- Expect exit code `78` to manifest as `CrashLoopBackOff`. **Do not
  auto-heal** — a fail-closed boot means the enforcement boundary is
  incomplete; rolling back the previous manifest is the safer move.
- The container runs with no shell. Use `kubectl debug` with an
  ephemeral container if you need interactive inspection.

## Configuration

All configuration is via `AURA_*` environment variables — see the
`Configuration` section of the README for the full table. For
production:

- `AURA_BIND=0.0.0.0:8080`
- `AURA_API_KEY=<long random secret>`
- `AURA_AUTH_DISABLED=false` (default — never flip this in prod)
- `AURA_POLICIES_DIR=/app/policies`
- `AURA_AUDIT_LOG_PATH=/app/logs/audit.jsonl`
- `AURA_ALLOWED_ORIGINS=` (empty unless you actually serve browsers)
- `AURA_LOG=info`

## Observability

- **Logs.** `tracing-subscriber` emits one JSON object per line on
  stdout. Pipe through Fluent Bit / Vector / Loki / your existing
  pipeline.
- **Metrics.** `metrics-exporter-prometheus` exposes counters and
  histograms at `GET /metrics`.
- **Health.** `/health` and `/ready` are unauthenticated by design so
  load balancers can probe them.
- **Version pin.** `GET /version` returns the build version and the
  canonical genesis hash. Pin both in your runbooks; a change in
  `genesis_hash` means you are running an incompatible protocol.

## Shipping the audit log

The audit log is append-only JSONL on the local filesystem. For
durability:

1. Mount the log directory on a journaled filesystem.
2. Stream the file out with `vector` or `fluent-bit` to S3 / GCS with
   Object Lock enabled (WORM).
3. Run `aura-replay --log <captured-file>` on the archive periodically
   as an independent integrity check.

WORM-native adapters and Merkle-root anchoring are roadmap v1.4–v2.0.

## Security hardening checklist

- [ ] Run as a dedicated unprivileged user (systemd `User=`, container
      `USER`).
- [ ] Mount `policies/` read-only.
- [ ] Mount `logs/` on a dedicated volume; back up immediately.
- [ ] Generate a long random `AURA_API_KEY` and rotate it on incident.
- [ ] Set `RestartPreventExitStatus=78` on systemd, do **not** auto-heal
      `CrashLoopBackOff` on K8s.
- [ ] Front Aura-Guard with TLS at the reverse proxy. Use mTLS if your
      clients can provide certs.
- [ ] Forward stdout logs to immutable storage.
- [ ] Schedule a recurring `aura-replay --verify-lineage` audit job.
