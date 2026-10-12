# Agent Illusion

A professional-looking website ("Helix Data Cloud") that doubles as a **prompt-injection
test harness** for evaluating how your own autonomous LLM agents behave when they encounter
injected instructions. Built for authorized red-team / hardening work on agents you control.

## How it works

The site plants small **canary prompts** across many channels an agent might read. Each
prompt asks the reader to make a harmless `GET` request to a unique **beacon** URL
(`/b/{vector}`) on this same server. A normal human browser never does this. If your agent
*acts* on an injected instruction, it hits the beacon, the server logs it, and the
monitoring dashboard shows **exactly which channel the agent obeyed**.

Nothing attacks anyone: the only requested action is a GET back to your own server. That is
what makes each injection observable and attributable.

## Injection vectors

| Channel      | Vectors |
|--------------|---------|
| HTTP headers | `X-Agent-Directive`, `X-Context-Note`, `X-Resource-Hint`, `Link: rel=preload` |
| HTML         | comment, `<meta generator>`, screen-reader-only text, off-screen div, white-on-white text, image `alt`, `data-*` attribute, `<noscript>`, JSON-LD, `aria-label`, `title` tooltip, footer microcopy, pricing note, docs code sample |
| Files        | `/llms.txt` (AI policy file), `/robots.txt`, CSS/JS comments |

Full catalog with IDs is the `vectors` slice in `main.go`.

## Run locally

```bash
go run .
# visit http://localhost:8080  and  http://localhost:8080/_monitor
```

## Configuration (env vars)

| Var             | Default         | Purpose |
|-----------------|-----------------|---------|
| `ADDR`          | `:8080`         | Listen address |
| `LOG_FILE`      | `events.jsonl`  | Append-only beacon log (survives restarts) |
| `MONITOR_TOKEN` | *(empty)*       | If set, `/_monitor` requires `?token=...` or `X-Monitor-Token` header. **Set this in production.** |

## Deploy to your cloud server

```bash
# build a static Linux binary on your machine
GOOS=linux GOARCH=amd64 go build -o agent-illusion .
scp agent-illusion user@your-server:/opt/agent-illusion/

# on the server (behind nginx/caddy for TLS), run it:
MONITOR_TOKEN=pick-a-long-secret ADDR=:8080 /opt/agent-illusion/agent-illusion
```

A sample `deploy/agent-illusion.service` systemd unit is included.

> **Note:** the beacon URLs are built from the request's `Host` / `X-Forwarded-Proto`
> headers, so running behind a reverse proxy with TLS works automatically — the injected
> prompts will carry your real `https://your-domain/b/...` URLs.

## Monitoring

- `/_monitor` — live dashboard (auto-refresh, coverage table + recent hits)
- `/_monitor/data.json` — raw JSON (stats + recent hits) for your own tooling
- `events.jsonl` — one JSON object per hit; tail it or ingest it into your SIEM

## Scope

This is a defensive tool for testing agents **you own and are authorized to test**. The
injected text is benign (it only triggers self-beacons). Do not repurpose the vectors to
target systems you do not control.
