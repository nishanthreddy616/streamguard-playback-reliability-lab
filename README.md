# StreamGuard Playback Reliability Lab

A small TypeScript service and browser simulator for exploring the backend decisions made when a viewer starts playback. The demo checks access and regional availability, selects a delivery edge, issues a short-lived demo grant, and records a decision trace. All identities, catalog records, and metrics are synthetic.

## Live demo

[Open the browser simulator](https://nishanthreddy616.github.io/streamguard-playback-reliability-lab/). It runs in the browser without a server. Choose request conditions, evaluate the decision, and inject an edge failure to view the failover path.

## Run locally

Requires Node.js 22.6 or newer. The API uses Node's built-in TypeScript type stripping and has no external runtime dependencies.

```sh
export STREAMGUARD_SIGNING_KEY="$(openssl rand -hex 32)"
npm start
```

Open `http://localhost:8080` and select **TypeScript API** to send requests to the local service. Use `npm run dev` to restart the service when files change.

Example request:

```sh
curl -s http://localhost:8080/api/playback-sessions \
  -H 'content-type: application/json' \
  -d '{"member_id":"member-active","asset_id":"catalog-alpha","region":"us-west","drm":"Widevine","preferred_edge":"edge-west","latency_profile":"healthy","simulate_edge_failure":true}'
```

## HTTP endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Service readiness |
| `POST` | `/api/playback-sessions` | Evaluate a request and issue a demo grant |
| `GET` | `/api/metrics` | In-memory counters and simulated latency |
| `GET` | `/api/events` | Recent decision events |

## Request flow

1. Validate the bounded JSON request.
2. Check member entitlement, catalog rights, region, and device policy.
3. Select a healthy edge and calculate simulated startup latency.
4. If the preferred edge is unavailable, route to a healthy alternate.
5. Sign a short-lived demo grant and return the result with a trace.

Access checks fail closed. An edge failure affects routing, not the access decision.

## Project structure

```text
src/server.ts  TypeScript HTTP API, policy checks, grant signing, and metrics
web/           Browser simulator source
dist/          Static files published by GitHub Pages
```

## Scope and limitations

GitHub Pages hosts the static browser simulator; the TypeScript API runs locally. This project does not stream media, connect to a DRM license service, authenticate real users, or return a playback URL or content key. The grant is for demonstration only. Catalogs and counters are in memory, reset on restart, and are not production storage or telemetry.
