import { createHmac, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { access, stat } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WEB_ROOT = path.join(ROOT, "web");
const SESSION_TTL_SECONDS = 15 * 60;
const MAX_BODY_BYTES = 32 * 1024;
const MAX_SAMPLES = 1_000;
const MAX_EVENTS = 12;

type Region = "us-west" | "us-east" | "uk-south";
type LatencyProfile = "healthy" | "degraded";
type TraceStatus = "ALLOW" | "DENY" | "HEALTHY" | "DEGRADED" | "RECOVERED" | "WARN" | "ERROR";

type CreateSessionRequest = {
  member_id: string;
  asset_id: string;
  region: Region;
  drm: string;
  preferred_edge?: string;
  latency_profile?: LatencyProfile;
  simulate_edge_failure?: boolean;
};

type TraceStep = { name: string; status: TraceStatus; detail: string; latency_ms: number };
type PlaybackEvent = { time: string; type: string; status: string; message: string; latency_ms: number; trace_id: string };
type SessionResponse = {
  session_id: string;
  decision: "ALLOW" | "DENY";
  reason_code?: string;
  message: string;
  member_id: string;
  asset_id: string;
  region: Region;
  drm: string;
  selected_edge?: string;
  failover: boolean;
  latency_ms: number;
  token_status?: string;
  token_expires_at?: string;
  token_preview?: string;
  trace: TraceStep[];
  created_at: string;
};

const members: Record<string, boolean> = {
  "member-active": true,
  "member-expired": false,
};

const assetRights: Record<string, Region[]> = {
  "catalog-alpha": ["us-west", "us-east", "uk-south"],
  "catalog-us-only": ["us-west", "us-east"],
  "catalog-eu-only": ["uk-south"],
};

const edgeLatency: Record<string, Record<Region, number>> = {
  "edge-west": { "us-west": 24, "us-east": 88, "uk-south": 162 },
  "edge-east": { "us-west": 82, "us-east": 27, "uk-south": 94 },
  "edge-eu": { "us-west": 158, "us-east": 92, "uk-south": 22 },
};

const allowedRegions = new Set<Region>(["us-west", "us-east", "uk-south"]);
const allowedDrm = new Set(["Widevine", "FairPlay", "PlayReady"]);
const startedAt = Date.now();
const signingKey = process.env.STREAMGUARD_SIGNING_KEY ?? "";
const recentLatencies: number[] = [];
const recentEvents: PlaybackEvent[] = [];
const metrics = { requests: 0, allowed: 0, denied: 0, failovers: 0 };

function json(response: ServerResponse, status: number, data: unknown): void {
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(data));
}

function traceStep(name: string, status: TraceStatus, detail: string, latency: number): TraceStep {
  return { name, status, detail, latency_ms: latency };
}

function signClaims(claims: Record<string, string | number>): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const unsigned = `${header}.${payload}`;
  const signature = createHmac("sha256", signingKey).update(unsigned).digest("base64url");
  return `${unsigned}.${signature}`;
}

function finish(
  result: SessionResponse,
  trace: TraceStep[],
  httpStatus: number,
  eventType: string,
  message: string,
): { result: SessionResponse; httpStatus: number } {
  result.trace = trace;
  metrics.requests += 1;
  if (result.decision === "ALLOW") metrics.allowed += 1;
  else metrics.denied += 1;
  if (result.failover) metrics.failovers += 1;
  recentLatencies.push(result.latency_ms);
  if (recentLatencies.length > MAX_SAMPLES) recentLatencies.shift();
  recentEvents.unshift({
    time: new Date().toISOString().slice(11, 19),
    type: eventType,
    status: result.decision,
    message,
    latency_ms: result.latency_ms,
    trace_id: result.session_id,
  });
  if (recentEvents.length > MAX_EVENTS) recentEvents.pop();
  return { result, httpStatus };
}

function deny(
  result: SessionResponse,
  trace: TraceStep[],
  reasonCode: string,
  message: string,
  latency: number,
  eventType: string,
): { result: SessionResponse; httpStatus: number } {
  result.reason_code = reasonCode;
  result.message = message;
  result.latency_ms = latency;
  return finish(result, trace, 403, eventType, message);
}

function nearestEdge(region: Region, excluded?: string): string {
  return Object.keys(edgeLatency)
    .filter((name) => name !== excluded)
    .sort((a, b) => edgeLatency[a][region] - edgeLatency[b][region])[0];
}

function createPlaybackSession(input: CreateSessionRequest): { result: SessionResponse; httpStatus: number } {
  const now = new Date();
  const traceId = randomUUID();
  const trace: TraceStep[] = [];
  const result: SessionResponse = {
    session_id: traceId,
    decision: "DENY",
    message: "Playback request denied.",
    member_id: input.member_id,
    asset_id: input.asset_id,
    region: input.region,
    drm: input.drm,
    failover: false,
    latency_ms: 0,
    trace,
    created_at: now.toISOString(),
  };
  const profile = input.latency_profile ?? "healthy";

  if (profile !== "healthy" && profile !== "degraded") {
    trace.push(traceStep("request-validation", "DENY", "Latency profile must be healthy or degraded.", 1));
    return deny(result, trace, "INVALID_LATENCY_PROFILE", "Invalid playback request.", 1, "request_rejected");
  }
  if (!(input.member_id in members)) {
    trace.push(traceStep("identity", "DENY", "Member record was not found.", 2));
    return deny(result, trace, "MEMBER_NOT_FOUND", "Member record was not found.", 2, "security_denied");
  }
  if (!members[input.member_id]) {
    trace.push(traceStep("entitlement", "DENY", "Membership is expired; no playback grant issued.", 3));
    return deny(result, trace, "ENTITLEMENT_EXPIRED", "Membership is expired; renew access to continue.", 3, "entitlement_denied");
  }
  trace.push(traceStep("entitlement", "ALLOW", "Active membership permits catalog access.", 3));

  const regions = assetRights[input.asset_id];
  if (!regions) {
    trace.push(traceStep("catalog", "DENY", "Asset is not present in the demo catalog.", 2));
    return deny(result, trace, "ASSET_NOT_FOUND", "Asset is not present in the demo catalog.", 5, "catalog_denied");
  }
  if (!regions.includes(input.region)) {
    trace.push(traceStep("license-window", "DENY", "This asset is not licensed for the requested region.", 4));
    return deny(result, trace, "REGION_NOT_LICENSED", "This asset is not licensed for the requested region.", 9, "license_denied");
  }
  trace.push(traceStep("license-window", "ALLOW", "Regional rights window is active for this asset.", 4));

  if (!allowedDrm.has(input.drm)) {
    trace.push(traceStep("device-policy", "DENY", "Requested DRM system is unsupported by this demo.", 2));
    return deny(result, trace, "DRM_UNSUPPORTED", "Requested DRM system is unsupported by this demo.", 11, "security_denied");
  }
  trace.push(traceStep("device-policy", "ALLOW", "Device protection profile is supported by this demo.", 2));

  const preferred = edgeLatency[input.preferred_edge ?? ""] ? input.preferred_edge! : nearestEdge(input.region);
  let selectedEdge = preferred;
  const failover = input.simulate_edge_failure === true;
  if (failover) {
    trace.push(traceStep("edge-health", "DEGRADED", `${selectedEdge} is marked unhealthy; routing to a healthy alternate.`, 7));
    selectedEdge = nearestEdge(input.region, selectedEdge);
    trace.push(traceStep("edge-failover", "RECOVERED", `Traffic moved to ${selectedEdge} without changing the playback grant.`, 8));
  } else {
    trace.push(traceStep("edge-health", "HEALTHY", `${selectedEdge} passed the health check.`, 5));
  }

  let latency = edgeLatency[selectedEdge][input.region] + 18 + (failover ? 12 : 0);
  if (profile === "degraded") {
    latency += 145;
    trace.push(traceStep("latency-budget", "WARN", "Origin response is elevated; session remains within the demo budget.", 145));
  } else {
    trace.push(traceStep("latency-budget", "HEALTHY", "Estimated startup path is within the demo budget.", 18));
  }

  if (signingKey.length < 32) {
    trace.push(traceStep("grant-signing", "ERROR", "Session grant could not be signed.", 1));
    result.reason_code = "SIGNING_UNAVAILABLE";
    result.message = "Session grant could not be signed. Set STREAMGUARD_SIGNING_KEY to at least 32 characters.";
    result.latency_ms = latency;
    return finish(result, trace, 500, "signing_error", "Grant signing failed");
  }

  const expiresAt = new Date(now.getTime() + SESSION_TTL_SECONDS * 1_000);
  const token = signClaims({
    iss: "streamguard-demo",
    sub: input.member_id,
    asset: input.asset_id,
    region: input.region,
    sid: traceId,
    iat: Math.floor(now.getTime() / 1_000),
    exp: Math.floor(expiresAt.getTime() / 1_000),
  });
  trace.push(traceStep("grant-signing", "ALLOW", "Short-lived HMAC session grant signed; no DRM key is issued by this demo.", 2));
  result.decision = "ALLOW";
  result.message = "Playback session authorized.";
  result.selected_edge = selectedEdge;
  result.failover = failover;
  result.latency_ms = latency;
  result.token_status = "signed · 15 min TTL";
  result.token_expires_at = expiresAt.toISOString();
  result.token_preview = `${token.slice(0, 26)}…redacted`;
  return finish(result, trace, 201, "session_allowed", "Playback session authorized");
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_BODY_BYTES) throw new Error("Request body exceeds 32 KB.");
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateRequest(value: unknown): CreateSessionRequest | string {
  if (!isRecord(value)) return "Request body must be one JSON object.";
  const allowedKeys = new Set([
    "member_id", "asset_id", "region", "drm", "preferred_edge", "latency_profile", "simulate_edge_failure",
  ]);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) return "Request contains an unsupported field.";
  for (const key of ["member_id", "asset_id", "region", "drm"] as const) {
    if (typeof value[key] !== "string" || !value[key]) return `${key} is required and must be a string.`;
  }
  if (!allowedRegions.has(value.region as Region)) return "Unsupported demo region.";
  if (value.preferred_edge !== undefined && typeof value.preferred_edge !== "string") return "preferred_edge must be a string.";
  if (value.latency_profile !== undefined && typeof value.latency_profile !== "string") return "latency_profile must be a string.";
  if (value.simulate_edge_failure !== undefined && typeof value.simulate_edge_failure !== "boolean") {
    return "simulate_edge_failure must be a boolean.";
  }
  return value as CreateSessionRequest;
}

async function serveStatic(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const requestPath = new URL(request.url ?? "/", "http://localhost").pathname;
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(requestPath);
  } catch {
    json(response, 400, { error: "Invalid URL path." });
    return;
  }
  const relativePath = decodedPath === "/" ? "index.html" : decodedPath.replace(/^\/+/, "");
  const target = path.resolve(WEB_ROOT, relativePath);
  if (!target.startsWith(`${WEB_ROOT}${path.sep}`)) {
    json(response, 404, { error: "Not found." });
    return;
  }
  try {
    await access(target);
    if (!(await stat(target)).isFile()) {
      json(response, 404, { error: "Not found." });
      return;
    }
  } catch {
    json(response, 404, { error: "Not found." });
    return;
  }
  const extension = path.extname(target).toLowerCase();
  const contentType = extension === ".html" ? "text/html; charset=utf-8"
    : extension === ".css" ? "text/css; charset=utf-8"
      : extension === ".js" ? "text/javascript; charset=utf-8"
        : extension === ".svg" ? "image/svg+xml"
          : "application/octet-stream";
  response.writeHead(200, { "Content-Type": contentType });
  createReadStream(target).pipe(response);
}

async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Cache-Control", "no-store");
  const url = new URL(request.url ?? "/", "http://localhost");
  const route = `${request.method ?? "GET"} ${url.pathname}`;

  if (route === "GET /api/health") {
    json(response, 200, { status: "ok", service: "playback-session-api", time: new Date().toISOString() });
    return;
  }
  if (route === "GET /api/metrics") {
    const sorted = [...recentLatencies].sort((a, b) => a - b);
    const p95 = sorted.length ? sorted[Math.floor((sorted.length - 1) * 0.95)] : 0;
    json(response, 200, {
      service: "playback-session-api",
      status: "operational",
      uptime_seconds: Math.floor((Date.now() - startedAt) / 1_000),
      ...metrics,
      p95_simulated_latency_ms: p95,
      events: recentEvents,
      notice: "Counters are in-memory demo telemetry; they reset when the process restarts.",
    });
    return;
  }
  if (route === "GET /api/events") {
    json(response, 200, { events: recentEvents });
    return;
  }
  if (route === "POST /api/playback-sessions") {
    let body: unknown;
    try {
      body = await readJsonBody(request);
    } catch (error) {
      json(response, 400, { error: "Invalid JSON request.", detail: error instanceof Error ? error.message : "Invalid body." });
      return;
    }
    const input = validateRequest(body);
    if (typeof input === "string") {
      json(response, 400, { error: input });
      return;
    }
    const { result, httpStatus } = createPlaybackSession(input);
    json(response, httpStatus, result);
    return;
  }
  if (url.pathname.startsWith("/api/")) {
    json(response, 404, { error: "API route not found." });
    return;
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    json(response, 405, { error: "Method not allowed." });
    return;
  }
  await serveStatic(request, response);
}

const port = Number(process.env.PORT ?? 8080);
if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("PORT must be a valid TCP port.");
const server = createServer((request, response) => {
  void handle(request, response).catch((error: unknown) => {
    console.error("Request failed:", error);
    if (!response.headersSent) json(response, 500, { error: "Internal server error." });
    else response.destroy();
  });
});
server.headersTimeout = 5_000;
server.requestTimeout = 10_000;
server.listen(port, "0.0.0.0", () => {
  console.log(`StreamGuard TypeScript API listening on http://localhost:${port}`);
});
