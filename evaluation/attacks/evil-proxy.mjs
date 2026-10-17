/**
 * Evil relay proxy for the v0 app.
 *
 * v0 has no evil mode and a single origin for both REST and socket.io. This
 * proxy sits in front of the untouched v0 server and the v0 frontend points at
 * it (VITE_API_URL = this proxy). It:
 *   - forwards every HTTP request to the real v0 backend unchanged (REST passes
 *     straight through, so register/login/friends all work);
 *   - for each browser socket, opens one upstream socket.io-client to the real
 *     v0 server and relays events both ways, applying the SAME transforms the v1
 *     backend uses. The transform logic is imported from the compiled v1
 *     dist/evil.js (single source of truth) via createEvilRelay/parseEvilConfig.
 *
 * Transforms applied:
 *   receive_message (server -> client)   replay/reorder/drop/duplicate/tamper/flip_type
 *   request_public_key (client -> server) swap_key (serve EVIL_SWAP_WITH's key)
 *
 * flip_content_type has no effect on v0 (no envelope); it passes through.
 *
 * Env: EVIL_MODE etc. (same as the v1 backend), plus:
 *   PROXY_PORT        port this proxy listens on (what the v0 frontend uses)
 *   V0_BACKEND_URL    the real v0 server, e.g. http://localhost:3300
 *   KRYPT_EVIL_JS     absolute path to the v1 backend's dist/evil.js
 *   KRYPT_BACKEND_NM  v1 backend node_modules (for socket.io server)
 *   KRYPT_FRONTEND_NM frontend node_modules (for socket.io-client)
 */
import http from "node:http";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const require = createRequire(import.meta.url);
const backendReq = createRequire(pathToFileURL(process.env.KRYPT_BACKEND_NM + "/"));
const frontendReq = createRequire(pathToFileURL(process.env.KRYPT_FRONTEND_NM + "/"));

const { Server } = backendReq("socket.io");
const { io: ioClient } = frontendReq("socket.io-client");
const { createEvilRelay, parseEvilConfig } = await import(pathToFileURL(process.env.KRYPT_EVIL_JS).href);

const PROXY_PORT = Number(process.env.PROXY_PORT ?? 3300);
const V0_BACKEND = process.env.V0_BACKEND_URL ?? "http://localhost:3301";
const backendHost = new URL(V0_BACKEND);

const config = parseEvilConfig(process.env);
const relay = config ? createEvilRelay(config) : null;
console.log(`[evil-proxy] EVIL_MODE=${process.env.EVIL_MODE ?? "(none)"} -> ${V0_BACKEND}, listening on ${PROXY_PORT}`);

// --- HTTP passthrough to the real v0 backend ---
// The browser talks only to this proxy, so the proxy (not the v0 server, whose
// CORS allowlist does not include our dev port) answers CORS for the browser.
function cors(req, res) {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin ?? "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", req.headers["access-control-request-headers"] ?? "Content-Type");
  res.setHeader("Vary", "Origin");
}
const httpServer = http.createServer((req, res) => {
  cors(req, res);
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }
  const opts = {
    hostname: backendHost.hostname,
    port: backendHost.port,
    path: req.url,
    method: req.method,
    headers: { ...req.headers, host: backendHost.host },
  };
  const up = http.request(opts, (upRes) => {
    // Drop the upstream's own CORS headers; keep the proxy's permissive ones.
    const headers = { ...upRes.headers };
    delete headers["access-control-allow-origin"];
    delete headers["access-control-allow-methods"];
    delete headers["access-control-allow-headers"];
    res.writeHead(upRes.statusCode ?? 502, headers);
    upRes.pipe(res);
  });
  up.on("error", (e) => {
    res.writeHead(502);
    res.end(`proxy error: ${e.message}`);
  });
  req.pipe(up);
});

// --- socket.io relay ---
const io = new Server(httpServer, { cors: { origin: "*", methods: ["GET", "POST"] } });

io.on("connection", (client) => {
  const upstream = ioClient(V0_BACKEND, { reconnection: false, transports: ["websocket", "polling"] });

  // server -> client
  upstream.onAny((event, ...args) => {
    if (event === "receive_message" && relay) {
      const payload = args[0];
      if (payload && typeof payload === "object" && payload.to && payload.from) {
        for (const m of relay.process(payload)) client.emit("receive_message", m);
        return;
      }
    }
    client.emit(event, ...args);
  });
  upstream.on("connect_error", (e) => client.emit("connect_error_upstream", e.message));

  // client -> server
  client.onAny((event, ...args) => {
    if (event === "request_public_key") {
      const [target, ack] = args;
      const served = relay ? relay.keySource(String(target)) : target;
      upstream.emit("request_public_key", served, (resp) => typeof ack === "function" && ack(resp));
      return;
    }
    if (event === "private_message") {
      const [payload, ack] = args;
      upstream.emit("private_message", payload, (res) => typeof ack === "function" && ack(res));
      return;
    }
    // Everything else (register_socket, friend events, ...) straight through.
    const last = args[args.length - 1];
    if (typeof last === "function") upstream.emit(event, ...args.slice(0, -1), last);
    else upstream.emit(event, ...args);
  });

  client.on("disconnect", () => upstream.close());
});

httpServer.listen(PROXY_PORT, () => console.log(`[evil-proxy] ready on ${PROXY_PORT}`));
