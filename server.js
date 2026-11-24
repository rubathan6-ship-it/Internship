const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const VALID_ID = "NSWKA0126005";
const PDF_PATH = path.join(ROOT, "protected", "NSWKA0126005.pdf");
const INDEX_PATH = path.join(ROOT, "index.html");
const STYLE_PATH = path.join(ROOT, "styles.css");
const SESSION_COOKIE = "verify_session";
const SESSION_MS = 8 * 60 * 60 * 1000;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES = 5;
const PORT = Number(process.env.PORT) || 3000;

const sessions = new Map();
const failures = new Map();

function parseCookies(header) {
  const result = {};
  for (const part of String(header || "").split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    const key = part.slice(0, separator).trim();
    const rawValue = part.slice(separator + 1).trim();
    if (!key) continue;
    try {
      result[key] = decodeURIComponent(rawValue);
    } catch {
      result[key] = rawValue;
    }
  }
  return result;
}

function isSecureRequest(req) {
  const forwarded = String(req.headers["x-forwarded-proto"] || "")
    .split(",")[0]
    .trim()
    .toLowerCase();
  return Boolean(req.socket.encrypted) || forwarded === "https";
}

function clearedCookie(name, secure) {
  let cookie = `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
  if (secure) cookie += "; Secure";
  return cookie;
}

function sessionCookie(token, secure) {
  let cookie = `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(SESSION_MS / 1000)}`;
  if (secure) cookie += "; Secure";
  return cookie;
}

function getSession(req) {
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, expiresAt: session.expiresAt };
}

function clientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return forwarded || req.socket.remoteAddress || "unknown";
}

function isRateLimited(req) {
  const ip = clientIp(req);
  const record = failures.get(ip);
  if (!record) return false;
  if (Date.now() - record.startedAt > RATE_WINDOW_MS) {
    failures.delete(ip);
    return false;
  }
  return record.failures >= MAX_FAILURES;
}

function recordFailure(req) {
  const ip = clientIp(req);
  const record = failures.get(ip);
  if (!record || Date.now() - record.startedAt > RATE_WINDOW_MS) {
    failures.set(ip, { startedAt: Date.now(), failures: 1 });
    return;
  }
  record.failures += 1;
}

function clearFailures(req) {
  failures.delete(clientIp(req));
}

function readBody(req, limit = 16384) {
  return new Promise((resolve, reject) => {
    let raw = "";
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    req.on("data", (chunk) => {
      raw += chunk;
      if (Buffer.byteLength(raw) > limit) {
        const error = new Error("Payload too large");
        error.statusCode = 413;
        finish(error);
        req.destroy();
      }
    });
    req.on("end", () => finish(null, new URLSearchParams(raw)));
    req.on("error", (error) => finish(error));
  });
}

function send(res, statusCode, body, headers = {}) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(statusCode, {
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": payload.length,
    "X-Content-Type-Options": "nosniff",
    ...headers,
  });
  res.end(payload);
}

function sendJson(res, statusCode, payload) {
  send(res, statusCode, JSON.stringify(payload), {
    "Content-Type": "application/json; charset=utf-8",
  });
}

function sendTextFile(res, filePath) {
  fs.readFile(filePath, (error, data) => {
    if (error) return send(res, 404, "Not found");
    const contentType = filePath.endsWith(".css")
      ? "text/css; charset=utf-8"
      : "text/html; charset=utf-8";
    send(res, 200, data, { "Content-Type": contentType, "Cache-Control": "no-cache" });
  });
}

function servePdf(req, res) {
  fs.stat(PDF_PATH, (error, stat) => {
    if (error || !stat.isFile()) return send(res, 404, "Document not found");

    const headers = {
      "Content-Type": "application/pdf",
      "Content-Disposition": 'inline; filename="NSWKA0126005.pdf"',
      "Accept-Ranges": "bytes",
      "Cache-Control": "private, no-store, max-age=0",
      "X-Content-Type-Options": "nosniff",
    };

    const range = req.headers.range;
    if (!range) {
      res.writeHead(200, { ...headers, "Content-Length": stat.size });
      if (req.method === "HEAD") return res.end();
      return fs.createReadStream(PDF_PATH).pipe(res);
    }

    const match = /^bytes=(\d*)-(\d*)$/.exec(String(range).trim());
    if (!match || (match[1] === "" && match[2] === "")) {
      res.writeHead(416, { ...headers, "Content-Range": `bytes */${stat.size}` });
      return res.end();
    }

    let start;
    let end;
    if (match[1] === "") {
      const suffixLength = Number(match[2]);
      start = Math.max(0, stat.size - suffixLength);
      end = stat.size - 1;
    } else {
      start = Number(match[1]);
      end = match[2] === "" ? stat.size - 1 : Math.min(Number(match[2]), stat.size - 1);
    }

    if (!Number.isFinite(start) || !Number.isFinite(end) || start < 0 || start >= stat.size || start > end) {
      res.writeHead(416, { ...headers, "Content-Range": `bytes */${stat.size}` });
      return res.end();
    }

    res.writeHead(206, {
      ...headers,
      "Content-Range": `bytes ${start}-${end}/${stat.size}`,
      "Content-Length": end - start + 1,
    });
    if (req.method === "HEAD") return res.end();
    fs.createReadStream(PDF_PATH, { start, end }).pipe(res);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const pathname = url.pathname;
    const session = getSession(req);
    const secure = isSecureRequest(req);

    if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
      return sendTextFile(res, INDEX_PATH);
    }

    if (req.method === "GET" && pathname === "/styles.css") {
      return sendTextFile(res, STYLE_PATH);
    }

    if (req.method === "GET" && pathname === "/favicon.ico") {
      res.writeHead(204);
      return res.end();
    }

    if (req.method === "GET" && pathname === "/api/session") {
      return sendJson(res, 200, { authenticated: Boolean(session) });
    }

    if (req.method === "POST" && pathname === "/login") {
      if (isRateLimited(req)) {
        return sendJson(res, 429, {
          ok: false,
          error: "Too many attempts. Please try again later.",
        });
      }

      const params = await readBody(req);
      if (params.get("id") === VALID_ID) {
        clearFailures(req);
        const token = crypto.randomBytes(32).toString("hex");
        sessions.set(token, { expiresAt: Date.now() + SESSION_MS });
        res.setHeader("Set-Cookie", sessionCookie(token, secure));
        return sendJson(res, 200, { ok: true });
      }

      recordFailure(req);
      return sendJson(res, 401, { ok: false, error: "Invalid Student ID." });
    }

    if (req.method === "POST" && pathname === "/logout") {
      if (session) sessions.delete(session.token);
      res.setHeader("Set-Cookie", clearedCookie(SESSION_COOKIE, secure));
      return sendJson(res, 200, { ok: true });
    }

    if ((req.method === "GET" || req.method === "HEAD") && pathname === "/document") {
      if (!session) return send(res, 403, "Forbidden");
      return servePdf(req, res);
    }

    return send(res, 404, "Not found");
  } catch (error) {
    if (error.statusCode) return send(res, error.statusCode, error.message);
    console.error(error);
    return send(res, 500, "Server error");
  }
});

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (session.expiresAt <= now) sessions.delete(token);
  }
  for (const [ip, record] of failures) {
    if (now - record.startedAt > RATE_WINDOW_MS) failures.delete(ip);
  }
}, 60 * 1000).unref();

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Document Verification running at http://localhost:${PORT}`);
});
