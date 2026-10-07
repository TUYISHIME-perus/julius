const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const ROOT = __dirname;
const SESSION_COOKIE = "campus_session";
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000;
const MAX_REQUEST_BYTES = 8192;
const PROTECTED_PAGES = new Set(["program-dashboard.html", "preachers.html"]);
const MIME_TYPES = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".gif", "image/gif"],
  [".ico", "image/x-icon"],
  [".jpeg", "image/jpeg"],
  [".jpg", "image/jpeg"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".webp", "image/webp"]
]);

function passwordRecord(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, record) {
  const actual = crypto.scryptSync(password, record.salt, 64);
  const expected = Buffer.from(record.hash, "hex");
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    let tooLarge = false;
    request.setEncoding("utf8");
    request.on("data", chunk => {
      if (tooLarge) return;
      body += chunk;
      if (Buffer.byteLength(body, "utf8") > MAX_REQUEST_BYTES) {
        tooLarge = true;
        reject(Object.assign(new Error("Request is too large."), { statusCode: 413 }));
      }
    });
    request.on("end", () => {
      if (tooLarge) return;
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(Object.assign(new Error("Send a valid JSON request."), { statusCode: 400 }));
      }
    });
    request.on("error", reject);
  });
}

function sendJson(response, statusCode, payload, headers = {}) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers
  });
  response.end(JSON.stringify(payload));
}

function cookieValue(request, name) {
  const cookies = (request.headers.cookie || "").split(";");
  const item = cookies.map(cookie => cookie.trim()).find(cookie => cookie.startsWith(name + "="));
  return item ? item.slice(name.length + 1) : "";
}

function createAppServer(options = {}) {
  const adminEmail = options.adminEmail || process.env.ADMIN_EMAIL;
  const initialPassword = options.adminPassword || process.env.ADMIN_PASSWORD;
  const authStorePath = options.authStorePath || path.join(ROOT, ".admin-credentials.json");
  const secureCookie = options.cookieSecure === undefined
    ? process.env.COOKIE_SECURE === "true"
    : options.cookieSecure;

  if (!adminEmail) {
    throw new Error("Set ADMIN_EMAIL before starting the site.");
  }

  let credentials = { email: adminEmail.trim().toLowerCase() };
  if (fs.existsSync(authStorePath)) {
    const saved = JSON.parse(fs.readFileSync(authStorePath, "utf8"));
    if (typeof saved.salt !== "string" || typeof saved.hash !== "string" ||
        !/^[0-9a-f]+$/i.test(saved.salt) || !/^[0-9a-f]+$/i.test(saved.hash)) {
      throw new Error("The saved administrator credential record is invalid.");
    }
    credentials = { ...credentials, salt: saved.salt, hash: saved.hash };
  } else {
    if (!initialPassword) {
      throw new Error("Set ADMIN_PASSWORD for the first server start.");
    }
    credentials = { ...credentials, ...passwordRecord(initialPassword) };
    fs.mkdirSync(path.dirname(authStorePath), { recursive: true });
    fs.writeFileSync(authStorePath, JSON.stringify({
      salt: credentials.salt,
      hash: credentials.hash
    }), { mode: 0o600 });
  }

  const sessions = new Map();
  const loginAttempts = new Map();

  function sessionCookie(value, maxAge) {
    return `${SESSION_COOKIE}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secureCookie ? "; Secure" : ""}`;
  }

  function sessionFor(request) {
    const token = cookieValue(request, SESSION_COOKIE);
    const expiresAt = sessions.get(token);
    if (!expiresAt) return "";
    if (expiresAt <= Date.now()) {
      sessions.delete(token);
      return "";
    }
    return token;
  }

  function sameOrigin(request) {
    const origin = request.headers.origin;
    if (!origin || !request.headers.host) return false;
    try {
      return new URL(origin).host === request.headers.host;
    } catch {
      return false;
    }
  }

  function handleApi(request, response, url) {
    if (request.method === "GET" && url.pathname === "/api/session") {
      sendJson(response, 200, { authenticated: Boolean(sessionFor(request)) });
      return true;
    }

    if (request.method !== "POST" || !["/api/login", "/api/logout", "/api/change-password"].includes(url.pathname)) {
      return false;
    }
    if (!sameOrigin(request)) {
      sendJson(response, 403, { error: "Request origin was not accepted." });
      return true;
    }
    if (url.pathname === "/api/logout") {
      const token = cookieValue(request, SESSION_COOKIE);
      sessions.delete(token);
      sendJson(response, 200, { ok: true }, { "Set-Cookie": sessionCookie("", 0) });
      return true;
    }

    readJson(request).then(data => {
      if (!data || typeof data !== "object" || Array.isArray(data)) {
        sendJson(response, 400, { error: "Send valid login details." });
        return;
      }

      if (url.pathname === "/api/login") {
        const address = request.socket.remoteAddress || "unknown";
        const attempts = loginAttempts.get(address) || { count: 0, resetAt: Date.now() + 15 * 60 * 1000 };
        if (attempts.resetAt <= Date.now()) {
          attempts.count = 0;
          attempts.resetAt = Date.now() + 15 * 60 * 1000;
        }
        if (attempts.count >= 10) {
          loginAttempts.set(address, attempts);
          sendJson(response, 429, { error: "Too many login attempts. Try again later." });
          return;
        }

        const email = typeof data.email === "string" ? data.email.trim().toLowerCase() : "";
        const password = typeof data.password === "string" ? data.password : "";
        if (email !== credentials.email || !verifyPassword(password, credentials)) {
          attempts.count += 1;
          loginAttempts.set(address, attempts);
          sendJson(response, 401, { error: "Incorrect email or password." });
          return;
        }

        loginAttempts.delete(address);
        const token = crypto.randomBytes(32).toString("hex");
        sessions.set(token, Date.now() + SESSION_DURATION_MS);
        sendJson(response, 200, { ok: true }, {
          "Set-Cookie": sessionCookie(token, Math.floor(SESSION_DURATION_MS / 1000))
        });
        return;
      }

      if (!sessionFor(request)) {
        sendJson(response, 401, { error: "Sign in to change the administrator password." });
        return;
      }
      const currentPassword = typeof data.currentPassword === "string" ? data.currentPassword : "";
      const newPassword = typeof data.newPassword === "string" ? data.newPassword : "";
      if (!verifyPassword(currentPassword, credentials)) {
        sendJson(response, 401, { error: "The current password is incorrect." });
        return;
      }
      if (newPassword.length < 12) {
        sendJson(response, 400, { error: "The new password must contain at least 12 characters." });
        return;
      }

      const nextCredentials = {
        email: credentials.email,
        ...passwordRecord(newPassword)
      };
      fs.mkdirSync(path.dirname(authStorePath), { recursive: true });
      fs.writeFileSync(authStorePath, JSON.stringify({
        salt: nextCredentials.salt,
        hash: nextCredentials.hash
      }), { mode: 0o600 });
      credentials = nextCredentials;
      sessions.clear();
      sendJson(response, 200, { ok: true }, { "Set-Cookie": sessionCookie("", 0) });
    }).catch(error => {
      if (response.headersSent || response.destroyed) return;
      sendJson(response, error.statusCode || 500, {
        error: error.statusCode ? error.message : "Unable to process the request."
      });
      if (!error.statusCode) console.error("Authentication request failed:", error);
    });
    return true;
  }

  return http.createServer((request, response) => {
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("Referrer-Policy", "same-origin");
    response.setHeader("X-Frame-Options", "DENY");

    let url;
    try {
      url = new URL(request.url, "http://localhost");
    } catch {
      response.writeHead(400).end("Invalid request URL.");
      return;
    }
    if (url.pathname.startsWith("/api/")) {
      if (handleApi(request, response, url)) return;
      sendJson(response, 404, { error: "Not found." });
      return;
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      response.writeHead(405, { Allow: "GET, HEAD" }).end("Method not allowed.");
      return;
    }

    let pathname;
    try {
      pathname = decodeURIComponent(url.pathname);
    } catch {
      response.writeHead(400).end("Invalid request path.");
      return;
    }
    const relativePath = pathname.replace(/^\/+/, "") || "index.html";
    const filePath = path.resolve(ROOT, relativePath);
    if (!filePath.startsWith(ROOT + path.sep) || !MIME_TYPES.has(path.extname(filePath).toLowerCase())) {
      response.writeHead(404).end("Not found.");
      return;
    }

    const page = path.basename(filePath);
    if (PROTECTED_PAGES.has(page) && !sessionFor(request)) {
      response.writeHead(302, {
        Location: `admin.html?returnTo=${encodeURIComponent(page)}`,
        "Cache-Control": "no-store"
      }).end();
      return;
    }

    fs.readFile(filePath, (error, contents) => {
      if (error) {
        // If the requested file is the site logo and it's missing, serve a small built-in JPEG.
        if (error.code === "ENOENT" && path.basename(filePath) === "church-logo.jpg") {
          const jpeg = Buffer.from(
            // 1x1 white JPEG
            "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAARCAABAAEDAREAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAb/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAH/AP/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAQUC/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwF//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAgEBPwF//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQAGPwJ//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPyF//9k=",
            "base64"
          );
          response.writeHead(200, {
            "Content-Type": "image/jpeg",
            "Cache-Control": "no-cache"
          });
          response.end(request.method === "HEAD" ? undefined : jpeg);
          return;
        }
        response.writeHead(error.code === "ENOENT" ? 404 : 500, { "Cache-Control": "no-store" });
        response.end(error.code === "ENOENT" ? "Not found." : "Unable to read the requested page.");
        if (error.code !== "ENOENT") console.error("Unable to serve page:", error);
        return;
      }
      response.writeHead(200, {
        "Content-Type": MIME_TYPES.get(path.extname(filePath).toLowerCase()),
        "Cache-Control": PROTECTED_PAGES.has(page) ? "no-store" : "no-cache"
      });
      response.end(request.method === "HEAD" ? undefined : contents);
    });
  });
}

if (require.main === module) {
  try {
    const server = createAppServer();
    const port = Number(process.env.PORT) || 3000;
    server.on("error", error => {
      if (error.code === "EADDRINUSE") {
        console.error(`Port ${port} is already in use. Stop the other site server or set PORT to a free port.`);
      } else {
        console.error("Unable to start the site server:", error.message);
      }
      process.exitCode = 1;
    });
    server.listen(port, () => {
      console.log(`Church programs site listening on port ${port}.`);
    });
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { createAppServer };
