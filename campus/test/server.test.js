const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { after, before, test } = require("node:test");
const { createAppServer } = require("../server");

const originalPassword = "original-test-password";
const replacementPassword = "replacement-test-password";
const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "campus-auth-"));
const authStorePath = path.join(temporaryDirectory, "credentials.json");
const server = createAppServer({
  adminEmail: "admin@example.com",
  adminPassword: originalPassword,
  authStorePath
});
let baseUrl;

before(async () => {
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise(resolve => server.close(resolve));
  fs.rmSync(temporaryDirectory, { recursive: true, force: true });
});

async function post(pathname, details, cookie) {
  return fetch(baseUrl + pathname, {
    method: "POST",
    headers: {
      Origin: baseUrl,
      "Content-Type": "application/json",
      ...(cookie ? { Cookie: cookie } : {})
    },
    body: JSON.stringify(details)
  });
}

test("protected pages are served only after server-side login", async () => {
  const initialRecord = fs.readFileSync(authStorePath, "utf8");
  assert.equal(initialRecord.includes(originalPassword), false);

  const blocked = await fetch(baseUrl + "/program-dashboard.html", { redirect: "manual" });
  assert.equal(blocked.status, 302);
  assert.match(blocked.headers.get("location"), /admin\.html\?returnTo=program-dashboard\.html/);

  const rejectedLogin = await post("/api/login", {
    email: "admin@example.com",
    password: "incorrect-password"
  });
  assert.equal(rejectedLogin.status, 401);

  const login = await post("/api/login", {
    email: "admin@example.com",
    password: originalPassword
  });
  assert.equal(login.status, 200);
  const cookie = login.headers.get("set-cookie").split(";")[0];
  assert.match(login.headers.get("set-cookie"), /HttpOnly/);
  assert.match(login.headers.get("set-cookie"), /SameSite=Strict/);

  const allowed = await fetch(baseUrl + "/program-dashboard.html", {
    headers: { Cookie: cookie }
  });
  assert.equal(allowed.status, 200);
  assert.match(await allowed.text(), /Program Dashboard/);
});

test("password changes save only a password hash and invalidate sessions", async () => {
  const login = await post("/api/login", {
    email: "admin@example.com",
    password: originalPassword
  });
  const cookie = login.headers.get("set-cookie").split(";")[0];
  const change = await post("/api/change-password", {
    currentPassword: originalPassword,
    newPassword: replacementPassword
  }, cookie);
  assert.equal(change.status, 200);

  const savedRecord = fs.readFileSync(authStorePath, "utf8");
  assert.equal(savedRecord.includes(originalPassword), false);
  assert.equal(savedRecord.includes(replacementPassword), false);
  assert.doesNotThrow(() => createAppServer({
    adminEmail: "admin@example.com",
    authStorePath
  }));

  const oldLogin = await post("/api/login", {
    email: "admin@example.com",
    password: originalPassword
  });
  assert.equal(oldLogin.status, 401);
  const newLogin = await post("/api/login", {
    email: "admin@example.com",
    password: replacementPassword
  });
  assert.equal(newLogin.status, 200);
});

test("server implementation and credential files are not publicly served", async () => {
  const serverSource = await fetch(baseUrl + "/server.js");
  assert.equal(serverSource.status, 404);
  const credentialFile = await fetch(baseUrl + "/.admin-credentials.json");
  assert.equal(credentialFile.status, 404);
  const loginPage = await fetch(baseUrl + "/admin.html");
  const loginMarkup = await loginPage.text();
  assert.equal(loginMarkup.includes("admin@example.com"), false);
  assert.equal(loginMarkup.includes(originalPassword), false);
});

test("site pages and all inline scripts are valid", async () => {
  const pageNames = fs.readdirSync(path.join(__dirname, ".."))
    .filter(name => name.endsWith(".html"));
  const faviconResponse = await fetch(baseUrl + "/church-logo.jpg");
  assert.equal(faviconResponse.status, 200);
  assert.match(faviconResponse.headers.get("content-type"), /^image\/jpeg/);

  for (const pageName of pageNames) {
    const pageSource = fs.readFileSync(path.join(__dirname, "..", pageName), "utf8");
    assert.match(pageSource, /<link rel="icon" href="church-logo\.jpg" type="image\/jpeg">/, `${pageName} should use the church logo as its browser tab icon`);
    const expectedStatus = ["preachers.html", "program-dashboard.html"].includes(pageName) ? 302 : 200;
    const route = "/" + encodeURIComponent(pageName);
    const response = await fetch(baseUrl + route, { redirect: "manual" });
    assert.equal(response.status, expectedStatus, `${pageName} should be served or protected`);

    for (const [index, script] of [...pageSource.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].entries()) {
      assert.doesNotThrow(
        () => new vm.Script(script[1], { filename: `${pageName} inline script ${index + 1}` }),
        `${pageName} inline script ${index + 1} should parse`
      );
    }

    for (const [, href] of pageSource.matchAll(/href="([^"]+)"/g)) {
      if (/^(?:[a-z]+:|#|\/\/)/i.test(href)) continue;
      const localTarget = decodeURIComponent(href.split(/[?#]/, 1)[0]);
      if (localTarget) {
        assert.ok(fs.existsSync(path.join(__dirname, "..", localTarget)), `${pageName} link should resolve: ${href}`);
      }
    }

    assert.match(pageSource, /<a href="https:\/\/www\.academia\.edu\/123429509\/Indirimbo_Zo_Guhimbaza_Imana_za_500_SDA_Church_500_"[^>]*>Songs of praise of God<\/a>/, `${pageName} should link to Songs of praise of God`);
    assert.match(pageSource, /<a href="https:\/\/bibiliya\.com\/"[^>]*>Holy bible<\/a>/, `${pageName} should link to the Holy Bible`);
  }
});
