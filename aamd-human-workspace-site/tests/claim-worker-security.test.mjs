import assert from "node:assert/strict";
import { installWebApiPolyfill } from "./web-api-polyfill.mjs";

installWebApiPolyfill();

const worker = (await import("../worker/index.js")).default;
assert.equal(typeof worker?.fetch, "function", "worker must export default.fetch");

const ORIGIN = "https://workspace.example";
const IDENTITY = {
  "oai-authenticated-user-id": "researcher-001",
  "oai-authenticated-user-email": "researcher-001@example.test",
};

class PoisonD1 {
  constructor() { this.calls = 0; }
  fail() {
    this.calls += 1;
    throw new Error("D1 must not be touched before request security checks pass");
  }
  exec() { return this.fail(); }
  prepare() { return this.fail(); }
  batch() { return this.fail(); }
}

function request(path, { method = "GET", headers = {}, body } = {}) {
  return new Request(`${ORIGIN}${path}`, { method, headers, body });
}

async function invoke(req, env = {}) {
  return worker.fetch(req, env, { waitUntil() {} });
}

async function expectStatus(label, req, status, env = {}) {
  const response = await invoke(req, env);
  assert.equal(response.status, status, `${label}: ${await response.text()}`);
  return response;
}

async function test(label, fn) {
  try {
    await fn();
    console.log(`ok - ${label}`);
  } catch (error) {
    console.error(`not ok - ${label}`);
    throw error;
  }
}

await test("identity requires both trusted headers before D1", async () => {
  for (const headers of [
    {},
    { "oai-authenticated-user-id": IDENTITY["oai-authenticated-user-id"] },
    { "oai-authenticated-user-email": IDENTITY["oai-authenticated-user-email"] },
  ]) {
    const db = new PoisonD1();
    await expectStatus("missing identity", request("/api/me", { headers }), 401, { DB: db });
    assert.equal(db.calls, 0);
  }
});

await test("cross-origin and cross-site writes fail before D1", async () => {
  const attempts = [
    { ...IDENTITY, origin: "https://evil.example", "content-type": "application/json" },
    { ...IDENTITY, origin: ORIGIN, "sec-fetch-site": "cross-site", "content-type": "application/json" },
    { ...IDENTITY, "sec-fetch-site": "same-origin", "content-type": "application/json" },
  ];
  for (const headers of attempts) {
    const db = new PoisonD1();
    await expectStatus(
      "cross-origin write",
      request("/api/bootstrap", { method: "POST", headers, body: "{}" }),
      403,
      { DB: db },
    );
    assert.equal(db.calls, 0);
  }
});

await test("JSON content type is mandatory for writes", async () => {
  const db = new PoisonD1();
  await expectStatus(
    "non-JSON write",
    request("/api/bootstrap", {
      method: "POST",
      headers: { ...IDENTITY, origin: ORIGIN, "sec-fetch-site": "same-origin", "content-type": "text/plain" },
      body: "{}",
    }),
    415,
    { DB: db },
  );
  assert.equal(db.calls, 0);
});

await test("ordinary mutation body is limited to 64 KiB", async () => {
  const db = new PoisonD1();
  await expectStatus(
    "oversize mutation",
    request("/api/bootstrap", {
      method: "POST",
      headers: { ...IDENTITY, origin: ORIGIN, "sec-fetch-site": "same-origin", "content-type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(65536) }),
    }),
    413,
    { DB: db },
  );
  assert.equal(db.calls, 0);
});

await test("admin import body is limited to 1 MiB", async () => {
  const db = new PoisonD1();
  await expectStatus(
    "oversize import",
    request("/api/admin/import", {
      method: "POST",
      headers: { ...IDENTITY, origin: ORIGIN, "sec-fetch-site": "same-origin", "content-type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(1048576) }),
    }),
    413,
    { DB: db },
  );
  assert.equal(db.calls, 0);
});

await test("the worker has zero runtime AICA/upstream dependency", async () => {
  const originalFetch = globalThis.fetch;
  let outboundCalls = 0;
  globalThis.fetch = async () => {
    outboundCalls += 1;
    throw new Error("outbound fetch forbidden during an experiment");
  };
  try {
    const response = await invoke(request("/"), { DB: new PoisonD1() });
    assert.equal(response.status, 200);
    assert.equal(outboundCalls, 0);
    const body = await response.text();
    assert.doesNotMatch(body, /AAMD_(?:UPSTREAM|AICA)_(?:URL|TOKEN|KEY)/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

await test("HTML and API responses disable unsafe caching", async () => {
  const root = await invoke(request("/"), { DB: new PoisonD1() });
  assert.ok((root.headers.get("cache-control") || "").includes("no-store"));
  assert.match(root.headers.get("content-security-policy") || "", /default-src\s+'self'|default-src\s+'none'/);

  const api = await invoke(request("/api/me"), { DB: new PoisonD1() });
  assert.equal(api.status, 401);
  assert.ok((api.headers.get("cache-control") || "").includes("no-store"));
});

console.log("Claim-worker request security tests passed");
