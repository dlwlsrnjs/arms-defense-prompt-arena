import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import worker, { __test } from "../worker/index.js";
import { MockD1 } from "./mock-d1.mjs";

const fixture = JSON.parse(await readFile(new URL("../fixtures/pilot-bundle.taxonomy-v3.synthetic.json", import.meta.url), "utf8"));
const fixtureTask = fixture.tasks[0];
const fixtureProposal = fixtureTask.llm_proposal;

test("read-only demo is an exact small projection of the synthetic V3 fixture", () => {
  const demo = __test.RCAT7_SYNTHETIC_DEMO;
  assert.equal(demo.source_bundle_id, fixture.bundle_id);
  assert.equal(demo.task_id, fixtureTask.task_id);
  assert.equal(demo.protocol_version, fixture.protocol_version);
  assert.equal(demo.codebook_version, fixture.codebook_version);
  assert.deepEqual(
    demo.human_reviewed_axes,
    fixtureProposal.reviewed_axes.map(({ axis, code }) => ({ axis, code })),
  );
  assert.deepEqual(
    demo.runtime_locked_axes,
    __test.RCAT7_TAXONOMY.runtime_locked_axes.map((axis) => ({ axis, code: fixtureTask.locked_axes[axis].code })),
  );
  assert.deepEqual(
    {
      synthetic: demo.synthetic,
      read_only: demo.read_only,
      persisted: demo.persisted,
      active: demo.active,
      claim_bearing: demo.claim_bearing,
    },
    { synthetic: true, read_only: true, persisted: false, active: false, claim_bearing: false },
  );
});

test("rendered page exposes the demo but leaves no build placeholders", () => {
  const page = __test.htmlPage();
  assert.doesNotMatch(page, /__RCAT7_(?:TAXONOMY|SYNTHETIC_DEMO)_JSON__/);
  assert.match(page, /READ-ONLY SYNTHETIC DEMO/);
  assert.match(page, /D1 미저장 · 비활성 · 배정 불가 · 논문 claim 제외/);
  assert.match(page, /aamd-taxonomy-v3-synthetic-pilot/);
  const script = page.match(/<script>([\s\S]*)<\/script>/)?.[1];
  assert.ok(script, "inline application script is present");
  assert.doesNotThrow(() => new Function(script));
});

test("empty D1 dashboard stays empty and never reports the preview as a bundle", async () => {
  const env = {
    DB: new MockD1(),
    AAMD_RECEIPT_HMAC_KEY: "test-only-receipt-key-32-characters-minimum",
    AAMD_BOOTSTRAP_ADMIN_IDS: "",
    AAMD_BOOTSTRAP_ADMIN_EMAILS: "",
  };
  const response = await worker.fetch(new Request("https://workspace.example/api/dashboard", {
    headers: {
      "oai-authenticated-user-id": "demo-contract-user",
      "oai-authenticated-user-email": "demo-contract@example.test",
    },
  }), env, { waitUntil() {} });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body.bundles, []);
  assert.equal(JSON.stringify(body).includes(fixture.bundle_id), false);
});
