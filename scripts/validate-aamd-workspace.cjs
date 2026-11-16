const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "dist/aamd-workspace.js"), "utf8");
const fixture = JSON.parse(fs.readFileSync(path.join(root, "dist/data/aamd-demo-task-bundle-v1.json"), "utf8"));
const subtle = {
  async digest(algorithm, bytes) {
    assert.strictEqual(String(algorithm).toUpperCase(), "SHA-256");
    const digest = crypto.createHash("sha256").update(Buffer.from(bytes)).digest();
    return digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength);
  },
};
const window = {
  crypto: { subtle },
  addEventListener() {},
};
vm.runInNewContext(source, {
  window,
  document: {},
  TextEncoder,
  Uint8Array,
  console,
}, { filename: "dist/aamd-workspace.js" });

const api = window.__AAMD_TEST__;
assert(api, "AAMD test API was not exposed");

const clone = (value) => JSON.parse(JSON.stringify(value));
const mustReject = (callback, pattern) => {
  assert.throws(callback, pattern);
};

async function main() {
  assert.strictEqual(api.validateBundle(fixture), fixture, "safe fixture must pass structural validation");
  assert.strictEqual(await api.verifyBundleHashes(fixture), true, "safe fixture hashes must recompute");

  const rawPayload = clone(fixture);
  rawPayload.tasks[0].evidence[0].raw_prompt = "forbidden";
  mustReject(() => api.validateBundle(rawPayload), /raw payload field/);

  const invalidPilot = clone(fixture);
  invalidPilot.mode = "pilot_import";
  invalidPilot.claim_bearing = true;
  mustReject(() => api.validateBundle(invalidPilot), /pilot_import.*claim_bearing=false/);

  const unblindedClaim = clone(fixture);
  unblindedClaim.mode = "claim_bearing_candidate";
  unblindedClaim.claim_bearing = true;
  unblindedClaim.proposal_delivery = {
    mode: "controlled_server_after_initial_lock",
    server_phase_gate: true,
    capability_receipt_hash: "a".repeat(64),
  };
  unblindedClaim.tasks.forEach((task) => { task.claim_bearing = true; });
  mustReject(() => api.validateBundle(unblindedClaim), /split은 blinded/);

  const embeddedClaim = clone(unblindedClaim);
  embeddedClaim.tasks.forEach((task) => { task.split = "blinded"; });
  mustReject(() => api.validateBundle(embeddedClaim), /embedded proposal/);

  const tamperedQueue = clone(fixture);
  [tamperedQueue.tasks[0], tamperedQueue.tasks[1]] = [tamperedQueue.tasks[1], tamperedQueue.tasks[0]];
  await assert.rejects(() => api.verifyBundleHashes(tamperedQueue), /codebook_hash|queue_hash/);

  const tamperedRecord = clone(fixture);
  tamperedRecord.tasks[0].question += " tampered";
  await assert.rejects(() => api.verifyBundleHashes(tamperedRecord), /record_hash/);

  const tamperedMask = clone(fixture);
  tamperedMask.visibility_mask.always_hidden.push("new_hidden_field");
  await assert.rejects(() => api.verifyBundleHashes(tamperedMask), /visibility_mask_hash/);

  assert.strictEqual(api.canRevealProposal({ initial: null, proposal_reveal: null }), false);
  assert.strictEqual(api.canRevealProposal({ initial: { event_hash: "x" }, proposal_reveal: null }), true);
  assert.strictEqual(api.canRevealProposal({ initial: { event_hash: "x" }, proposal_reveal: { event_hash: "y" } }), false);

  assert.strictEqual(api.isAllowedLabel(fixture.tasks[0], fixture.tasks[0].label_options[0].value), true);
  assert.strictEqual(api.isAllowedLabel(fixture.tasks[0], "out_of_codebook"), false);

  const canonicalA = api.canonicalJson({ z: 1, a: { y: 2, b: 3 } });
  const canonicalB = api.canonicalJson({ a: { b: 3, y: 2 }, z: 1 });
  assert.strictEqual(canonicalA, canonicalB, "canonical JSON must ignore object insertion order");

  const row = Object.fromEntries(api.csvColumns.map((column) => [column, column === "task_id" ? "task,\"quoted\"" : ""]));
  const csvA = api.csvExport([row]);
  const csvB = api.csvExport([clone(row)]);
  assert.strictEqual(csvA, csvB, "CSV projection must be deterministic");
  assert(csvA.includes('"task,""quoted"""'), "CSV cells must be quoted and escaped");
  assert.strictEqual(new Set(api.csvColumns).size, api.csvColumns.length, "CSV columns must be unique");
  const formulaRow = Object.fromEntries(api.csvColumns.map((column) => [column, column === "task_id" ? " =HYPERLINK(1)" : ""]));
  assert(api.csvExport([formulaRow]).includes("' =HYPERLINK(1)"), "CSV formula-like cells must be neutralized");

  console.log(JSON.stringify({
    ok: true,
    tasks: fixture.tasks.length,
    benchmarks: fixture.tasks.map((task) => task.benchmark),
    bundle_rejections_tested: 7,
    blind_first_gate: true,
    deterministic_serializers: ["canonical_json", "csv_projection"],
  }, null, 2));
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
