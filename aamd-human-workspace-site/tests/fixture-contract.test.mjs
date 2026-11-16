import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { installWebApiPolyfill } from "./web-api-polyfill.mjs";

installWebApiPolyfill();
const { __test } = await import("../worker/index.js");
const fixtureUrl = new URL("../fixtures/pilot-bundle.synthetic.json", import.meta.url);
const bundle = JSON.parse(await readFile(fixtureUrl, "utf8"));
const validated = __test.validateBundle(bundle);
const task = validated.tasks[0];

assert.equal(task.llm_proposal.provenance.model_id, "Qwen/Qwen2.5-VL-32B-Instruct");
assert.equal(task.llm_proposal.provenance.parameters, "32B");
assert.equal(task.llm_proposal.provenance.model_revision_status, "candidate_needs_G0_attestation");

const record = {
  benchmark: task.benchmark,
  record_handle: task.record_handle,
  title: task.title,
  question: task.question,
  instructions: task.instructions,
  evidence: task.evidence,
  label_options: task.label_options,
};
const mask = {
  schema_version: 2,
  strategy: "abstract-evidence-plus-frozen-llm-proposal",
  forbidden: ["raw_payload", "raw_prompt", "attack_text", "harmful_request", "target_response", "outcome", "ground_truth", "system_prompt"],
  visible: ["benchmark", "record_handle", "title", "question", "instructions", "evidence", "label_options", "llm_proposal"],
};
const queue = [{ ordinal: 0, task_id: task.task_id, record_handle: task.record_handle, record_hash: task.record_hash }];

assert.equal(await __test.sha256Hex(record), task.record_hash);
assert.equal(await __test.sha256Hex(mask), bundle.visibility_mask_hash);
assert.equal(await __test.sha256Hex(queue), bundle.queue_hash);
console.log("Synthetic 32B-provenance fixture contract passed");
