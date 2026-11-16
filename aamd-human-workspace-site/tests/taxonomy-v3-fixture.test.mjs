import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { installWebApiPolyfill } from "./web-api-polyfill.mjs";

installWebApiPolyfill();
const { __test } = await import("../worker/index.js");
const fixtureUrl = new URL("../fixtures/pilot-bundle.taxonomy-v3.synthetic.json", import.meta.url);
const bundle = JSON.parse(await readFile(fixtureUrl, "utf8"));
const validated = __test.validateBundle(bundle);
const task = validated.tasks[0];
const humanAxes = ["adaptation_mechanism", "consumed_response_signal", "search_action", "semantic_linkage"];
const lockedAxes = ["memory_source_scope", "memory_operation", "evidence_provenance", "dialogue_horizon"];

assert.equal(__test.RCAT7_TAXONOMY.taxonomy_id, "aamd-rcat-7-v1.1");
assert.equal(__test.RCAT7_TAXONOMY.taxonomy_version, "1.1.0");
assert.equal(__test.RCAT7_TAXONOMY.taxonomy_hash, "2f8512333c90888aa640e8432ec262cdd452adbae3d1e8df5c96c5654a5c816c");
assert.deepEqual(__test.RCAT7_TAXONOMY.human_reviewed_axes, humanAxes);
assert.deepEqual(__test.RCAT7_TAXONOMY.runtime_locked_axes, lockedAxes);
assert.deepEqual(__test.RCAT7_TAXONOMY.required_axes, [...humanAxes, ...lockedAxes]);
const sentinels = new Set(["none", "uncertain", "unmapped"]);
const nonSentinelCount = (axis) => Object.keys(__test.RCAT7_TAXONOMY.axes[axis].codes).filter((code) => !sentinels.has(code)).length;
assert.deepEqual(Object.fromEntries(__test.RCAT7_TAXONOMY.required_axes.map((axis) => [axis, nonSentinelCount(axis)])), {
  adaptation_mechanism: 7,
  consumed_response_signal: 10,
  search_action: 4,
  semantic_linkage: 2,
  memory_source_scope: 6,
  memory_operation: 5,
  evidence_provenance: 3,
  dialogue_horizon: 5,
});
const renderedPage = __test.htmlPage();
assert.doesNotMatch(renderedPage, /__RCAT7_TAXONOMY_JSON__/);
const renderedScript = renderedPage.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(renderedScript);
assert.doesNotThrow(() => new Function(renderedScript[1]));

assert.equal(validated.schema_version, 2);
assert.equal(validated.protocol_version, "aamd-llm-first-taxonomy-review-v3");
assert.equal(validated.codebook_version, "aamd-rcat-7-v1.1");
assert.equal(task.taxonomy_id, __test.RCAT7_TAXONOMY.taxonomy_id);
assert.equal(task.taxonomy_version, __test.RCAT7_TAXONOMY.taxonomy_version);
assert.equal(task.taxonomy_hash, __test.RCAT7_TAXONOMY.taxonomy_hash);
assert.deepEqual(Object.keys(task.locked_axes), lockedAxes);
assert.deepEqual(task.llm_proposal.reviewed_axes.map((entry) => entry.axis), humanAxes);
assert.equal(task.llm_proposal.provenance.model_id, "Qwen/Qwen2.5-VL-32B-Instruct");
assert.equal(task.llm_proposal.provenance.parameters, "32B");
assert.equal(task.llm_proposal.provenance.labeler_config_id, "aamd-llm-first-labeler-32b-v3");
assert.equal(task.llm_proposal.provenance.taxonomy_hash, task.taxonomy_hash);
assert.equal(task.locked_axes.evidence_provenance.code, "RCAT7.PROVENANCE.DIRECT_RESPONSE_TO_SUCCESSOR_RECEIPT");
assert.equal(task.llm_proposal.benign_confound.code, "RCAT7.CONFOUND.ACCESSIBILITY_OR_FORMAT_CONVERSION");
assert.ok(task.llm_proposal.benign_confound.evidence_handles.length > 0);
assert.equal(await __test.sha256Hex(task.locked_axes), task.locked_axes_hash);
assert.equal(task.llm_proposal.locked_axes_hash, task.locked_axes_hash);

const record = {
  benchmark: task.benchmark,
  record_handle: task.record_handle,
  title: task.title,
  question: task.question,
  instructions: task.instructions,
  evidence: task.evidence,
  taxonomy_id: task.taxonomy_id,
  taxonomy_version: task.taxonomy_version,
  taxonomy_hash: task.taxonomy_hash,
  locked_axes: task.locked_axes,
  locked_axes_hash: task.locked_axes_hash,
};
const mask = {
  schema_version: 3,
  strategy: "abstract-evidence-plus-frozen-taxonomy-proposal",
  forbidden: ["raw_payload", "raw_prompt", "attack_text", "harmful_request", "target_response", "attack_method", "outcome", "ground_truth", "system_prompt"],
  visible: ["benchmark", "record_handle", "title", "question", "instructions", "evidence", "taxonomy_id", "taxonomy_version", "taxonomy_hash", "locked_axes", "locked_axes_hash", "llm_proposal"],
};
const queue = [{ ordinal: 0, task_id: task.task_id, record_handle: task.record_handle, record_hash: task.record_hash }];
assert.equal(await __test.sha256Hex(record), task.record_hash);
assert.equal(await __test.sha256Hex(mask), validated.visibility_mask_hash);
assert.equal(await __test.sha256Hex(queue), validated.queue_hash);

for (const [name, mutate, code] of [
  ["task taxonomy", (copy) => { copy.tasks[0].taxonomy_hash = "0".repeat(64); }, "taxonomy_contract_mismatch"],
  ["proposal taxonomy", (copy) => { copy.tasks[0].llm_proposal.provenance.taxonomy_hash = "0".repeat(64); }, "taxonomy_contract_mismatch"],
  ["reviewed cardinality", (copy) => { copy.tasks[0].llm_proposal.reviewed_axes.pop(); }, "taxonomy_axis_cardinality"],
  ["reviewed coverage", (copy) => { copy.tasks[0].llm_proposal.reviewed_axes[1] = JSON.parse(JSON.stringify(copy.tasks[0].llm_proposal.reviewed_axes[0])); }, "taxonomy_axis_coverage"],
  ["reviewed code", (copy) => { copy.tasks[0].llm_proposal.reviewed_axes[0].code = "RCAT7.MECHANISM.NOT_REGISTERED"; }, "invalid_taxonomy_code"],
  ["reviewed evidence", (copy) => { copy.tasks[0].llm_proposal.reviewed_axes[0].evidence_handles = []; }, "missing_category_evidence"],
  ["mapping consistency", (copy) => { copy.tasks[0].llm_proposal.mapping_status = "none"; }, "mapping_mechanism_mismatch"],
  ["labeler identity", (copy) => { copy.tasks[0].llm_proposal.provenance.labeler_config_id = "aamd-llm-first-labeler-32b-v2"; }, "labeler_contract_mismatch"],
  ["schema", (copy) => { copy.schema_version = 1; }, "schema_version"],
  ["proposal version", (copy) => { copy.tasks[0].llm_proposal.version = "offline-32b-rcat7-v0"; }, "proposal_version_mismatch"],
  ["proposal lock binding", (copy) => { copy.tasks[0].llm_proposal.locked_axes_hash = "f".repeat(64); }, "locked_axes_hash_mismatch"],
  ["proposal lock overwrite", (copy) => { copy.tasks[0].llm_proposal.locked_axes = copy.tasks[0].locked_axes; }, "unknown_field"],
  ["locked code", (copy) => { copy.tasks[0].locked_axes.evidence_provenance.code = "RCAT7.PROVENANCE.NOT_REGISTERED"; }, "invalid_locked_axis_code"],
  ["locked evidence", (copy) => { copy.tasks[0].locked_axes.evidence_provenance.evidence_handles = []; }, "missing_locked_evidence"],
  ["memory pair", (copy) => { copy.tasks[0].locked_axes.memory_operation.code = "none"; }, "memory_lock_mismatch"],
  ["mechanism confound", (copy) => { copy.tasks[0].llm_proposal.benign_confound.code = "RCAT7.CONFOUND.SCOPE_CLARIFICATION"; }, "confound_mechanism_mismatch"],
  ["confound evidence", (copy) => { copy.tasks[0].llm_proposal.benign_confound.evidence_handles = []; }, "missing_confound_evidence"],
]) {
  const invalid = JSON.parse(JSON.stringify(bundle));
  mutate(invalid);
  assert.throws(() => __test.validateBundle(invalid), (error) => error?.code === code, name);
}

console.log("Synthetic V3 RCAT-7 V1.1 fixture and negative contract tests passed");
