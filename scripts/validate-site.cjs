const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const root = path.resolve(__dirname, "..");
const dist = path.join(root, "dist");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const fail = (message) => {
  throw new Error(message);
};

const html = read("dist/index.html");
const js = read("dist/app.js");
const memoryJs = read("dist/memory-explorer.js");
const aamdJs = read("dist/aamd-workspace.js");
const status = JSON.parse(read("dist/data/arena-status.json"));
const traces = JSON.parse(read("dist/data/memduel-traces.json"));
const adaptive = JSON.parse(read("dist/data/adaptive-scenarios.json"));
const memoryExplorer = JSON.parse(read("dist/data/memory-explorer-v1.json"));
const aamdDemo = JSON.parse(read("dist/data/aamd-demo-task-bundle-v1.json"));

const htmlIds = [...html.matchAll(/\bid="([A-Za-z][\w:-]*)"/g)].map((match) => match[1]);
const duplicateIds = htmlIds.filter((id, index) => htmlIds.indexOf(id) !== index);
if (duplicateIds.length) fail(`duplicate HTML ids: ${[...new Set(duplicateIds)].join(", ")}`);

const referencedIds = [...js.matchAll(/\$\("#([A-Za-z][\w:-]*)"\)/g)].map((match) => match[1]);
const missingIds = [...new Set(referencedIds)].filter((id) => !htmlIds.includes(id));
if (missingIds.length) fail(`app.js references missing HTML ids: ${missingIds.join(", ")}`);

const viewPanels = [...html.matchAll(/data-view-panel="([a-z-]+)"/g)].map((match) => match[1]);
const viewTargets = [...html.matchAll(/data-view-target="([a-z-]+)"/g)].map((match) => match[1]);
const expectedViews = ["overview", "models", "arena", "results", "memory", "aamd", "method"];
if (viewPanels.length !== expectedViews.length || expectedViews.some((view) => !viewPanels.includes(view))) {
  fail(`dashboard must expose exactly these seven view panels: ${expectedViews.join(", ")}`);
}
if (expectedViews.some((view) => !viewTargets.includes(view))) {
  fail("dashboard sidebar or CTA is missing a view target");
}
if (!html.includes('class="dashboard-sidebar"') || !html.includes('class="dashboard-main"')) {
  fail("dashboard must include a left navigation and a view container");
}
if (!js.includes("function initViewSwitcher()") || !js.includes('window.addEventListener("hashchange"')) {
  fail("app.js must initialize accessible hash-based dashboard navigation");
}
const memoryUiIds = [
  "memory-stat-slots", "memory-stat-episodes", "memory-stat-transitions", "memory-stat-reviews",
  "memory-pack-id", "memory-load-state", "memory-record-type", "memory-filter-family",
  "memory-filter-category", "memory-filter-strategy", "memory-filter-decision", "memory-filter-search",
  "memory-record-list", "memory-detail-fields", "memory-review-form", "memory-review-status",
  "memory-review-invariant", "memory-review-adaptation", "memory-review-benign", "memory-review-task",
  "memory-review-note", "memory-export-json", "memory-export-csv", "memory-clear-reviews",
  "memory-limitations-list",
];
const missingMemoryUiIds = memoryUiIds.filter((id) => !htmlIds.includes(id));
if (missingMemoryUiIds.length) fail(`memory evidence lab is missing UI ids: ${missingMemoryUiIds.join(", ")}`);
if (!memoryJs.includes("localStorage") || !memoryJs.includes("window.confirm") || !memoryJs.includes("storage_scope: \"local_browser_only\"")) {
  fail("memory evidence reviews must be local-only, exportable, and confirmed before clearing");
}
for (const caveat of ["3B LEGACY ONLY", "PAYLOAD-FREE", "NOT OFFICIAL ARMS", "SURVIVOR-BIASED SLOTS", "TRANSITIONS INFERRED"]) {
  if (!html.includes(caveat)) fail(`memory evidence lab is missing caveat: ${caveat}`);
}

const aamdUiIds = [
  "aamd-workspace", "aamd-mode-banner", "aamd-mode-badge", "aamd-reviewer", "aamd-start-session",
  "aamd-bundle-import", "aamd-bundle-hash", "aamd-queue-hash", "aamd-codebook-hash",
  "aamd-visibility-mask-hash", "aamd-task-queue", "aamd-task-split", "aamd-initial-form",
  "aamd-initial-label", "aamd-initial-evidence", "aamd-initial-readaptation", "aamd-reveal-proposal",
  "aamd-proposal-content", "aamd-final-form", "aamd-final-disposition", "aamd-final-readaptation",
  "aamd-second-reviewer", "aamd-second-label", "aamd-second-readaptation", "aamd-adjudicator",
  "aamd-adjudicated-label", "aamd-adjudication-readaptation",
  "aamd-adjudication-no-gold", "aamd-export-json", "aamd-export-csv",
];
const missingAamdUiIds = aamdUiIds.filter((id) => !htmlIds.includes(id));
if (missingAamdUiIds.length) fail(`AAMD workspace is missing UI ids: ${missingAamdUiIds.join(", ")}`);
const aamdCacheBlock = aamdJs.match(/const ids = \[([\s\S]*?)\];/);
if (!aamdCacheBlock) fail("AAMD workspace must declare its cached element ids");
const cachedAamdIds = [...aamdCacheBlock[1].matchAll(/"(aamd-[^"]+)"/g)].map((match) => match[1]);
const missingCachedAamdIds = cachedAamdIds.filter((id) => !htmlIds.includes(id));
if (missingCachedAamdIds.length) fail(`AAMD script caches missing HTML ids: ${missingCachedAamdIds.join(", ")}`);
for (const contract of [
  "excluded_demo", "pilot_import", "claim_bearing_candidate", "fixed_manifest_order",
  "controlled_server_after_initial_lock", "ui_phase_gate_only_not_authoritative",
  "human_initial_locked", "llm_proposal_revealed", "human_final_locked", "independent_second_vote_locked",
]) {
  if (!aamdJs.includes(contract)) fail(`AAMD workspace is missing protocol contract: ${contract}`);
}
if (!aamdJs.includes("localStorage") || !aamdJs.includes("canonicalJson")
  || !aamdJs.includes("verifyBundleHashes") || !aamdJs.includes("validateEventChain")) {
  fail("AAMD workspace must preserve local drafts, canonical exports, and hash/event-chain validation");
}
const benchmarkTabs = [...html.matchAll(/data-aamd-view="(ALL|T[1-4])"/g)].map((match) => match[1]);
if (benchmarkTabs.join(",") !== "ALL,T1,T2,T3,T4") fail("AAMD workspace must expose ALL and T1–T4 task views");

for (const match of html.matchAll(/(?:href|src)="\.\/([^"#?]+)"/g)) {
  const asset = path.join(dist, match[1]);
  if (!fs.existsSync(asset)) fail(`missing relative asset: ${match[1]}`);
}

if (!Array.isArray(status.targets) || status.targets.length !== 3) {
  fail("arena-status.json must describe exactly three targets");
}
const measuredTargets = status.targets.filter((target) => target.post_warm_asr);
if (measuredTargets.length && measuredTargets.length !== status.targets.length) {
  fail("post-warm publication must be atomic across all three targets");
}
if (measuredTargets.length) {
  const expectedBudgets = ["1", "3", "5", "10", "30"];
  if (status.ready_targets !== 3) fail("all measured targets must pass checkpoint and memory gates");
  if (!status.warm_gate || status.warm_gate.version !== "public-v2-gate-v2") {
    fail("measured results must name the public-v2 warm gate version");
  }
  if (!status.runtime_profile || !status.runtime_profile.version) {
    fail("measured results must expose their runtime precision profile");
  }
  for (const target of measuredTargets) {
    const report = target.post_warm_asr;
    const budgetKeys = Object.keys(report.budgets || {}).sort((a, b) => Number(a) - Number(b));
    if (!target.checkpoint_ready || !target.memory_ready) fail(`${target.id} is not publication-ready`);
    if (!target.memory || target.memory.sha256 !== report.memory_sha256) {
      fail(`${target.id} memory hash does not match its ASR report`);
    }
    if (report.evaluation_view !== "sealed_eval_quick" || report.frozen_memory !== true || report.independent_runs !== true) {
      fail(`${target.id} must use independent frozen-memory sealed_eval_quick runs`);
    }
    if (budgetKeys.join(",") !== expectedBudgets.join(",")) {
      fail(`${target.id} must report budgets ${expectedBudgets.join(",")}`);
    }
    for (const budget of expectedBudgets) {
      const metric = report.budgets[budget];
      const asr = metric.strict_target_call_asr;
      if (metric.n !== 116 || typeof asr !== "number" || asr < 0 || asr > 1) {
        fail(`${target.id} budget ${budget} has an invalid sample count or ASR`);
      }
      if (!Number.isInteger(metric.successes) || metric.successes < 0 || metric.successes > metric.n) {
        fail(`${target.id} budget ${budget} has an invalid success count`);
      }
      const byDataset = metric.by_dataset || {};
      const jailbreakbench = byDataset.jailbreakbench || {};
      const strongreject = byDataset.strongreject || {};
      if (jailbreakbench.n !== 55 || strongreject.n !== 61) {
        fail(`${target.id} budget ${budget} must preserve the 55/61 dataset split`);
      }
    }
  }
}
if (!html.includes('id="mode-open-memory"') || !html.includes('id="mode-blind-defense"')) {
  fail("adaptive duel must expose OPEN MEMORY and BLIND DEFENSE controls");
}
if (!js.includes('fetch("./data/adaptive-scenarios.json"') || !js.includes('protocol: "adaptive-live-duel-v1"')) {
  fail("app.js must load the adaptive scenario contract and render adaptive-live-duel-v1 envelopes");
}
if (adaptive.schema_version !== 1 || adaptive.mode !== "closed-loop-adaptive-safe-simulation") {
  fail("adaptive-scenarios.json must declare the closed-loop adaptive safe simulation schema");
}
if (!Array.isArray(adaptive.scenarios) || adaptive.scenarios.length !== 5) {
  fail("adaptive-scenarios.json must contain exactly five scenarios");
}

const validControls = new Set([
  "instruction_hierarchy", "untrusted_multimodal", "intent_first",
  "transformation_resistance", "safe_alternative", "benign_preservation",
]);
const requiredScenarioKeys = [
  "id", "label", "category", "difficulty", "attack_budget", "initial_strategy",
  "image_summary", "required_control_keys", "variants", "utility_probe",
];
for (const scenario of adaptive.scenarios) {
  const missing = requiredScenarioKeys.filter((key) => scenario[key] === undefined || scenario[key] === null);
  if (missing.length) fail(`${scenario.id || "unknown scenario"} missing keys: ${missing.join(", ")}`);
  if (!Array.isArray(scenario.required_control_keys) || !scenario.required_control_keys.length) {
    fail(`${scenario.id} must require at least one defense control`);
  }
  if (scenario.required_control_keys.some((key) => !validControls.has(key))) {
    fail(`${scenario.id} contains an unknown defense control`);
  }
  if (!Array.isArray(scenario.variants) || scenario.variants.length < 2) {
    fail(`${scenario.id} needs at least two safe adaptive variants`);
  }
  for (const variant of scenario.variants) {
    if (!variant.focus || !variant.label || !variant.detail) fail(`${scenario.id} has an incomplete variant`);
  }
}

if (traces.schema_version !== 1 || !Array.isArray(traces.rounds) || traces.rounds.length !== 5) {
  fail("the compatibility trace fixture must contain schema v1 and five adaptive seeds");
}

if (!memoryExplorer.summary || typeof memoryExplorer.summary !== "object") {
  fail("memory-explorer-v1.json must include a top-level summary object");
}
if (!memoryExplorer.counts || typeof memoryExplorer.counts !== "object") {
  fail("memory-explorer-v1.json must include a top-level counts object");
}
if (!Array.isArray(memoryExplorer.limitations) || !memoryExplorer.limitations.length) {
  fail("memory-explorer-v1.json must include explicit limitations");
}
for (const collection of ["slots", "episodes", "transitions"]) {
  if (!Array.isArray(memoryExplorer[collection])) fail(`memory-explorer-v1.json ${collection} must be an array`);
}
if (memoryExplorer.slots.length !== 101 || memoryExplorer.episodes.length !== 220 || memoryExplorer.transitions.length !== 307) {
  fail("memory explorer must preserve the audited 101 slots / 220 episodes / 307 transitions counts");
}
const forbiddenMemoryKeys = new Set([
  "behavior_id", "behavior_text", "harmful_prompt", "raw_prompt", "target_response", "judge_reason",
  "reflection", "attack_payload", "user_text", "assistant_text",
]);
const scanMemoryKeys = (value, location = "memoryExplorer") => {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => scanMemoryKeys(item, `${location}[${index}]`));
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    if (forbiddenMemoryKeys.has(key.toLowerCase())) fail(`${location} exposes forbidden payload field: ${key}`);
    scanMemoryKeys(item, `${location}.${key}`);
  }
};
scanMemoryKeys(memoryExplorer);

const stableClone = (value) => {
  if (Array.isArray(value)) return value.map(stableClone);
  if (value && typeof value === "object") {
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = stableClone(value[key]);
      return result;
    }, {});
  }
  return value;
};
const canonicalHash = (value) => crypto.createHash("sha256")
  .update(JSON.stringify(stableClone(value)), "utf8")
  .digest("hex");
const publicTaskIdentity = (task) => ({
  task_id: task.task_id,
  benchmark: task.benchmark,
  benchmark_name: task.benchmark_name,
  record_handle: task.record_handle,
  split: task.split,
  claim_bearing: task.claim_bearing,
  title: task.title,
  question: task.question,
  instructions: task.instructions,
  evidence: task.evidence,
  label_options: task.label_options,
});
const codebookIdentity = (tasks) => tasks.map((task) => ({
  benchmark: task.benchmark,
  label_options: task.label_options,
}));
const queueIdentity = (tasks) => tasks.map((task, index) => ({
  assignment_ordinal: index + 1,
  task_id: task.task_id,
  benchmark: task.benchmark,
  record_handle: task.record_handle,
  record_hash: task.record_hash,
  split: task.split,
  claim_bearing: task.claim_bearing,
}));
const aamdForbiddenKeys = new Set([
  ...forbiddenMemoryKeys,
  "raw_dialogue", "raw_response", "attack_method", "outcome", "real_split", "split_name", "true_split",
]);
const scanAamdKeys = (value, location = "aamdDemo") => {
  if (typeof value === "string") {
    if (value.length > 12000) fail(`${location} exceeds the public string limit`);
    return;
  }
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => scanAamdKeys(item, `${location}[${index}]`));
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    if (aamdForbiddenKeys.has(key.toLowerCase())) fail(`${location} exposes forbidden payload field: ${key}`);
    scanAamdKeys(item, `${location}.${key}`);
  }
};
scanAamdKeys(aamdDemo);
if (aamdDemo.schema_version !== 1 || aamdDemo.mode !== "excluded_demo" || aamdDemo.claim_bearing !== false) {
  fail("checked-in AAMD bundle must remain an excluded, non-claim-bearing schema-v1 demo");
}
if (!aamdDemo.safety_boundary || aamdDemo.safety_boundary.payload_free !== true
  || aamdDemo.safety_boundary.raw_harmful_prompt_present !== false
  || aamdDemo.safety_boundary.raw_target_response_present !== false
  || aamdDemo.safety_boundary.judge_rationale_present !== false) {
  fail("checked-in AAMD bundle must declare the payload-free safety boundary");
}
if (aamdDemo.proposal_delivery.mode !== "embedded_fixture_demo_only"
  || aamdDemo.proposal_delivery.server_phase_gate !== false) {
  fail("checked-in AAMD proposals must be explicit demo-only embedded fixtures");
}
if (!Array.isArray(aamdDemo.tasks) || aamdDemo.tasks.length !== 4
  || aamdDemo.tasks.map((task) => task.benchmark).join(",") !== "T1,T2,T3,T4") {
  fail("checked-in AAMD bundle must contain one ordered payload-free T1–T4 demo task");
}
for (const task of aamdDemo.tasks) {
  if (task.claim_bearing !== false || task.split !== "excluded_pilot") {
    fail(`${task.task_id} must remain outside claim-bearing splits`);
  }
  if (canonicalHash(publicTaskIdentity(task)) !== task.record_hash) {
    fail(`${task.task_id} record hash does not recompute`);
  }
}
if (canonicalHash(codebookIdentity(aamdDemo.tasks)) !== aamdDemo.codebook_hash) {
  fail("AAMD demo codebook hash does not recompute");
}
if (canonicalHash(queueIdentity(aamdDemo.tasks)) !== aamdDemo.assignment.queue_hash) {
  fail("AAMD demo queue hash does not recompute");
}
if (canonicalHash(aamdDemo.visibility_mask) !== aamdDemo.visibility_mask_hash) {
  fail("AAMD demo visibility-mask hash does not recompute");
}
if (!aamdDemo.visibility_mask.masked_until_initial_lock.includes("llm_proposal")
  || !aamdDemo.visibility_mask.always_hidden.includes("real_split")) {
  fail("AAMD demo visibility mask must hide the proposal phase and real split");
}

const requiredRoundKeys = [
  "id", "label", "category", "difficulty", "attack_budget", "memory", "pipeline",
  "vlm_input", "required_controls", "utility_probe", "baseline", "explanation",
];
for (const round of traces.rounds) {
  const missing = requiredRoundKeys.filter((key) => round[key] === undefined || round[key] === null);
  if (missing.length) fail(`${round.id || "unknown round"} missing keys: ${missing.join(", ")}`);
  if (!Array.isArray(round.pipeline) || round.pipeline.length < 4) fail(`${round.id} needs four pipeline stages`);
  if (!String(round.vlm_input.user_text || "").includes("[REDACTED]")) {
    fail(`${round.id} public user_text must preserve a [REDACTED] boundary`);
  }
}

const publicFiles = [
  "README.md",
  "dist/index.html",
  "dist/styles.css",
  "dist/app.js",
  "dist/memory-explorer.js",
  "dist/aamd-workspace.js",
  "dist/data/arena-status.json",
  "dist/data/adaptive-scenarios.json",
  "dist/data/memduel-traces.json",
  "dist/data/memory-explorer-v1.json",
  "dist/data/aamd-demo-task-bundle-v1.json",
].map(read).join("\n");
const forbidden = [
  /\/home\//i,
  /\/data1\//i,
  /github_pat_/i,
  /ghp_[A-Za-z0-9]{20,}/,
  /(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{12,}/,
  /BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY/,
];
for (const pattern of forbidden) {
  if (pattern.test(publicFiles)) fail(`public content matched forbidden pattern ${pattern}`);
}

console.log(JSON.stringify({
  ok: true,
  html_ids: htmlIds.length,
  js_id_references: new Set(referencedIds).size,
  targets: status.targets.length,
  dashboard_views: viewPanels,
  adaptive_scenarios: adaptive.scenarios.length,
  compatibility_seeds: traces.rounds.length,
  memory_evidence: {
    slots: memoryExplorer.slots.length,
    episodes: memoryExplorer.episodes.length,
    transitions: memoryExplorer.transitions.length,
  },
  aamd_workspace: {
    mode: aamdDemo.mode,
    claim_bearing: aamdDemo.claim_bearing,
    tasks: aamdDemo.tasks.length,
    benchmarks: aamdDemo.tasks.map((task) => task.benchmark),
    hashes_recomputed: ["record", "codebook", "queue", "visibility_mask"],
  },
  duel_modes: ["open_memory", "blind_defense"],
}, null, 2));
