const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const dist = path.join(root, "dist");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const fail = (message) => {
  throw new Error(message);
};

const html = read("dist/index.html");
const js = read("dist/app.js");
const status = JSON.parse(read("dist/data/arena-status.json"));
const traces = JSON.parse(read("dist/data/memduel-traces.json"));
const adaptive = JSON.parse(read("dist/data/adaptive-scenarios.json"));

const htmlIds = [...html.matchAll(/\bid="([A-Za-z][\w:-]*)"/g)].map((match) => match[1]);
const duplicateIds = htmlIds.filter((id, index) => htmlIds.indexOf(id) !== index);
if (duplicateIds.length) fail(`duplicate HTML ids: ${[...new Set(duplicateIds)].join(", ")}`);

const referencedIds = [...js.matchAll(/\$\("#([A-Za-z][\w:-]*)"\)/g)].map((match) => match[1]);
const missingIds = [...new Set(referencedIds)].filter((id) => !htmlIds.includes(id));
if (missingIds.length) fail(`app.js references missing HTML ids: ${missingIds.join(", ")}`);

const viewPanels = [...html.matchAll(/data-view-panel="([a-z-]+)"/g)].map((match) => match[1]);
const viewTargets = [...html.matchAll(/data-view-target="([a-z-]+)"/g)].map((match) => match[1]);
const expectedViews = ["overview", "models", "arena", "results", "method"];
if (viewPanels.length !== expectedViews.length || expectedViews.some((view) => !viewPanels.includes(view))) {
  fail(`dashboard must expose exactly these five view panels: ${expectedViews.join(", ")}`);
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

for (const match of html.matchAll(/(?:href|src)="\.\/([^"#?]+)"/g)) {
  const asset = path.join(dist, match[1]);
  if (!fs.existsSync(asset)) fail(`missing relative asset: ${match[1]}`);
}

if (!Array.isArray(status.targets) || status.targets.length !== 3) {
  fail("arena-status.json must describe exactly three targets");
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
  "dist/data/arena-status.json",
  "dist/data/adaptive-scenarios.json",
  "dist/data/memduel-traces.json",
].map(read).join("\n");
const forbidden = [
  /\/home\//i,
  /\/data1\//i,
  /github_pat_/i,
  /ghp_[A-Za-z0-9]{20,}/,
  /sk-[A-Za-z0-9_-]{12,}/,
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
  duel_modes: ["open_memory", "blind_defense"],
}, null, 2));
