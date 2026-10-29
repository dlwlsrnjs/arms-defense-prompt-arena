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

const htmlIds = [...html.matchAll(/\bid="([A-Za-z][\w:-]*)"/g)].map((match) => match[1]);
const duplicateIds = htmlIds.filter((id, index) => htmlIds.indexOf(id) !== index);
if (duplicateIds.length) fail(`duplicate HTML ids: ${[...new Set(duplicateIds)].join(", ")}`);

const referencedIds = [...js.matchAll(/\$\("#([A-Za-z][\w:-]*)"\)/g)].map((match) => match[1]);
const missingIds = [...new Set(referencedIds)].filter((id) => !htmlIds.includes(id));
if (missingIds.length) fail(`app.js references missing HTML ids: ${missingIds.join(", ")}`);

for (const match of html.matchAll(/(?:href|src)="\.\/([^"#?]+)"/g)) {
  const asset = path.join(dist, match[1]);
  if (!fs.existsSync(asset)) fail(`missing relative asset: ${match[1]}`);
}

if (!Array.isArray(status.targets) || status.targets.length !== 3) {
  fail("arena-status.json must describe exactly three targets");
}
if (traces.schema_version !== 1 || !Array.isArray(traces.rounds) || traces.rounds.length !== 5) {
  fail("memduel-traces.json must contain schema v1 and five rounds");
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
  replay_rounds: traces.rounds.length,
}, null, 2));
