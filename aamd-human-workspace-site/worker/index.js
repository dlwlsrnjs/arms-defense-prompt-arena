const API_VERSION = "aamd-claim-workspace-v2";
const LLM_FIRST_PROTOCOL = "aamd-llm-first-human-review-v2";
const LLM_FIRST_LABELER = Object.freeze({
  labeler_config_id: "aamd-llm-first-labeler-32b-v1",
  model_id: "Qwen/Qwen2.5-VL-32B-Instruct",
  parameters: "32B",
  model_revision: "7cfb30d71a1f4f49a57592323337a4a4727301da",
  prompt_template_hash: "cfad4c64a0f0afa97db52b779e29f86220df6fd8b6a7fb6f5989f1d8bf27eab2",
  decoding_config_hash: "3725e1f6f82d2a4b469375f668431fd7c406314f0e3b57ac6d02b7af9e887add",
  seed: 20261116,
});
// Fail closed until a separately generated G0 manifest is reviewed and its exact
// SHA-256 is committed in a new source version. Bundle-authored status text is
// never sufficient to enable claim-bearing collection.
const TRUSTED_LABELER_G0_ATTESTATION_SHA256 = null;
// This second commitment binds every proposal and source hash in one exact
// canonical claim bundle. It prevents reuse of a valid model attestation on an
// unreviewed proposal. A future claim-enabled source version must set both.
const TRUSTED_LABELER_CLAIM_BUNDLE_SHA256 = null;
const LEGACY_PROTOCOLS = new Set(["aamd-v1", "aamd-human-protocol-v1", "aamd-annotation-workspace-v1"]);
const SUPPORTED_PROTOCOLS = new Set([...LEGACY_PROTOCOLS, LLM_FIRST_PROTOCOL]);
const MAX_JSON_BYTES = 64 * 1024;
const MAX_IMPORT_BYTES = 1024 * 1024;
const ROLES = ["admin", "primary", "secondary", "adjudicator"];
const REVIEW_ROLES = ["primary", "secondary", "adjudicator"];
const BENCHMARKS = ["T1", "T2", "T3", "T4"];
const STAGES = ["initial", "reveal", "final", "secondary", "adjudicate"];
const LLM_FIRST_STAGES = ["final", "secondary", "adjudicate"];
const FINAL_DECISIONS = ["accept", "retain_human", "edit_after_proposal", "reject_proposal", "abstain_after_proposal"];
const LLM_FIRST_DECISIONS = ["accept", "edit", "reject", "abstain"];
const RESOLUTIONS = ["agreement", "resolved", "pending", "disagreement", "escalated"];
const T4_FIELDS = ["defense_invariant", "benign_exception", "predicted_readaptation", "evaluation_probe"];
const FORBIDDEN_KEYS = new Set([
  "raw_payload", "raw_payloads", "raw_prompt", "raw_attack_prompt", "attack_prompt",
  "attack_text", "harmful_prompt", "harmful_request", "harmful_request_text",
  "target_response", "raw_target_response", "attack_method", "outcome",
  "future_outcome", "ground_truth", "gold_label", "real_split", "hidden_split",
  "judge_rationale", "system_prompt", "secret", "api_token",
]);

function isLlmFirstProtocol(protocolVersion) { return protocolVersion === LLM_FIRST_PROTOCOL; }
function stageSequence(protocolVersion) { return isLlmFirstProtocol(protocolVersion) ? LLM_FIRST_STAGES : STAGES; }
function protocolField(value) {
  const protocol = idField(value, "protocol_version");
  if (!SUPPORTED_PROTOCOLS.has(protocol)) throw new HttpError(400, "unsupported_protocol", "protocol_version is not supported; use a registered legacy protocol or " + LLM_FIRST_PROTOCOL);
  return protocol;
}

class HttpError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

const BODY_CACHE = new WeakMap();

function canonicalize(value) {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonicalize(value[key])).join(",") + "}";
}

async function sha256Hex(value) {
  const input = new TextEncoder().encode(typeof value === "string" ? value : canonicalize(value));
  const digest = await crypto.subtle.digest("SHA-256", input);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmacHex(secret, value) {
  if (typeof secret !== "string" || secret.length < 32) throw new HttpError(503, "receipt_key_unavailable", "AAMD_RECEIPT_HMAC_KEY must be configured with at least 32 characters");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(typeof value === "string" ? value : canonicalize(value)));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function exactKeys(value, required, optional = [], name = "object") {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400, "invalid_shape", name + " must be an object");
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw new HttpError(400, "unknown_field", name + "." + key + " is not allowed");
  for (const key of required) if (!(key in value)) throw new HttpError(400, "missing_field", name + "." + key + " is required");
}

function textField(value, name, min = 1, max = 4000) {
  if (typeof value !== "string") throw new HttpError(400, "invalid_field", name + " must be a string");
  const normalized = value.trim();
  if (normalized.length < min || normalized.length > max || normalized.includes("\0")) throw new HttpError(400, "invalid_field", name + " must contain " + min + "-" + max + " safe characters");
  return normalized;
}

function idField(value, name, max = 160) {
  const id = textField(value, name, 1, max);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@+\-]*$/.test(id)) throw new HttpError(400, "invalid_identifier", name + " has an invalid identifier format");
  return id;
}

function hashField(value, name) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new HttpError(400, "invalid_hash", name + " must be lowercase SHA-256 hex");
  return value;
}

function isoTimestampField(value, name) {
  const timestamp = textField(value, name, 20, 40);
  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== timestamp) throw new HttpError(400, "invalid_timestamp", name + " must be a canonical ISO-8601 UTC timestamp");
  return timestamp;
}

function rejectForbiddenKeys(value, path = "bundle") {
  if (Array.isArray(value)) return value.forEach((entry, index) => rejectForbiddenKeys(entry, path + "[" + index + "]"));
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase().replace(/[- ]/g, "_");
    if (FORBIDDEN_KEYS.has(normalized) || normalized.startsWith("raw_")) throw new HttpError(400, "forbidden_payload_field", path + "." + key + " is forbidden");
    rejectForbiddenKeys(child, path + "." + key);
  }
}

function parseCsvEnv(value) { return new Set(String(value || "").split(",").map((entry) => entry.trim().toLowerCase()).filter(Boolean)); }
async function one(statement) { return statement.first(); }
async function all(statement) { const result = await statement.all(); return result.results || []; }

function responseHeaders(request, contentType) {
  const headers = new Headers({
    "content-type": contentType,
    "cache-control": "no-store, max-age=0",
    "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "referrer-policy": "no-referrer", "x-content-type-options": "nosniff", "x-frame-options": "DENY",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "permissions-policy": "camera=(), microphone=(), geolocation=()", "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin", "vary": "Origin",
  });
  const origin = request.headers.get("origin");
  if (origin && origin === new URL(request.url).origin) { headers.set("access-control-allow-origin", origin); headers.set("access-control-allow-credentials", "true"); }
  return headers;
}

function jsonResponse(request, body, status = 200) { return new Response(JSON.stringify(body), { status, headers: responseHeaders(request, "application/json; charset=utf-8") }); }

function assertSameOriginMutation(request) {
  const expected = new URL(request.url).origin;
  const origin = request.headers.get("origin");
  if (!origin || origin !== expected) throw new HttpError(403, "csrf_origin", "A same-origin Origin header is required");
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin") throw new HttpError(403, "csrf_fetch_site", "Cross-site mutation rejected");
  const type = (request.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase();
  if (type !== "application/json") throw new HttpError(415, "content_type", "Content-Type must be application/json");
}

async function readJson(request, limit = MAX_JSON_BYTES) {
  if (BODY_CACHE.has(request)) return BODY_CACHE.get(request);
  const stated = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(stated) && stated > limit) throw new HttpError(413, "request_too_large", "Request body exceeds the limit");
  let bytes;
  if (request.body && typeof request.body.getReader === "function") {
    const reader = request.body.getReader(); const chunks = []; let size = 0;
    while (true) {
      const { done, value } = await reader.read(); if (done) break; size += value.byteLength;
      if (size > limit) { await reader.cancel(); throw new HttpError(413, "request_too_large", "Request body exceeds the limit"); }
      chunks.push(value);
    }
    bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  } else if (typeof request.text === "function") {
    bytes = new TextEncoder().encode(await request.text());
    if (bytes.byteLength > limit) throw new HttpError(413, "request_too_large", "Request body exceeds the limit");
  } else throw new HttpError(400, "missing_body", "A JSON body is required");
  try { const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); BODY_CACHE.set(request, parsed); return parsed; }
  catch { throw new HttpError(400, "invalid_json", "Body must be valid UTF-8 JSON"); }
}

async function authenticate(request, env) {
  if (!env.DB || !env.DB.prepare) throw new HttpError(503, "database_unavailable", "D1 binding DB is unavailable");
  const rawId = request.headers.get("oai-authenticated-user-id");
  const rawEmail = request.headers.get("oai-authenticated-user-email");
  if (!rawId || !rawEmail) throw new HttpError(401, "authentication_required", "Authenticated Sites identity headers are required");
  const authUserId = idField(rawId, "authenticated user id", 256);
  const email = rawEmail.trim().toLowerCase();
  if (email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(401, "invalid_identity", "Authenticated email is invalid");
  const identityHash = await hmacHex(env.AAMD_RECEIPT_HMAC_KEY, "aamd-identity-v1\n" + authUserId); const now = new Date().toISOString();
  await env.DB.prepare("INSERT INTO workspace_users (auth_user_id,email,email_normalized,identity_hash,created_at,last_seen_at) VALUES (?,?,?,?,?,?) ON CONFLICT(auth_user_id) DO UPDATE SET email=excluded.email,email_normalized=excluded.email_normalized,last_seen_at=excluded.last_seen_at")
    .bind(authUserId, email, email, identityHash, now, now).run();
  const user = await one(env.DB.prepare("SELECT id,auth_user_id,email,identity_hash,admin_tainted,created_at FROM workspace_users WHERE auth_user_id=?").bind(authUserId));
  const bootstrapIds = parseCsvEnv(env.AAMD_BOOTSTRAP_ADMIN_IDS); const bootstrapEmails = parseCsvEnv(env.AAMD_BOOTSTRAP_ADMIN_EMAILS);
  if (bootstrapIds.has(authUserId.toLowerCase()) || bootstrapEmails.has(email)) {
    const reviewerRole = await one(env.DB.prepare("SELECT role FROM user_roles WHERE user_id=? AND role IN ('primary','secondary','adjudicator') LIMIT 1").bind(user.id));
    if (reviewerRole) throw new HttpError(409, "role_separation", "A reviewer identity cannot be promoted through the bootstrap-admin path");
    await env.DB.prepare("UPDATE workspace_users SET admin_tainted=1 WHERE id=? AND admin_tainted=0").bind(user.id).run();
    await env.DB.prepare("INSERT OR IGNORE INTO user_roles (user_id,role,granted_by,created_at) VALUES (?,'admin',NULL,?)").bind(user.id, now).run();
    user.admin_tainted = 1;
  }
  user.roles = (await all(env.DB.prepare("SELECT role FROM user_roles WHERE user_id=? ORDER BY role").bind(user.id))).map((row) => row.role);
  return user;
}

function requireRole(user, role) {
  if (role === "admin" && !user.roles.includes("admin")) throw new HttpError(403, "role_required", "Role required: admin");
  if (role === "admin" && Number(user.admin_tainted) !== 1) throw new HttpError(409, "role_separation", "An admin role without permanent admin taint is invalid");
  if (REVIEW_ROLES.includes(role) && Number(user.admin_tainted) === 1) throw new HttpError(409, "role_separation", "An admin-tainted identity can never act as a reviewer");
  if (!user.roles.includes(role)) throw new HttpError(403, "role_required", "Role required: " + role);
}
function publicUser(user) { return { account_id: user.auth_user_id, identity_hash: user.identity_hash, email: user.email, roles: user.roles, created_at: user.created_at }; }

function validateAffordance(value, name, allowEmpty = false) {
  exactKeys(value, T4_FIELDS, [], name); const out = {};
  for (const field of T4_FIELDS) out[field] = textField(value[field], name + "." + field, allowEmpty ? 0 : 1, 1600);
  return out;
}

function validateEvidence(entry, index) {
  exactKeys(entry, ["handle", "label", "value"], [], "evidence[" + index + "]");
  return { handle: idField(entry.handle, "evidence.handle"), label: textField(entry.label, "evidence.label", 1, 160), value: textField(entry.value, "evidence.value", 1, 1200) };
}

function validateLabelOption(entry, index) {
  exactKeys(entry, ["value", "label", "help"], [], "label_options[" + index + "]");
  return { value: idField(entry.value, "label_options.value"), label: textField(entry.label, "label_options.label", 1, 160), help: textField(entry.help, "label_options.help", 1, 500) };
}

function validateProposalProvenance(value, name, claimBearing) {
  exactKeys(value, ["labeler_config_id", "model_id", "parameters", "model_revision", "model_revision_status", "prompt_template_hash", "decoding_config_hash", "seed", "generator_code_revision", "generated_at", "source_bundle_hash"], ["g0_attestation_hash"], name);
  const exact = {
    labeler_config_id: textField(value.labeler_config_id, name + ".labeler_config_id", 1, 160),
    model_id: textField(value.model_id, name + ".model_id", 1, 240),
    parameters: textField(value.parameters, name + ".parameters", 1, 32),
    model_revision: textField(value.model_revision, name + ".model_revision", 1, 160),
    prompt_template_hash: hashField(value.prompt_template_hash, name + ".prompt_template_hash"),
    decoding_config_hash: hashField(value.decoding_config_hash, name + ".decoding_config_hash"),
  };
  for (const [field, expected] of Object.entries(LLM_FIRST_LABELER)) {
    if (field === "seed") continue;
    if (exact[field] !== expected) throw new HttpError(400, "labeler_contract_mismatch", name + "." + field + " must match the frozen 32B first-pass labeler contract");
  }
  if (!Number.isSafeInteger(value.seed) || value.seed !== LLM_FIRST_LABELER.seed) throw new HttpError(400, "labeler_seed_mismatch", name + ".seed must match the frozen decoding seed");
  const revisionStatus = textField(value.model_revision_status, name + ".model_revision_status", 1, 80);
  if (!["candidate_needs_G0_attestation", "g0_attested"].includes(revisionStatus)) throw new HttpError(400, "invalid_revision_status", name + ".model_revision_status is not supported");
  if (claimBearing && revisionStatus !== "g0_attested") throw new HttpError(409, "labeler_revision_unattested", "Claim-bearing bundles require G0-attested 32B weights");
  let g0AttestationHash;
  if (revisionStatus === "g0_attested") {
    g0AttestationHash = hashField(value.g0_attestation_hash, name + ".g0_attestation_hash");
    if (!TRUSTED_LABELER_G0_ATTESTATION_SHA256) throw new HttpError(409, "labeler_g0_unconfigured", "This source version has no trusted G0 attestation commitment");
    if (g0AttestationHash !== TRUSTED_LABELER_G0_ATTESTATION_SHA256) throw new HttpError(409, "labeler_g0_mismatch", "The proposal G0 attestation does not match the trusted source commitment");
  } else if ("g0_attestation_hash" in value) {
    throw new HttpError(400, "unexpected_g0_attestation", "Candidate revisions cannot claim a G0 attestation hash");
  }
  const generatedAt = isoTimestampField(value.generated_at, name + ".generated_at");
  if (Date.parse(generatedAt) > Date.now() + 5 * 60 * 1000) throw new HttpError(400, "future_generation_timestamp", name + ".generated_at cannot be in the future");
  const provenance = {
    ...exact,
    model_revision_status: revisionStatus,
    seed: value.seed,
    generator_code_revision: idField(value.generator_code_revision, name + ".generator_code_revision"),
    generated_at: generatedAt,
    source_bundle_hash: hashField(value.source_bundle_hash, name + ".source_bundle_hash"),
  };
  if (g0AttestationHash) provenance.g0_attestation_hash = g0AttestationHash;
  return provenance;
}

function validateProposal(value, task, name, llmFirst = false, claimBearing = false) {
  exactKeys(value, ["proposal_id", "version", "label", "confidence", "evidence_handles", "rationale", ...(llmFirst ? ["provenance"] : [])], ["affordance"], name);
  if (!task.label_options.some((option) => option.value === value.label)) throw new HttpError(400, "invalid_proposal_label", name + ".label is outside the codebook");
  if (!Number.isInteger(value.confidence) || value.confidence < 0 || value.confidence > 100) throw new HttpError(400, "invalid_confidence", name + ".confidence is invalid");
  if (!Array.isArray(value.evidence_handles) || value.evidence_handles.length > task.evidence.length) throw new HttpError(400, "invalid_evidence_handles", name + ".evidence_handles is invalid");
  const allowed = new Set(task.evidence.map((entry) => entry.handle)); const handles = [...new Set(value.evidence_handles.map((handle) => idField(handle, name + ".evidence_handles[]")))];
  if (handles.some((handle) => !allowed.has(handle))) throw new HttpError(400, "invalid_evidence_handle", name + " references unknown evidence");
  const proposal = { proposal_id: idField(value.proposal_id, name + ".proposal_id"), version: idField(value.version, name + ".version"), label: value.label, confidence: value.confidence, evidence_handles: handles, rationale: textField(value.rationale, name + ".rationale", 1, 2000) };
  if (task.benchmark === "T4") proposal.affordance = validateAffordance(value.affordance, name + ".affordance");
  else if ("affordance" in value) throw new HttpError(400, "unexpected_affordance", "Only T4 may contain affordance");
  if (llmFirst) proposal.provenance = validateProposalProvenance(value.provenance, name + ".provenance", claimBearing);
  return proposal;
}

function validateBundle(value) {
  rejectForbiddenKeys(value);
  exactKeys(value, ["schema_version", "bundle_id", "mode", "claim_bearing", "protocol_version", "codebook_version", "visibility_mask_hash", "queue_hash", "tasks"], [], "bundle");
  if (value.schema_version !== 1) throw new HttpError(400, "schema_version", "Only schema_version 1 is accepted");
  if (!["claim_bearing_candidate", "pilot_import"].includes(value.mode)) throw new HttpError(400, "invalid_mode", "Unsupported mode");
  if (typeof value.claim_bearing !== "boolean" || ((value.mode === "claim_bearing_candidate") !== value.claim_bearing)) throw new HttpError(400, "claim_mode_mismatch", "claim flag and mode conflict");
  if (!Array.isArray(value.tasks) || value.tasks.length < 1 || value.tasks.length > 500) throw new HttpError(400, "invalid_tasks", "tasks must contain 1-500 records");
  const bundle = { schema_version: 1, bundle_id: idField(value.bundle_id, "bundle_id"), mode: value.mode, claim_bearing: value.claim_bearing, protocol_version: protocolField(value.protocol_version), codebook_version: idField(value.codebook_version, "codebook_version"), visibility_mask_hash: hashField(value.visibility_mask_hash, "visibility_mask_hash"), queue_hash: hashField(value.queue_hash, "queue_hash"), tasks: [] };
  const taskIds = new Set(); const recordHandles = new Set();
  for (let index = 0; index < value.tasks.length; index += 1) {
    const source = value.tasks[index]; const name = "tasks[" + index + "]";
    exactKeys(source, ["task_id", "benchmark", "record_handle", "record_hash", "split", "claim_bearing", "title", "question", "instructions", "evidence", "label_options", "llm_proposal"], [], name);
    if (!BENCHMARKS.includes(source.benchmark) || source.split !== "blinded" || source.claim_bearing !== bundle.claim_bearing) throw new HttpError(400, "task_boundary", name + " violates benchmark, split, or claim boundary");
    if (!Array.isArray(source.evidence) || source.evidence.length < 1 || source.evidence.length > 32 || !Array.isArray(source.label_options) || source.label_options.length < 2 || source.label_options.length > 32) throw new HttpError(400, "task_cardinality", name + " has invalid evidence or labels");
    const task = { task_id: idField(source.task_id, name + ".task_id"), benchmark: source.benchmark, record_handle: idField(source.record_handle, name + ".record_handle"), record_hash: hashField(source.record_hash, name + ".record_hash"), split: "blinded", claim_bearing: source.claim_bearing, title: textField(source.title, name + ".title", 1, 240), question: textField(source.question, name + ".question", 1, 1200), instructions: textField(source.instructions, name + ".instructions", 1, 1600), evidence: source.evidence.map(validateEvidence), label_options: source.label_options.map(validateLabelOption) };
    if (taskIds.has(task.task_id) || recordHandles.has(task.record_handle)) throw new HttpError(400, "duplicate_task", "Duplicate task or record handle");
    taskIds.add(task.task_id); recordHandles.add(task.record_handle);
    if (new Set(task.evidence.map((entry) => entry.handle)).size !== task.evidence.length || new Set(task.label_options.map((entry) => entry.value)).size !== task.label_options.length) throw new HttpError(400, "duplicate_code", name + " has duplicate evidence or label codes");
    task.llm_proposal = validateProposal(source.llm_proposal, task, name + ".llm_proposal", isLlmFirstProtocol(bundle.protocol_version), bundle.claim_bearing); bundle.tasks.push(task);
  }
  return bundle;
}

function validateJudgment(value, task, name) {
  exactKeys(value, ["label", "confidence", "rationale", "abstain"], task.benchmark === "T4" ? ["affordance"] : [], name);
  if (typeof value.abstain !== "boolean") throw new HttpError(400, "invalid_abstain", name + ".abstain must be boolean");
  const labels = new Set(task.label_options.map((entry) => entry.value));
  if (value.abstain ? value.label !== null : (typeof value.label !== "string" || !labels.has(value.label))) throw new HttpError(400, "invalid_label", name + ".label conflicts with codebook or abstention");
  if (!Number.isInteger(value.confidence) || value.confidence < 0 || value.confidence > 100) throw new HttpError(400, "invalid_confidence", name + ".confidence is invalid");
  const out = { label: value.label, confidence: value.confidence, rationale: textField(value.rationale, name + ".rationale", value.abstain ? 0 : 1, 3000), abstain: value.abstain };
  if (task.benchmark === "T4") out.affordance = validateAffordance(value.affordance, name + ".affordance", value.abstain);
  return out;
}

function proposalJudgment(proposal) {
  const judgment = { label: proposal.label, confidence: proposal.confidence, rationale: proposal.rationale, abstain: false };
  if (proposal.affordance) judgment.affordance = proposal.affordance;
  return judgment;
}

function validateLlmFirstDecision(decision, judgment, proposal) {
  if (!LLM_FIRST_DECISIONS.includes(decision)) throw new HttpError(400, "invalid_decision", "Unknown LLM-first review decision");
  const matches = canonicalize(judgment) === canonicalize(proposalJudgment(proposal));
  if (decision === "accept" && !matches) throw new HttpError(400, "accept_requires_unchanged_proposal", "Accept requires an unchanged proposal-derived judgment");
  if ((decision === "edit" || decision === "reject") && (judgment.abstain || matches)) throw new HttpError(400, "review_decision_mismatch", "Edit or reject requires a non-abstaining judgment that differs from the proposal");
  if ((decision === "abstain") !== judgment.abstain) throw new HttpError(400, "decision_abstain_mismatch", "Decision and abstention conflict");
}

function substantiveJudgment(judgment) {
  const value = { label: judgment.label, abstain: judgment.abstain };
  if (judgment.affordance) value.affordance = judgment.affordance;
  return value;
}

async function handleMe(request, env, user) { return jsonResponse(request, { ok: true, api_version: API_VERSION, user: publicUser(user), claim_collection_enabled: env.AAMD_CLAIM_COLLECTION_ENABLED === "true", runtime_dependency: "Sites Worker + D1 only" }); }
async function handleBootstrap(request, user) { const body = await readJson(request); exactKeys(body, [], [], "bootstrap"); return jsonResponse(request, { ok: true, user: publicUser(user), bootstrap_admin: user.roles.includes("admin") }); }

async function handleRoleGrant(request, env, user) {
  requireRole(user, "admin"); const body = await readJson(request); exactKeys(body, ["auth_user_id", "roles"], [], "role grant");
  const targetId = idField(body.auth_user_id, "auth_user_id", 256);
  if (!Array.isArray(body.roles) || body.roles.length < 1 || body.roles.some((role) => !ROLES.includes(role)) || new Set(body.roles).size !== body.roles.length || (body.roles.includes("admin") && body.roles.length !== 1)) throw new HttpError(400, "invalid_roles", "roles must be either admin alone or a unique non-empty reviewer-role list");
  const target = await one(env.DB.prepare("SELECT id,identity_hash,admin_tainted FROM workspace_users WHERE auth_user_id=?").bind(targetId));
  if (!target) throw new HttpError(404, "user_not_registered", "User must visit before role assignment");
  if (target.id === user.id && !body.roles.includes("admin")) throw new HttpError(409, "self_admin_lockout", "Cannot remove own admin role");
  const reviewerGrant = body.roles.some((role) => REVIEW_ROLES.includes(role));
  if (reviewerGrant && Number(target.admin_tainted) === 1) throw new HttpError(409, "role_separation", "An admin-tainted identity can never receive a reviewer role");
  const assigned = await one(env.DB.prepare("SELECT COUNT(*) AS count FROM task_assignments WHERE user_id=?").bind(target.id));
  if (Number(assigned.count) > 0) throw new HttpError(409, "roles_frozen", "Reviewer roles are frozen after the first assignment");
  const now = new Date().toISOString(); const statements = [env.DB.prepare("DELETE FROM user_roles WHERE user_id=?").bind(target.id)];
  if (body.roles.includes("admin")) statements.push(env.DB.prepare("UPDATE workspace_users SET admin_tainted=1 WHERE id=? AND admin_tainted=0").bind(target.id));
  for (const role of body.roles) statements.push(env.DB.prepare("INSERT INTO user_roles (user_id,role,granted_by,created_at) VALUES (?,?,?,?)").bind(target.id, role, user.id, now));
  await env.DB.batch(statements); return jsonResponse(request, { ok: true, identity_hash: target.identity_hash, roles: [...body.roles].sort() });
}

async function handleImport(request, env, user) {
  requireRole(user, "admin"); const bundle = validateBundle(await readJson(request, MAX_IMPORT_BYTES));
  if (bundle.mode === "claim_bearing_candidate" && env.AAMD_CLAIM_COLLECTION_ENABLED !== "true") throw new HttpError(409, "claim_collection_disabled", "Claim-bearing collection is disabled; import pilot_import or explicitly enable the preregistered claim gate");
  if (bundle.claim_bearing && !isLlmFirstProtocol(bundle.protocol_version)) throw new HttpError(409, "legacy_claim_import_disabled", "Legacy protocols are preserved for pilot/history only; new claim-bearing imports require the 32B LLM-first protocol");
  if (await one(env.DB.prepare("SELECT bundle_id FROM task_bundles WHERE bundle_id=?").bind(bundle.bundle_id))) throw new HttpError(409, "bundle_exists", "Bundle id cannot be reused");
  const now = new Date().toISOString(); const bundleHash = await sha256Hex(bundle);
  if (bundle.claim_bearing) {
    if (!TRUSTED_LABELER_CLAIM_BUNDLE_SHA256) throw new HttpError(409, "labeler_claim_bundle_unconfigured", "This source version has no trusted claim-bundle commitment");
    if (bundleHash !== TRUSTED_LABELER_CLAIM_BUNDLE_SHA256) throw new HttpError(409, "labeler_claim_bundle_mismatch", "The canonical claim bundle does not match the trusted source commitment");
  }
  const statements = [env.DB.prepare("INSERT INTO task_bundles (bundle_id,schema_version,mode,claim_bearing,protocol_version,codebook_version,visibility_mask_hash,queue_hash,bundle_hash,task_count,imported_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(bundle.bundle_id, 1, bundle.mode, bundle.claim_bearing ? 1 : 0, bundle.protocol_version, bundle.codebook_version, bundle.visibility_mask_hash, bundle.queue_hash, bundleHash, bundle.tasks.length, user.id, now)];
  for (let ordinal = 0; ordinal < bundle.tasks.length; ordinal += 1) {
    const complete = bundle.tasks[ordinal]; const { llm_proposal: proposal, ...publicTask } = complete; const proposalHash = await sha256Hex(proposal);
    statements.push(env.DB.prepare("INSERT INTO tasks (task_id,bundle_id,ordinal,benchmark,record_handle,record_hash,public_task_json,proposal_json,proposal_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
      .bind(complete.task_id, bundle.bundle_id, ordinal, complete.benchmark, complete.record_handle, complete.record_hash, canonicalize(publicTask), canonicalize(proposal), proposalHash, now));
  }
  await env.DB.batch(statements);
  return jsonResponse(request, { ok: true, bundle_id: bundle.bundle_id, bundle_hash: bundleHash, task_count: bundle.tasks.length, status: "quarantined", next: "A different admin must approve this immutable bundle." }, 201);
}

async function handleApprove(request, env, user) {
  requireRole(user, "admin"); const body = await readJson(request); exactKeys(body, ["bundle_id"], [], "approval");
  const bundleId = idField(body.bundle_id, "bundle_id");
  const bundle = await one(env.DB.prepare("SELECT bundle_id,bundle_hash,imported_by FROM task_bundles WHERE bundle_id=?").bind(bundleId));
  if (!bundle) throw new HttpError(404, "bundle_not_found", "Bundle not found");
  if (bundle.imported_by === user.id) throw new HttpError(409, "two_person_rule", "Uploader cannot approve their own bundle");
  if (await one(env.DB.prepare("SELECT bundle_id FROM bundle_approvals WHERE bundle_id=?").bind(bundleId))) throw new HttpError(409, "already_approved", "Bundle is already approved");
  const approvedAt = new Date().toISOString(); const approvalHash = await sha256Hex({ bundle_id: bundleId, bundle_hash: bundle.bundle_hash, approver: user.identity_hash, approved_at: approvedAt });
  await env.DB.prepare("INSERT INTO bundle_approvals (bundle_id,approved_by,approved_at,approval_hash) VALUES (?,?,?,?)").bind(bundleId, user.id, approvedAt, approvalHash).run();
  return jsonResponse(request, { ok: true, bundle_id: bundleId, status: "approved", approved_at: approvedAt, approval_hash: approvalHash }, 201);
}

async function bundleIdOrDefault(env, requested, approvedOnly = true) {
  if (requested) {
    const id = idField(requested, "bundle_id");
    const sql = approvedOnly ? "SELECT b.bundle_id FROM task_bundles b JOIN bundle_approvals a ON a.bundle_id=b.bundle_id WHERE b.bundle_id=?" : "SELECT bundle_id FROM task_bundles WHERE bundle_id=?";
    if (!await one(env.DB.prepare(sql).bind(id))) throw new HttpError(404, "bundle_not_found", approvedOnly ? "Approved bundle not found" : "Bundle not found");
    return id;
  }
  const sql = approvedOnly ? "SELECT b.bundle_id FROM task_bundles b JOIN bundle_approvals a ON a.bundle_id=b.bundle_id ORDER BY a.approved_at,b.bundle_id LIMIT 1" : "SELECT bundle_id FROM task_bundles ORDER BY created_at,bundle_id LIMIT 1";
  const row = await one(env.DB.prepare(sql)); if (!row) throw new HttpError(409, "no_bundle", approvedOnly ? "No approved bundle exists" : "No bundle exists"); return row.bundle_id;
}

async function bundleProtocol(env, bundleId) {
  const row = await one(env.DB.prepare("SELECT protocol_version FROM task_bundles WHERE bundle_id=?").bind(bundleId));
  if (!row) throw new HttpError(404, "bundle_not_found", "Bundle not found");
  return row.protocol_version;
}

async function eventMap(env, taskId) {
  const rows = await all(env.DB.prepare("SELECT stage,payload_json,receipt_json,event_hash,server_received_at FROM stage_events WHERE task_id=? ORDER BY CASE stage WHEN 'initial' THEN 1 WHEN 'reveal' THEN 2 WHEN 'final' THEN 3 WHEN 'secondary' THEN 4 ELSE 5 END").bind(taskId));
  return Object.fromEntries(rows.map((row) => [row.stage, { payload: JSON.parse(row.payload_json), receipt: JSON.parse(row.receipt_json), event_hash: row.event_hash, server_received_at: row.server_received_at }]));
}
function taskStatus(events, protocolVersion) {
  if (isLlmFirstProtocol(protocolVersion)) return events.adjudicate ? "adjudicated" : events.secondary ? "awaiting_adjudication" : events.final ? "awaiting_secondary" : "awaiting_primary_review";
  return events.adjudicate ? "adjudicated" : events.secondary ? "awaiting_adjudication" : events.final ? "awaiting_secondary" : events.reveal ? "awaiting_primary_final" : events.initial ? "proposal_available" : "awaiting_initial";
}

async function incompleteAssignment(env, userId, role, bundleId) {
  const completion = role === "primary" ? "final" : role === "secondary" ? "secondary" : "adjudicate";
  return one(env.DB.prepare("SELECT a.assignment_id,a.task_id,a.bundle_id,a.role,a.assignment_hash,a.assigned_at FROM task_assignments a LEFT JOIN stage_events e ON e.task_id=a.task_id AND e.stage=? WHERE a.user_id=? AND a.role=? AND a.bundle_id=? AND e.event_id IS NULL ORDER BY a.assigned_at,a.task_id LIMIT 1").bind(completion, userId, role, bundleId));
}

async function eligibleTasks(env, userId, role, bundleId) {
  if (role === "primary") return all(env.DB.prepare("SELECT t.task_id FROM tasks t LEFT JOIN task_assignments a ON a.task_id=t.task_id AND a.role='primary' WHERE t.bundle_id=? AND a.assignment_id IS NULL ORDER BY t.ordinal,t.task_id").bind(bundleId));
  if (role === "secondary") return all(env.DB.prepare("SELECT t.task_id FROM tasks t JOIN stage_events f ON f.task_id=t.task_id AND f.stage='final' JOIN task_assignments p ON p.task_id=t.task_id AND p.role='primary' LEFT JOIN task_assignments a ON a.task_id=t.task_id AND a.role='secondary' WHERE t.bundle_id=? AND p.user_id<>? AND a.assignment_id IS NULL ORDER BY t.ordinal,t.task_id").bind(bundleId, userId));
  return all(env.DB.prepare("SELECT t.task_id FROM tasks t JOIN stage_events s ON s.task_id=t.task_id AND s.stage='secondary' JOIN task_assignments p ON p.task_id=t.task_id AND p.role='primary' JOIN task_assignments q ON q.task_id=t.task_id AND q.role='secondary' LEFT JOIN task_assignments a ON a.task_id=t.task_id AND a.role='adjudicator' WHERE t.bundle_id=? AND p.user_id<>? AND q.user_id<>? AND a.assignment_id IS NULL ORDER BY t.ordinal,t.task_id").bind(bundleId, userId, userId));
}

async function handleNextAssignment(request, env, user) {
  const body = await readJson(request); exactKeys(body, ["role"], ["bundle_id"], "assignment request");
  if (!REVIEW_ROLES.includes(body.role)) throw new HttpError(400, "invalid_role", "Invalid review role"); requireRole(user, body.role);
  const bundleId = await bundleIdOrDefault(env, body.bundle_id, true); const current = await incompleteAssignment(env, user.id, body.role, bundleId);
  if (current) return jsonResponse(request, { ok: true, assignment: current, reused: true });
  const candidates = await eligibleTasks(env, user.id, body.role, bundleId); const ranked = [];
  for (const candidate of candidates) ranked.push({ ...candidate, score: await sha256Hex("aamd-assignment-rank-v1\n" + bundleId + "\n" + body.role + "\n" + user.identity_hash + "\n" + candidate.task_id) });
  ranked.sort((a, b) => a.score.localeCompare(b.score) || a.task_id.localeCompare(b.task_id));
  for (const candidate of ranked) {
    const assignmentHash = await sha256Hex("aamd-assignment-v1\n" + bundleId + "\n" + candidate.task_id + "\n" + body.role + "\n" + user.identity_hash);
    const assignmentId = crypto.randomUUID(); const assignedAt = new Date().toISOString();
    const result = await env.DB.prepare("INSERT OR IGNORE INTO task_assignments (assignment_id,bundle_id,task_id,role,user_id,assignment_hash,assigned_at) VALUES (?,?,?,?,?,?,?)").bind(assignmentId, bundleId, candidate.task_id, body.role, user.id, assignmentHash, assignedAt).run();
    if (((result.meta && result.meta.changes) || 0) > 0) return jsonResponse(request, { ok: true, assignment: { assignment_id: assignmentId, bundle_id: bundleId, task_id: candidate.task_id, role: body.role, assignment_hash: assignmentHash, assigned_at: assignedAt }, reused: false }, 201);
  }
  throw new HttpError(409, "no_eligible_task", "No eligible task is available");
}

async function handleTaskList(request, env, user, url) {
  const role = url.searchParams.get("role"); if (!REVIEW_ROLES.includes(role)) throw new HttpError(400, "invalid_role", "role query is required"); requireRole(user, role);
  const bundleId = await bundleIdOrDefault(env, url.searchParams.get("bundle_id"), true);
  const rows = await all(env.DB.prepare("SELECT a.assignment_id,a.task_id,a.bundle_id,a.role,a.assignment_hash,a.assigned_at,t.ordinal,t.benchmark FROM task_assignments a JOIN tasks t ON t.task_id=a.task_id WHERE a.user_id=? AND a.role=? AND a.bundle_id=? ORDER BY a.assigned_at,a.task_id").bind(user.id, role, bundleId));
  const protocolVersion = await bundleProtocol(env, bundleId);
  const tasks = []; for (const row of rows) tasks.push({ ...row, protocol_version: protocolVersion, status: taskStatus(await eventMap(env, row.task_id), protocolVersion) });
  return jsonResponse(request, { ok: true, bundle_id: bundleId, protocol_version: protocolVersion, role, tasks });
}

async function assignmentFor(env, user, taskId, role) {
  if (!REVIEW_ROLES.includes(role)) throw new HttpError(400, "invalid_role", "Valid role required"); requireRole(user, role);
  const row = await one(env.DB.prepare("SELECT a.assignment_id,a.bundle_id,a.task_id,a.role,a.assignment_hash,a.assigned_at,t.public_task_json,t.proposal_json,t.proposal_hash,t.benchmark FROM task_assignments a JOIN tasks t ON t.task_id=a.task_id JOIN bundle_approvals b ON b.bundle_id=a.bundle_id WHERE a.task_id=? AND a.role=? AND a.user_id=?").bind(taskId, role, user.id));
  if (!row) throw new HttpError(404, "assignment_not_found", "Task is not assigned to this reviewer role"); row.task = JSON.parse(row.public_task_json); row.protocol_version = await bundleProtocol(env, row.bundle_id); return row;
}

async function handleTaskView(request, env, user, taskId, url) {
  const role = url.searchParams.get("role"); const assignment = await assignmentFor(env, user, taskId, role); const events = await eventMap(env, taskId);
  const llmFirst = isLlmFirstProtocol(assignment.protocol_version); const proposal = JSON.parse(assignment.proposal_json);
  const body = { ok: true, assignment: { assignment_id: assignment.assignment_id, bundle_id: assignment.bundle_id, task_id: taskId, role, assignment_hash: assignment.assignment_hash, assigned_at: assignment.assigned_at }, protocol_version: assignment.protocol_version, workflow: llmFirst ? "llm_first_human_review" : "blind_first_legacy", task: assignment.task, status: taskStatus(events, assignment.protocol_version), version: Object.keys(events).length };
  if (role === "primary") {
    if (llmFirst) { body.proposal = proposal; body.final = events.final || null; }
    else { body.initial = events.initial || null; body.reveal_receipt = events.reveal ? events.reveal.receipt : null; body.proposal = events.reveal ? proposal : null; body.final = events.final || null; }
  }
  else if (role === "secondary") { if (llmFirst) body.proposal = proposal; body.secondary = events.secondary || null; }
  else {
    if (!events.secondary) throw new HttpError(409, "secondary_not_locked", "Secondary vote is not locked");
    if (llmFirst) body.proposal = proposal;
    body.votes = { primary_final: events.final.payload, secondary: events.secondary.payload }; body.adjudication = events.adjudicate || null;
  }
  return jsonResponse(request, body);
}

function idempotencyKey(request) {
  const key = request.headers.get("idempotency-key");
  if (!key || !/^[A-Za-z0-9._:\-]{8,128}$/.test(key)) throw new HttpError(400, "idempotency_key", "Idempotency-Key header of 8-128 safe characters is required");
  return key;
}

async function appendStageEvent(env, assignment, user, stage, body, payload, previousStage) {
  const sequence = stageSequence(assignment.protocol_version); const expected = sequence.indexOf(stage);
  if (expected < 0) throw new HttpError(409, "protocol_stage_disabled", "Stage is disabled for this bundle protocol");
  const key = idempotencyKey(body.request); const keyHash = await sha256Hex("aamd-idempotency-v1\n" + key); const requestHash = await sha256Hex(body.raw);
  if (body.raw.expected_version !== expected) throw new HttpError(409, "version_mismatch", "expected_version must be " + expected + " for " + stage);
  const existing = await one(env.DB.prepare("SELECT actor_user_id,idempotency_key_hash,request_hash,receipt_json FROM stage_events WHERE task_id=? AND stage=?").bind(assignment.task_id, stage));
  if (existing) {
    if (existing.actor_user_id === user.id && existing.idempotency_key_hash === keyHash && existing.request_hash === requestHash) return { receipt: JSON.parse(existing.receipt_json), replayed: true };
    if (existing.actor_user_id === user.id && existing.idempotency_key_hash === keyHash) throw new HttpError(409, "idempotency_conflict", "Idempotency-Key was reused with a different body");
    throw new HttpError(409, "stage_locked", "Immutable stage already locked");
  }
  const countRow = await one(env.DB.prepare("SELECT COUNT(*) AS count FROM stage_events WHERE task_id=?").bind(assignment.task_id));
  if (Number(countRow.count) !== expected) throw new HttpError(409, "version_mismatch", "Task version changed; reload before locking");
  let previousEventHash = "GENESIS";
  if (previousStage) { const previous = await one(env.DB.prepare("SELECT event_hash FROM stage_events WHERE task_id=? AND stage=?").bind(assignment.task_id, previousStage)); if (!previous) throw new HttpError(409, "previous_stage_required", "Required previous stage is not locked"); previousEventHash = previous.event_hash; }
  const eventId = crypto.randomUUID(); const receivedAt = new Date().toISOString(); const payloadJson = canonicalize(payload); const payloadHash = await sha256Hex(payloadJson);
  const chainVersion = isLlmFirstProtocol(assignment.protocol_version) ? "aamd-stage-chain-v2" : "aamd-stage-chain-v1";
  const eventHash = await sha256Hex({ chain_version: chainVersion, event_id: eventId, bundle_id: assignment.bundle_id, task_id: assignment.task_id, stage, actor_hash: user.identity_hash, actor_role: assignment.role, payload_hash: payloadHash, previous_event_hash: previousEventHash, server_received_at: receivedAt });
  const receiptBase = { event_id: eventId, event_hash: eventHash, previous_event_hash: previousEventHash, payload_hash: payloadHash, request_hash: requestHash, expected_version: expected, accepted_version: expected + 1, server_received_at: receivedAt, chain_version: chainVersion, signature_algorithm: "HMAC-SHA256" };
  const receipt = { ...receiptBase, server_signature: await hmacHex(env.AAMD_RECEIPT_HMAC_KEY, receiptBase) };
  try {
    await env.DB.prepare("INSERT INTO stage_events (event_id,bundle_id,task_id,stage,actor_user_id,actor_role,idempotency_key_hash,request_hash,expected_version,payload_json,payload_hash,previous_event_hash,event_hash,server_received_at,receipt_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
      .bind(eventId, assignment.bundle_id, assignment.task_id, stage, user.id, assignment.role, keyHash, requestHash, expected, payloadJson, payloadHash, previousEventHash, eventHash, receivedAt, canonicalize(receipt)).run();
  } catch (error) { if (/unique|constraint/i.test(String(error))) throw new HttpError(409, "stage_race", "Another immutable event won the race"); throw error; }
  return { receipt, replayed: false };
}

function stageBody(raw, required) { exactKeys(raw, [...required, "expected_version"], [], "stage submission"); if (!Number.isInteger(raw.expected_version)) throw new HttpError(400, "expected_version", "expected_version must be integer"); }

async function handleInitial(request, env, user, taskId) {
  const assignment = await assignmentFor(env, user, taskId, "primary"); const raw = await readJson(request); stageBody(raw, ["judgment"]);
  if (isLlmFirstProtocol(assignment.protocol_version)) throw new HttpError(409, "protocol_stage_disabled", "LLM-first bundles do not collect a blind initial judgment");
  const accepted = await appendStageEvent(env, assignment, user, "initial", { request, raw }, { judgment: validateJudgment(raw.judgment, assignment.task, "judgment") }, null);
  return jsonResponse(request, { ok: true, ...accepted }, accepted.replayed ? 200 : 201);
}
async function handleReveal(request, env, user, taskId) {
  const assignment = await assignmentFor(env, user, taskId, "primary"); const raw = await readJson(request); stageBody(raw, ["initial_event_hash"]);
  if (isLlmFirstProtocol(assignment.protocol_version)) throw new HttpError(409, "protocol_stage_disabled", "The LLM proposal is already visible in this bundle protocol");
  const initial = await one(env.DB.prepare("SELECT event_hash FROM stage_events WHERE task_id=? AND stage='initial'").bind(taskId));
  if (!initial || raw.initial_event_hash !== initial.event_hash) throw new HttpError(409, "initial_receipt_mismatch", "Matching initial receipt required");
  const accepted = await appendStageEvent(env, assignment, user, "reveal", { request, raw }, { initial_event_hash: initial.event_hash, proposal_hash: assignment.proposal_hash }, "initial");
  return jsonResponse(request, { ok: true, ...accepted, proposal: JSON.parse(assignment.proposal_json) }, accepted.replayed ? 200 : 201);
}
async function handleFinal(request, env, user, taskId) {
  const assignment = await assignmentFor(env, user, taskId, "primary"); const raw = await readJson(request); const llmFirst = isLlmFirstProtocol(assignment.protocol_version);
  stageBody(raw, llmFirst ? ["decision", "judgment"] : ["reveal_event_hash", "decision", "judgment"]);
  const judgment = validateJudgment(raw.judgment, assignment.task, "judgment");
  if (llmFirst) {
    const proposal = JSON.parse(assignment.proposal_json); validateLlmFirstDecision(raw.decision, judgment, proposal);
    const accepted = await appendStageEvent(env, assignment, user, "final", { request, raw }, { decision: raw.decision, proposal_id: proposal.proposal_id, proposal_version: proposal.version, proposal_hash: assignment.proposal_hash, judgment }, null);
    return jsonResponse(request, { ok: true, ...accepted }, accepted.replayed ? 200 : 201);
  }
  if (!FINAL_DECISIONS.includes(raw.decision)) throw new HttpError(400, "invalid_decision", "Unknown decision");
  const reveal = await one(env.DB.prepare("SELECT event_hash FROM stage_events WHERE task_id=? AND stage='reveal'").bind(taskId)); if (!reveal || raw.reveal_event_hash !== reveal.event_hash) throw new HttpError(409, "reveal_receipt_mismatch", "Matching reveal receipt required");
  if ((raw.decision === "abstain_after_proposal") !== judgment.abstain) throw new HttpError(400, "decision_abstain_mismatch", "Decision and abstention conflict");
  const accepted = await appendStageEvent(env, assignment, user, "final", { request, raw }, { decision: raw.decision, judgment }, "reveal"); return jsonResponse(request, { ok: true, ...accepted }, accepted.replayed ? 200 : 201);
}
async function handleSecondary(request, env, user, taskId) {
  const assignment = await assignmentFor(env, user, taskId, "secondary"); const raw = await readJson(request); const llmFirst = isLlmFirstProtocol(assignment.protocol_version);
  stageBody(raw, llmFirst ? ["decision", "judgment"] : ["judgment"]);
  const judgment = validateJudgment(raw.judgment, assignment.task, "judgment"); let payload = { judgment };
  if (llmFirst) { const proposal = JSON.parse(assignment.proposal_json); validateLlmFirstDecision(raw.decision, judgment, proposal); payload = { decision: raw.decision, proposal_id: proposal.proposal_id, proposal_version: proposal.version, proposal_hash: assignment.proposal_hash, judgment }; }
  const accepted = await appendStageEvent(env, assignment, user, "secondary", { request, raw }, payload, "final"); return jsonResponse(request, { ok: true, ...accepted }, accepted.replayed ? 200 : 201);
}
async function handleAdjudicate(request, env, user, taskId) {
  const assignment = await assignmentFor(env, user, taskId, "adjudicator"); const raw = await readJson(request); stageBody(raw, ["resolution", "judgment"]);
  if (!RESOLUTIONS.includes(raw.resolution)) throw new HttpError(400, "invalid_resolution", "Unknown resolution"); const judgment = validateJudgment(raw.judgment, assignment.task, "judgment"); const events = await eventMap(env, taskId);
  if (!events.final || !events.secondary) throw new HttpError(409, "votes_not_locked", "Both votes must be locked");
  if (raw.resolution === "agreement") {
    const primary = events.final.payload; const secondary = events.secondary.payload;
    const nonAbstaining = !primary.judgment.abstain && !secondary.judgment.abstain && !judgment.abstain;
    const sameJudgment = canonicalize(substantiveJudgment(primary.judgment)) === canonicalize(substantiveJudgment(secondary.judgment)) && canonicalize(substantiveJudgment(judgment)) === canonicalize(substantiveJudgment(primary.judgment));
    const sameDecision = !isLlmFirstProtocol(assignment.protocol_version) || primary.decision === secondary.decision;
    if (!nonAbstaining || !sameJudgment || !sameDecision) throw new HttpError(400, "invalid_agreement", "Agreement requires matching non-abstaining substantive judgments and, for LLM-first review, matching decisions");
  }
  if (raw.resolution === "resolved" && judgment.abstain) throw new HttpError(400, "resolved_abstain", "Resolved cannot abstain");
  const accepted = await appendStageEvent(env, assignment, user, "adjudicate", { request, raw }, { resolution: raw.resolution, judgment }, "secondary"); return jsonResponse(request, { ok: true, ...accepted }, accepted.replayed ? 200 : 201);
}

async function handleDashboard(request, env, user) {
  const bundles = await all(env.DB.prepare("SELECT b.bundle_id,b.mode,b.claim_bearing,b.protocol_version,b.codebook_version,b.bundle_hash,b.task_count,b.created_at,CASE WHEN a.bundle_id IS NULL THEN 'quarantined' ELSE 'approved' END AS status,a.approved_at,COUNT(DISTINCT CASE WHEN e.stage='adjudicate' THEN e.task_id END) AS adjudicated FROM task_bundles b LEFT JOIN bundle_approvals a ON a.bundle_id=b.bundle_id LEFT JOIN stage_events e ON e.bundle_id=b.bundle_id GROUP BY b.bundle_id ORDER BY b.created_at,b.bundle_id"));
  const mine = await all(env.DB.prepare("SELECT role,COUNT(*) AS assigned FROM task_assignments WHERE user_id=? GROUP BY role ORDER BY role").bind(user.id));
  return jsonResponse(request, { ok: true, bundles, my_assignments: mine, user: publicUser(user), claim_collection_enabled: env.AAMD_CLAIM_COLLECTION_ENABLED === "true", runtime_dependency: "Sites Worker + D1 only; no AICA runtime call" });
}

async function buildAdminExport(env, bundleId) {
  const bundle = await one(env.DB.prepare("SELECT b.bundle_id,b.schema_version,b.mode,b.claim_bearing,b.protocol_version,b.codebook_version,b.visibility_mask_hash,b.queue_hash,b.bundle_hash,b.task_count,b.created_at,a.approved_at,a.approval_hash FROM task_bundles b LEFT JOIN bundle_approvals a ON a.bundle_id=b.bundle_id WHERE b.bundle_id=?").bind(bundleId));
  if (!bundle) throw new HttpError(404, "bundle_not_found", "Bundle not found");
  const taskRows = await all(env.DB.prepare("SELECT t.task_id,t.ordinal,t.public_task_json,t.proposal_json,t.proposal_hash,CASE WHEN r.event_id IS NULL THEN 0 ELSE 1 END AS revealed FROM tasks t LEFT JOIN stage_events r ON r.task_id=t.task_id AND r.stage='reveal' WHERE t.bundle_id=? ORDER BY t.ordinal,t.task_id").bind(bundleId));
  const events = await all(env.DB.prepare("SELECT e.event_id,e.task_id,e.stage,u.identity_hash AS actor_hash,e.actor_role,e.idempotency_key_hash,e.request_hash,e.expected_version,e.payload_json,e.payload_hash,e.previous_event_hash,e.event_hash,e.server_received_at,e.receipt_json FROM stage_events e JOIN workspace_users u ON u.id=e.actor_user_id WHERE e.bundle_id=? ORDER BY e.task_id,CASE e.stage WHEN 'initial' THEN 1 WHEN 'reveal' THEN 2 WHEN 'final' THEN 3 WHEN 'secondary' THEN 4 ELSE 5 END").bind(bundleId));
  const assignments = await all(env.DB.prepare("SELECT a.assignment_id,a.task_id,a.role,u.identity_hash AS actor_hash,a.assignment_hash,a.assigned_at FROM task_assignments a JOIN workspace_users u ON u.id=a.user_id WHERE a.bundle_id=? ORDER BY a.task_id,a.role").bind(bundleId));
  const llmFirst = isLlmFirstProtocol(bundle.protocol_version); const assignedTaskIds = new Set(assignments.map((row) => row.task_id)); const approved = Boolean(bundle.approved_at);
  const exported = { schema_version: llmFirst ? 2 : 1, export_type: "aamd-claim-workspace-admin-export", workflow: llmFirst ? "llm_first_human_review" : "blind_first_legacy", generated_at: new Date().toISOString(), bundle, tasks: taskRows.map((row) => ({ task: JSON.parse(row.public_task_json), ordinal: row.ordinal, proposal_hash: row.proposal_hash, proposal: llmFirst ? (approved ? JSON.parse(row.proposal_json) : null) : row.revealed ? JSON.parse(row.proposal_json) : null, proposal_release_status: llmFirst ? (!approved ? "sealed_unapproved" : assignedTaskIds.has(row.task_id) ? "available_to_assigned_reviewers_before_human_review" : "approved_not_assigned") : row.revealed ? "released_after_initial_lock" : "sealed" })), assignments, events: events.map((row) => ({ event_id: row.event_id, task_id: row.task_id, stage: row.stage, actor_hash: row.actor_hash, actor_role: row.actor_role, idempotency_key_hash: row.idempotency_key_hash, request_hash: row.request_hash, expected_version: row.expected_version, payload_hash: row.payload_hash, previous_event_hash: row.previous_event_hash, event_hash: row.event_hash, server_received_at: row.server_received_at, payload: JSON.parse(row.payload_json), receipt: JSON.parse(row.receipt_json) })) };
  exported.export_hash = await sha256Hex(exported);
  exported.signature_algorithm = "HMAC-SHA256";
  exported.export_signature = await hmacHex(env.AAMD_RECEIPT_HMAC_KEY, {
    export_hash: exported.export_hash,
    bundle_id: exported.bundle.bundle_id,
    generated_at: exported.generated_at,
  });
  return exported;
}

async function handleExport(request, env, user, url) { requireRole(user, "admin"); const bundleId = await bundleIdOrDefault(env, url.searchParams.get("bundle_id"), false); return jsonResponse(request, { ok: true, export: await buildAdminExport(env, bundleId) }); }

function htmlPage() { return PAGE; }

async function route(request, env) {
  const url = new URL(request.url);
  if (request.method === "OPTIONS") {
    if (request.headers.get("origin") !== url.origin) throw new HttpError(403, "cors_origin", "Cross-origin preflight rejected");
    const headers = responseHeaders(request, "text/plain; charset=utf-8"); headers.set("access-control-allow-methods", "GET, POST, OPTIONS"); headers.set("access-control-allow-headers", "content-type, idempotency-key"); headers.set("access-control-max-age", "600"); return new Response(null, { status: 204, headers });
  }
  if (url.pathname === "/" && request.method === "GET") return new Response(htmlPage(), { headers: responseHeaders(request, "text/html; charset=utf-8") });
  if (!url.pathname.startsWith("/api/")) throw new HttpError(404, "not_found", "Not found");
  if (!['GET', 'POST'].includes(request.method)) throw new HttpError(405, "method_not_allowed", "Method not allowed");
  const origin = request.headers.get("origin"); if (origin && origin !== url.origin) throw new HttpError(403, "cors_origin", "Cross-origin request rejected");
  if (request.method === "POST") { assertSameOriginMutation(request); await readJson(request, url.pathname === "/api/admin/import" ? MAX_IMPORT_BYTES : MAX_JSON_BYTES); }
  const user = await authenticate(request, env);
  if (url.pathname === "/api/me" && request.method === "GET") return handleMe(request, env, user);
  if (url.pathname === "/api/bootstrap" && request.method === "POST") return handleBootstrap(request, user);
  if (url.pathname === "/api/dashboard" && request.method === "GET") return handleDashboard(request, env, user);
  if (url.pathname === "/api/tasks" && request.method === "GET") return handleTaskList(request, env, user, url);
  if (url.pathname === "/api/tasks" && request.method === "POST") return handleNextAssignment(request, env, user);
  if (url.pathname === "/api/admin/import" && request.method === "POST") return handleImport(request, env, user);
  if (url.pathname === "/api/admin/approve" && request.method === "POST") return handleApprove(request, env, user);
  if (url.pathname === "/api/admin/roles" && request.method === "POST") return handleRoleGrant(request, env, user);
  if (url.pathname === "/api/admin/export" && request.method === "GET") return handleExport(request, env, user, url);
  const match = url.pathname.match(/^\/api\/tasks\/([A-Za-z0-9][A-Za-z0-9._:@+\-]*)(?:\/(initial|reveal|final|secondary|adjudicate))?$/);
  if (match) {
    const taskId = decodeURIComponent(match[1]); const stage = match[2];
    if (!stage && request.method === "GET") return handleTaskView(request, env, user, taskId, url);
    if (stage && request.method === "POST") {
      if (stage === "initial") return handleInitial(request, env, user, taskId);
      if (stage === "reveal") return handleReveal(request, env, user, taskId);
      if (stage === "final") return handleFinal(request, env, user, taskId);
      if (stage === "secondary") return handleSecondary(request, env, user, taskId);
      return handleAdjudicate(request, env, user, taskId);
    }
  }
  throw new HttpError(404, "not_found", "API route not found");
}

const PAGE = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AAMD Human Workspace</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;color:#111;background:#fff}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#fff;color:#111}.layout{display:grid;grid-template-columns:240px 1fr;min-height:100vh}aside{border-right:1px solid #ddd;padding:28px 18px;position:sticky;top:0;height:100vh;background:#fafafa}.brand{font-weight:800;margin:0 10px 28px}.brand small{display:block;font-weight:500;color:#666;margin-top:6px}.nav{display:grid;gap:5px}.nav button{border:0;background:transparent;text-align:left;padding:11px 12px;border-radius:7px;color:#333}.nav button.active,.nav button:hover{background:#111;color:#fff}main{padding:38px;max-width:1120px;width:100%}.top{display:flex;justify-content:space-between;border-bottom:1px solid #ddd;padding-bottom:20px;margin-bottom:25px}.eyebrow{font-size:.75rem;letter-spacing:.12em;text-transform:uppercase;color:#666}.status{padding:7px 10px;border:1px solid #aaa;border-radius:999px;font-size:.8rem}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.card{border:1px solid #d4d4d4;border-radius:9px;padding:18px;background:#fff}.card h3{margin:0 0 10px}.metric{font-size:1.8rem;font-weight:750}.muted{color:#666;font-size:.9rem;line-height:1.55}.notice{border-left:4px solid #111;background:#f5f5f5;padding:13px 15px;margin:16px 0}.error{border-color:#9c1c1c;color:#8d1111}.ok{border-color:#246b35;color:#195a2a}label{display:block;font-weight:650;margin:14px 0 6px}input,select,textarea{width:100%;border:1px solid #999;border-radius:6px;padding:10px;background:#fff;color:#111;font:inherit}textarea{min-height:90px;resize:vertical}button{cursor:pointer;border:1px solid #111;background:#111;color:#fff;border-radius:6px;padding:10px 14px;font:inherit}button.secondary{background:#fff;color:#111}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.evidence{border-top:1px solid #ddd;padding:11px 0}.evidence code{display:block;color:#555;margin-bottom:5px}.view{display:none}.view.active{display:block}.pill{display:inline-block;border:1px solid #bbb;border-radius:999px;padding:3px 8px;font-size:.78rem;margin:2px}pre{white-space:pre-wrap;word-break:break-word;background:#f6f6f6;border:1px solid #ddd;padding:12px;border-radius:6px;max-height:420px;overflow:auto}.task-list button{width:100%;background:#fff;color:#111;text-align:left;margin:4px 0}@media(max-width:760px){.layout{grid-template-columns:1fr}aside{height:auto;position:static;border-right:0;border-bottom:1px solid #ddd;padding:15px}.nav{grid-template-columns:repeat(3,1fr)}main{padding:22px}.grid{grid-template-columns:1fr}.top{display:block}}
</style></head><body><div class="layout"><aside><div class="brand">AAMD Workspace<small>LLM-first · human-reviewed</small></div><div class="nav"><button data-view="dashboard" class="active">Dashboard</button><button data-view="queue">My queue</button><button data-view="review">Review</button><button data-view="admin">Admin</button><button data-view="protocol">Protocol</button></div></aside><main><div class="top"><div><div class="eyebrow">Defense-useful adaptive attack memory</div><h1>Human review workspace</h1></div><div class="row"><span id="collection-mode" class="status">Pilot-only 확인 중</span><span id="identity" class="status">인증 확인 중</span></div></div><div id="message"></div>
<section id="dashboard" class="view active"><div class="notice"><strong>실험 중 AICA 호출 없음.</strong> Qwen2.5-VL-32B의 고정된 1차 proposal은 오프라인에서 미리 계산되며, reviewer는 proposal과 추상 증거를 함께 확인해 수용·수정·거부·보류합니다. Sites Worker + D1에는 검수 이력만 남습니다.</div><div id="dashboard-cards" class="grid"></div></section>
<section id="queue" class="view"><h2>My queue</h2><div class="row"><select id="queue-bundle"><option value="">Approved bundle 선택</option></select><select id="queue-role"><option value="primary">Primary</option><option value="secondary">Secondary</option><option value="adjudicator">Adjudicator</option></select><button id="assign">다음 과제 배정</button><button id="refresh-queue" class="secondary">새로고침</button></div><div id="task-list" class="task-list"></div></section>
<section id="review" class="view"><h2>Review</h2><div id="review-empty" class="notice">My queue에서 과제를 선택하세요.</div><div id="review-task"></div></section>
<section id="admin" class="view"><h2>Administration</h2><div class="notice">검증된 bundle은 먼저 격리됩니다. 업로더가 아닌 별도 admin의 승인 후에만 배정됩니다.</div><div class="grid"><div class="card"><h3>Bundle import</h3><textarea id="bundle-json" placeholder="payload-free blinded JSON"></textarea><button id="import-bundle">검증·격리</button></div><div class="card"><h3>Approve quarantined</h3><input id="approve-bundle" placeholder="Bundle ID"><button id="approve">별도 관리자 승인</button><h3 style="margin-top:22px">Role assignment</h3><input id="role-user" placeholder="Auth user ID"><input id="role-values" value="primary" placeholder="primary,secondary"><button id="assign-roles">역할 저장</button></div><div class="card"><h3>Admin export</h3><input id="admin-bundle" placeholder="Bundle ID"><button id="export-bundle">JSON export</button><p class="muted">AICA 또는 외부 서버 연결 경로가 없습니다. 비밀키와 인증 원문은 export하지 않습니다.</p></div></div><pre id="admin-output"></pre></section>
<section id="protocol" class="view"><h2>Review protocol</h2><div class="grid"><div class="card"><h3>1 · Frozen 32B proposal</h3><p class="muted">Qwen/Qwen2.5-VL-32B-Instruct의 exact revision·프롬프트·디코딩 provenance가 고정된 proposal과 추상 증거를 첫 화면에서 함께 제공합니다. 32B는 초안 제안자이며 정답자나 판정자가 아닙니다.</p></div><div class="card"><h3>2 · Human review</h3><p class="muted">Primary가 proposal을 수용·수정·거부·보류하고 근거와 confidence를 잠급니다.</p></div><div class="card"><h3>3 · Independent quality review</h3><p class="muted">다른 secondary가 같은 proposal을 보되 primary vote는 보지 않고 검수하며, 제3자가 마지막에 adjudicate합니다.</p></div></div><div class="notice">T4는 방어 불변식, 정상 예외, 예상 재적응, 평가 probe 네 필드를 정확히 기록합니다. 원문 payload·기법·실제 split·outcome은 저장하거나 노출하지 않습니다.</div><div class="notice"><strong>G0 gate:</strong> 현재 32B revision 후보는 pilot에만 허용됩니다. 검토된 model attestation과 exact claim-bundle hash를 새 서버 source에 함께 커밋하기 전에는 모든 신규 claim-bearing bundle을 거부합니다.</div><div class="notice"><strong>한계:</strong> 사람 검수가 LLM 오류나 자동화 편향을 제거한다고 보장하지 않습니다. 별도 proposal-blind reference subset이 없으면 anchoring의 인과 효과나 사람 독립 정답을 주장하지 않습니다.</div><div class="notice"><strong>연구 경계:</strong> 이 서비스는 수집 통제용 private workflow prototype입니다. G2 입력 계약, IRB/면제, 동의·보존 정책, frozen cohort 승인 없이 생성된 기록은 논문 claim denominator에 포함할 수 없습니다.</div></section>
</main></div><script>
const state={me:null,current:null,role:"primary",bundleId:""};const $=s=>document.querySelector(s);const esc=s=>String(s==null?"":s).replace(/[&<>\"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'\"':"&quot;","'":"&#39;"}[c]));const idem=()=>crypto.randomUUID();
function msg(text,kind=""){ $("#message").innerHTML=text?'<div class="notice '+kind+'">'+esc(text)+'</div>':"" }
async function api(path,options={}){const init={...options,headers:{...(options.headers||{})}};if(init.body&&!init.headers["content-type"])init.headers["content-type"]="application/json";const r=await fetch(path,init);let b={};try{b=await r.json()}catch{}if(!r.ok)throw new Error((b.error&&b.error.message)||("HTTP "+r.status));return b}
function show(name){document.querySelectorAll(".view").forEach(v=>v.classList.toggle("active",v.id===name));document.querySelectorAll(".nav button").forEach(v=>v.classList.toggle("active",v.dataset.view===name))}document.querySelectorAll(".nav button").forEach(b=>b.onclick=()=>show(b.dataset.view));
async function boot(){try{await api("/api/bootstrap",{method:"POST",body:"{}"});const me=await api("/api/me");state.me=me.user;$("#identity").textContent=me.user.email+" · "+(me.user.roles.join(", ")||"no role")+" · Account ID: "+me.user.account_id;$("#collection-mode").textContent=me.claim_collection_enabled?"Claim-enabled":"Pilot-only";await dashboard()}catch(e){msg(e.message,"error");$("#identity").textContent="접근 불가";$("#collection-mode").textContent="Pilot-only"}}
async function dashboard(){const d=await api("/api/dashboard");const approved=d.bundles.filter(b=>b.status==="approved");const select=$("#queue-bundle");const previous=select.value||state.bundleId;select.innerHTML=approved.map(b=>'<option value="'+esc(b.bundle_id)+'">'+esc(b.bundle_id)+' · '+esc(b.protocol_version)+'</option>').join("")||'<option value="">승인된 bundle 없음</option>';const preferred=[...approved].reverse().find(b=>b.protocol_version==="aamd-llm-first-human-review-v2")||approved[approved.length-1];state.bundleId=approved.some(b=>b.bundle_id===previous)?previous:(preferred?preferred.bundle_id:"");select.value=state.bundleId;$("#dashboard-cards").innerHTML=d.bundles.map(b=>'<div class="card"><h3>'+esc(b.bundle_id)+'</h3><div class="metric">'+esc(b.adjudicated)+' / '+esc(b.task_count)+'</div><p class="muted">'+esc(b.status)+' · '+esc(b.mode)+' · '+esc(b.protocol_version)+'</p></div>').join("")||'<div class="card"><h3>Bundle 없음</h3><p class="muted">관리자가 사전 계산 bundle을 가져와야 합니다.</p></div>'}
async function loadQueue(){state.role=$("#queue-role").value;state.bundleId=$("#queue-bundle").value;try{if(!state.bundleId)throw new Error("먼저 승인된 bundle을 선택하세요.");const d=await api("/api/tasks?role="+encodeURIComponent(state.role)+"&bundle_id="+encodeURIComponent(state.bundleId));$("#task-list").innerHTML=d.tasks.map(t=>'<button data-task="'+esc(t.task_id)+'"><strong>'+esc(t.task_id)+'</strong><br><span class="muted">'+esc(t.benchmark)+" · "+esc(t.status)+'</span></button>').join("")||'<div class="notice">배정된 과제가 없습니다.</div>';document.querySelectorAll("[data-task]").forEach(b=>b.onclick=()=>openTask(b.dataset.task))}catch(e){msg(e.message,"error")}}
$("#refresh-queue").onclick=loadQueue;$("#queue-role").onchange=loadQueue;$("#queue-bundle").onchange=loadQueue;$("#assign").onclick=async()=>{try{state.bundleId=$("#queue-bundle").value;if(!state.bundleId)throw new Error("먼저 승인된 bundle을 선택하세요.");await api("/api/tasks",{method:"POST",body:JSON.stringify({role:$("#queue-role").value,bundle_id:state.bundleId})});await loadQueue()}catch(e){msg(e.message,"error")}};
function judgmentForm(task,p,seed=null){const opts=task.label_options.map(o=>'<option value="'+esc(o.value)+'"'+(seed&&seed.label===o.value?' selected':'')+'>'+esc(o.label)+'</option>').join("");const t4=task.benchmark==="T4"?['defense_invariant','benign_exception','predicted_readaptation','evaluation_probe'].map(k=>'<label>'+esc(k)+'</label><textarea id="'+p+'-'+k+'">'+esc(seed&&seed.affordance?seed.affordance[k]:"")+'</textarea>').join(""):"";return '<label>Label</label><select id="'+p+'-label">'+opts+'</select><label>Confidence</label><input id="'+p+'-confidence" type="number" min="0" max="100" value="'+esc(seed?seed.confidence:70)+'"><label>Rationale</label><textarea id="'+p+'-rationale">'+esc(seed?seed.rationale:"")+'</textarea><label><input id="'+p+'-abstain" type="checkbox" style="width:auto"'+(seed&&seed.abstain?' checked':'')+'> Abstain</label>'+t4}
function llmFirstDecision(){return '<label>Review decision</label><select id="decision"><option value="accept">Accept unchanged</option><option value="edit">Edit proposal</option><option value="reject">Reject and replace</option><option value="abstain">Abstain</option></select>'}
function wireLlmFirstDecision(p){const decision=$("#decision"),abstain=$("#"+p+"-abstain");decision.onchange=()=>{abstain.checked=decision.value==="abstain"};abstain.onchange=()=>{if(abstain.checked)decision.value="abstain";else if(decision.value==="abstain")decision.value="accept"}}
function judgment(task,p){const abstain=$("#"+p+"-abstain").checked;const j={label:abstain?null:$("#"+p+"-label").value,confidence:Number($("#"+p+"-confidence").value),rationale:$("#"+p+"-rationale").value,abstain};if(task.benchmark==="T4"){j.affordance={};['defense_invariant','benign_exception','predicted_readaptation','evaluation_probe'].forEach(k=>j.affordance[k]=$("#"+p+"-"+k).value)}return j}
async function openTask(id){try{state.current=await api("/api/tasks/"+encodeURIComponent(id)+"?role="+encodeURIComponent(state.role));show("review");renderTask()}catch(e){msg(e.message,"error")}}
function renderTask(){const d=state.current,t=d.task;$("#review-empty").style.display="none";$("#review-task").innerHTML='<div class="card"><span class="pill">'+esc(t.benchmark)+'</span><span class="pill">'+esc(d.status)+'</span><h3>'+esc(t.title)+'</h3><p>'+esc(t.question)+'</p><p class="muted">'+esc(t.instructions)+'</p>'+t.evidence.map(e=>'<div class="evidence"><code>'+esc(e.handle)+" · "+esc(e.label)+'</code>'+esc(e.value)+'</div>').join("")+'</div><div id="stage" class="card" style="margin-top:14px"></div>';const s=$("#stage");
if(d.assignment.role==="primary"){if(d.workflow==="llm_first_human_review"){if(!d.final){s.innerHTML='<h3>Frozen LLM proposal</h3><p class="muted">Evidence와 proposal을 대조한 뒤 그대로 수용하거나 수정·거부·보류하세요. 내용을 바꾸면 decision도 Edit 또는 Reject로 변경해야 합니다.</p><pre>'+esc(JSON.stringify(d.proposal,null,2))+'</pre>'+llmFirstDecision()+judgmentForm(t,"j",d.proposal)+'<button id="submit-stage">Human review 잠금</button>';wireLlmFirstDecision("j");$("#submit-stage").onclick=()=>submitStage("final",{expected_version:0,decision:$("#decision").value,judgment:judgment(t,"j")})}else s.innerHTML='<h3>Primary review complete</h3><pre>'+esc(JSON.stringify(d.final,null,2))+'</pre>'}else if(!d.initial){s.innerHTML='<h3>Legacy blind initial</h3>'+judgmentForm(t,"j")+'<button id="submit-stage">최초 판정 잠금</button>';$("#submit-stage").onclick=()=>submitStage("initial",{expected_version:0,judgment:judgment(t,"j")})}else if(!d.proposal){s.innerHTML='<h3>Initial locked</h3><pre>'+esc(JSON.stringify(d.initial,null,2))+'</pre><button id="submit-stage">제안 공개</button>';$("#submit-stage").onclick=()=>submitStage("reveal",{expected_version:1,initial_event_hash:d.initial.event_hash})}else if(!d.final){s.innerHTML='<h3>Precomputed proposal</h3><pre>'+esc(JSON.stringify(d.proposal,null,2))+'</pre><label>Decision</label><select id="decision"><option>accept</option><option>retain_human</option><option>edit_after_proposal</option><option>reject_proposal</option><option>abstain_after_proposal</option></select>'+judgmentForm(t,"j")+'<button id="submit-stage">최종 판정 잠금</button>';$("#submit-stage").onclick=()=>submitStage("final",{expected_version:2,reveal_event_hash:d.reveal_receipt.event_hash,decision:$("#decision").value,judgment:judgment(t,"j")})}else s.innerHTML='<h3>Primary complete</h3><pre>'+esc(JSON.stringify(d.final,null,2))+'</pre>'}
else if(d.assignment.role==="secondary"){if(!d.secondary){if(d.workflow==="llm_first_human_review"){s.innerHTML='<h3>Independent secondary review</h3><p class="muted">같은 LLM proposal을 검수하지만 primary 판정은 서버에서 제외됩니다.</p><pre>'+esc(JSON.stringify(d.proposal,null,2))+'</pre>'+llmFirstDecision()+judgmentForm(t,"j",d.proposal)+'<button id="submit-stage">독립 검수 잠금</button>';wireLlmFirstDecision("j");$("#submit-stage").onclick=()=>submitStage("secondary",{expected_version:1,decision:$("#decision").value,judgment:judgment(t,"j")})}else{s.innerHTML='<h3>Independent secondary</h3><p class="muted">제안과 primary 판정은 서버에서 제외되었습니다.</p>'+judgmentForm(t,"j")+'<button id="submit-stage">독립 판정 잠금</button>';$("#submit-stage").onclick=()=>submitStage("secondary",{expected_version:3,judgment:judgment(t,"j")})}}else s.innerHTML='<h3>Secondary complete</h3><pre>'+esc(JSON.stringify(d.secondary,null,2))+'</pre>'}
else if(!d.adjudication){s.innerHTML='<h3>Adjudication</h3>'+(d.proposal?'<h4>Frozen proposal</h4><pre>'+esc(JSON.stringify(d.proposal,null,2))+'</pre>':'')+'<h4>Human reviews</h4><pre>'+esc(JSON.stringify(d.votes,null,2))+'</pre><label>Resolution</label><select id="resolution"><option>agreement</option><option>resolved</option><option>pending</option><option>disagreement</option><option>escalated</option></select>'+judgmentForm(t,"j")+'<button id="submit-stage">조정 결과 잠금</button>';$("#submit-stage").onclick=()=>submitStage("adjudicate",{expected_version:d.workflow==="llm_first_human_review"?2:4,resolution:$("#resolution").value,judgment:judgment(t,"j")})}else s.innerHTML='<h3>Complete</h3><pre>'+esc(JSON.stringify(d.adjudication,null,2))+'</pre>'}
async function submitStage(stage,body){try{const id=state.current.assignment.task_id;await api("/api/tasks/"+encodeURIComponent(id)+"/"+stage,{method:"POST",headers:{"idempotency-key":idem()},body:JSON.stringify(body)});await openTask(id);msg("HMAC 서버 영수증과 함께 잠겼습니다.","ok")}catch(e){msg(e.message,"error")}}
$("#import-bundle").onclick=async()=>{try{const d=await api("/api/admin/import",{method:"POST",body:$("#bundle-json").value});$("#admin-output").textContent=JSON.stringify(d,null,2);await dashboard()}catch(e){msg(e.message,"error")}};
$("#approve").onclick=async()=>{try{const d=await api("/api/admin/approve",{method:"POST",body:JSON.stringify({bundle_id:$("#approve-bundle").value})});$("#admin-output").textContent=JSON.stringify(d,null,2);await dashboard()}catch(e){msg(e.message,"error")}};
$("#assign-roles").onclick=async()=>{try{const roles=$("#role-values").value.split(",").map(x=>x.trim()).filter(Boolean);const d=await api("/api/admin/roles",{method:"POST",body:JSON.stringify({auth_user_id:$("#role-user").value,roles})});$("#admin-output").textContent=JSON.stringify(d,null,2)}catch(e){msg(e.message,"error")}};
$("#export-bundle").onclick=async()=>{try{const d=await api("/api/admin/export?bundle_id="+encodeURIComponent($("#admin-bundle").value));const blob=new Blob([JSON.stringify(d.export,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="aamd-export-"+d.export.bundle.bundle_id+".json";a.click();URL.revokeObjectURL(a.href);$("#admin-output").textContent="Export hash: "+d.export.export_hash}catch(e){msg(e.message,"error")}};boot();
</script></body></html>`;

export const __test = { canonicalize, sha256Hex, hmacHex, validateBundle, validateJudgment, rejectForbiddenKeys, assertSameOriginMutation };
export default { async fetch(request, env) { try { return await route(request, env); } catch (error) { if (error instanceof HttpError) return jsonResponse(request, { ok: false, error: { code: error.code, message: error.message } }, error.status); console.error("AAMD worker error", error); return jsonResponse(request, { ok: false, error: { code: "internal_error", message: "Internal server error" } }, 500); } } };
