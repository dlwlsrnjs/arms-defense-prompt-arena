(() => {
  "use strict";

  const DATA_URL = "./data/aamd-demo-task-bundle-v1.json";
  const STORAGE_PREFIX = "aamd-annotation-workspace-v1:";
  const ACTIVE_POINTER_KEY = `${STORAGE_PREFIX}active-session`;
  const MAX_IMPORT_BYTES = 1024 * 1024;
  const MAX_TASKS = 200;
  const BENCHMARKS = new Set(["T1", "T2", "T3", "T4"]);
  const BUNDLE_MODES = new Set(["excluded_demo", "pilot_import", "claim_bearing_candidate"]);
  const FINAL_DISPOSITIONS = new Set([
    "accept", "retain_human", "edit_after_proposal", "reject_proposal", "abstain_after_proposal",
  ]);
  const ADJUDICATION_STATUSES = new Set(["pending", "agreement", "disagreement", "escalated", "resolved"]);
  const EVENT_STAGES = Object.freeze(["initial", "proposal_reveal", "final", "second_vote", "adjudication"]);
  const FORBIDDEN_KEYS = new Set([
    "behavior_id", "behavior_text", "harmful_prompt", "raw_prompt", "target_response", "judge_reason",
    "reflection", "attack_payload", "user_text", "assistant_text", "raw_dialogue", "raw_response",
    "attack_method", "outcome", "real_split", "split_name", "true_split",
  ]);
  const CSV_COLUMNS = Object.freeze([
    "schema_version", "bundle_id", "bundle_hash", "queue_hash", "visibility_mask_hash", "session_id", "primary_reviewer",
    "assignment_ordinal", "task_id", "benchmark", "record_handle", "record_hash", "split", "claim_bearing",
    "initial_label", "initial_confidence", "initial_evidence_handles", "initial_abstain", "initial_abstain_reason",
    "initial_rationale", "initial_invariant", "initial_benign_exception", "initial_evaluation_probe",
    "initial_predicted_readaptation", "initial_event_hash",
    "proposal_revealed", "proposal_id", "proposal_version", "proposal_label", "proposal_hash",
    "final_disposition", "final_label", "final_confidence", "final_evidence_handles", "final_note",
    "final_invariant", "final_benign_exception", "final_evaluation_probe", "final_predicted_readaptation", "final_event_hash",
    "second_reviewer", "second_label", "second_confidence", "second_evidence_handles", "second_abstain", "second_event_hash",
    "second_invariant", "second_benign_exception", "second_evaluation_probe", "second_predicted_readaptation",
    "adjudicator", "adjudication_status", "adjudicated_label", "adjudication_no_gold", "adjudication_note", "adjudication_event_hash",
    "adjudication_invariant", "adjudication_benign_exception", "adjudication_evaluation_probe",
    "adjudication_predicted_readaptation",
  ]);

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const elements = {};
  let bundle = null;
  let bundleHash = "";
  let session = null;
  let currentTaskId = null;
  let benchmarkView = "ALL";
  let secondVoteTaskId = null;

  function cacheElements() {
    const ids = [
      "aamd-mode-banner", "aamd-mode-badge", "aamd-bundle-title", "aamd-mode-note", "aamd-reviewer",
      "aamd-session-id", "aamd-start-session", "aamd-reset-session", "aamd-bundle-import", "aamd-session-status",
      "aamd-bundle-id", "aamd-bundle-hash", "aamd-queue-hash", "aamd-codebook-hash", "aamd-visibility-mask-hash",
      "aamd-proposer-version",
      "aamd-count-assigned", "aamd-count-initial", "aamd-count-final", "aamd-count-second", "aamd-count-adjudicated",
      "aamd-queue-count", "aamd-task-queue", "aamd-task-kind", "aamd-task-title", "aamd-task-state",
      "aamd-task-question", "aamd-task-instructions", "aamd-task-record", "aamd-task-hash", "aamd-task-split",
      "aamd-evidence-list", "aamd-stage-initial", "aamd-stage-proposal", "aamd-stage-final", "aamd-stage-second",
      "aamd-initial-form", "aamd-initial-fields", "aamd-initial-label", "aamd-initial-confidence",
      "aamd-initial-confidence-output", "aamd-initial-evidence", "aamd-initial-rationale", "aamd-initial-t4",
      "aamd-initial-invariant", "aamd-initial-benign", "aamd-initial-probe", "aamd-initial-readaptation",
      "aamd-initial-abstain",
      "aamd-initial-abstain-wrap", "aamd-initial-abstain-reason", "aamd-initial-status",
      "aamd-proposal-panel", "aamd-proposal-lock", "aamd-reveal-proposal", "aamd-proposal-content",
      "aamd-proposal-id", "aamd-proposal-model", "aamd-proposal-label", "aamd-proposal-confidence",
      "aamd-proposal-evidence", "aamd-proposal-rationale", "aamd-final-form", "aamd-final-fields",
      "aamd-final-disposition", "aamd-final-label", "aamd-final-confidence", "aamd-final-confidence-output",
      "aamd-final-evidence", "aamd-final-note", "aamd-final-t4", "aamd-final-invariant", "aamd-final-benign",
      "aamd-final-probe", "aamd-final-readaptation", "aamd-final-status", "aamd-second-panel", "aamd-second-lock",
      "aamd-begin-second",
      "aamd-second-form", "aamd-second-fields", "aamd-second-reviewer", "aamd-second-label",
      "aamd-second-confidence", "aamd-second-confidence-output", "aamd-second-evidence", "aamd-second-abstain",
      "aamd-second-t4", "aamd-second-invariant", "aamd-second-benign", "aamd-second-probe",
      "aamd-second-readaptation", "aamd-second-status", "aamd-adjudication-form", "aamd-adjudication-fields",
      "aamd-adjudication-status", "aamd-adjudication-t4", "aamd-adjudication-invariant",
      "aamd-adjudication-benign", "aamd-adjudication-probe", "aamd-adjudication-readaptation",
      "aamd-adjudicator", "aamd-adjudicated-label", "aamd-adjudication-no-gold", "aamd-adjudication-note",
      "aamd-adjudication-result", "aamd-export-json", "aamd-export-csv", "aamd-export-status",
    ];
    ids.forEach((id) => { elements[id] = document.getElementById(id); });
    elements.workspace = $("#aamd-workspace");
    elements.taskPanel = $(".aamd-task-panel");
    elements.benchmarkTabs = $$('[data-aamd-view]');
  }

  function stableClone(value) {
    if (Array.isArray(value)) return value.map(stableClone);
    if (value && typeof value === "object") {
      return Object.keys(value).sort().reduce((result, key) => {
        result[key] = stableClone(value[key]);
        return result;
      }, {});
    }
    return value;
  }

  function canonicalJson(value, spacing = 0) {
    return JSON.stringify(stableClone(value), null, spacing);
  }

  function queueIdentity(tasks) {
    return tasks.map((task, index) => ({
      assignment_ordinal: index + 1,
      task_id: task.task_id,
      benchmark: task.benchmark,
      record_handle: task.record_handle,
      record_hash: task.record_hash,
      split: task.split,
      claim_bearing: task.claim_bearing,
    }));
  }

  function publicTaskIdentity(task) {
    return {
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
    };
  }

  function codebookIdentity(tasks) {
    return tasks.map((task) => ({ benchmark: task.benchmark, label_options: task.label_options }));
  }

  function controlledDeliveryAdapter(candidate = bundle) {
    if (!candidate || candidate.mode !== "claim_bearing_candidate") return null;
    const adapter = window.__AAMD_CONTROLLED_DELIVERY__;
    const delivery = candidate.proposal_delivery || {};
    if (!adapter || typeof adapter.fetchProposal !== "function") return null;
    if (adapter.bundle_id !== candidate.bundle_id) return null;
    if (adapter.capability_receipt_hash !== delivery.capability_receipt_hash) return null;
    return adapter;
  }

  function canExecuteBundle(candidate = bundle) {
    return Boolean(candidate && (candidate.mode !== "claim_bearing_candidate" || controlledDeliveryAdapter(candidate)));
  }

  function canRevealProposal(annotation) {
    return Boolean(annotation && annotation.initial && !annotation.proposal_reveal);
  }

  function eventPayloadForHash(event) {
    if (!event) return null;
    const payload = stableClone(event);
    delete payload.event_hash;
    return payload;
  }

  function completeAffordance(affordance) {
    return Boolean(affordance && [
      "defense_invariant", "benign_exception", "evaluation_probe", "predicted_readaptation",
    ].every((key) => typeof affordance[key] === "string" && affordance[key].trim()));
  }

  async function sha256(value) {
    if (!window.crypto || !window.crypto.subtle) throw new Error("Web Crypto SHA-256를 사용할 수 없습니다.");
    const bytes = new TextEncoder().encode(typeof value === "string" ? value : canonicalJson(value));
    const digest = await window.crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function cleanText(value, maximum = 4000) {
    const text = String(value === undefined || value === null ? "" : value).trim();
    if (text.length > maximum) throw new Error(`텍스트가 ${maximum}자를 초과했습니다.`);
    return text;
  }

  function setStatus(element, message, kind = "") {
    if (!element) return;
    element.textContent = message;
    element.dataset.kind = kind;
  }

  function validateSafeObject(value, location = "bundle") {
    if (typeof value === "string") {
      if (value.length > 12000) throw new Error(`${location}: 문자열이 허용 길이를 초과했습니다.`);
      return;
    }
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) {
      value.forEach((item, index) => validateSafeObject(item, `${location}[${index}]`));
      return;
    }
    Object.entries(value).forEach(([key, item]) => {
      if (FORBIDDEN_KEYS.has(key.toLowerCase())) throw new Error(`${location}: 금지된 raw payload field '${key}'`);
      validateSafeObject(item, `${location}.${key}`);
    });
  }

  function requireObject(value, name) {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} object가 필요합니다.`);
    return value;
  }

  function validateBundle(candidate) {
    requireObject(candidate, "bundle");
    validateSafeObject(candidate);
    if (candidate.schema_version !== 1) throw new Error("지원하지 않는 task-bundle schema_version입니다.");
    if (!BUNDLE_MODES.has(candidate.mode)) throw new Error("bundle mode는 excluded_demo, pilot_import 또는 claim_bearing_candidate여야 합니다.");
    if (candidate.mode === "excluded_demo" && candidate.claim_bearing !== false) {
      throw new Error("excluded_demo는 claim_bearing=false여야 합니다.");
    }
    if (candidate.mode === "claim_bearing_candidate" && candidate.claim_bearing !== true) {
      throw new Error("claim_bearing_candidate는 claim_bearing=true여야 합니다.");
    }
    if (candidate.mode === "pilot_import" && candidate.claim_bearing !== false) {
      throw new Error("pilot_import는 claim_bearing=false여야 합니다.");
    }
    ["bundle_id", "protocol_version", "codebook_version", "codebook_hash"].forEach((key) => {
      if (!cleanText(candidate[key], 160)) throw new Error(`${key}가 비어 있습니다.`);
    });
    if (candidate.codebook_hash_policy !== "canonical_benchmark_label_options_v1") {
      throw new Error("지원하지 않는 codebook_hash_policy입니다.");
    }
    if (candidate.record_hash_policy !== "canonical_public_task_v1") {
      throw new Error("지원하지 않는 record_hash_policy입니다.");
    }
    if (!/^[a-f0-9]{64}$/.test(candidate.codebook_hash)) throw new Error("codebook_hash는 SHA-256 hex여야 합니다.");
    if (candidate.visibility_mask_policy !== "canonical_visibility_mask_v1") {
      throw new Error("지원하지 않는 visibility_mask_policy입니다.");
    }
    const visibilityMask = requireObject(candidate.visibility_mask, "visibility_mask");
    ["visible_before_initial_lock", "masked_until_initial_lock", "always_hidden"].forEach((key) => {
      if (!Array.isArray(visibilityMask[key]) || !visibilityMask[key].length) {
        throw new Error(`visibility_mask.${key}가 필요합니다.`);
      }
    });
    if (visibilityMask.claim_split_display !== "blinded") {
      throw new Error("visibility_mask.claim_split_display는 blinded여야 합니다.");
    }
    if (!visibilityMask.masked_until_initial_lock.includes("llm_proposal")
      || !visibilityMask.always_hidden.includes("real_split")) {
      throw new Error("visibility mask가 proposal 또는 real split을 가리지 않습니다.");
    }
    if (!/^[a-f0-9]{64}$/.test(String(candidate.visibility_mask_hash || ""))) {
      throw new Error("visibility_mask_hash는 SHA-256 hex여야 합니다.");
    }
    const provider = requireObject(candidate.proposal_provider, "proposal_provider");
    ["kind", "model_id", "revision", "template_version", "template_hash"].forEach((key) => {
      if (!cleanText(provider[key], 240)) throw new Error(`proposal_provider.${key}가 비어 있습니다.`);
    });
    if (!/^[a-f0-9]{64}$/.test(provider.template_hash)) throw new Error("proposal template_hash는 SHA-256 hex여야 합니다.");
    const delivery = requireObject(candidate.proposal_delivery, "proposal_delivery");
    if (candidate.mode === "claim_bearing_candidate") {
      if (delivery.mode !== "controlled_server_after_initial_lock" || delivery.server_phase_gate !== true
        || !/^[a-f0-9]{64}$/.test(String(delivery.capability_receipt_hash || ""))) {
        throw new Error("claim-bearing candidate는 receipt-bound controlled server delivery가 필요합니다.");
      }
    } else if (delivery.mode !== "embedded_fixture_demo_only" || delivery.server_phase_gate !== false
      || delivery.capability_receipt_hash !== null) {
      throw new Error("demo/pilot proposal은 embedded_fixture_demo_only로 선언해야 합니다.");
    }
    const assignment = requireObject(candidate.assignment, "assignment");
    if (assignment.method !== "fixed_manifest_order" || assignment.shuffle_allowed !== false) {
      throw new Error("task bundle은 fixed_manifest_order이며 shuffle_allowed=false여야 합니다.");
    }
    if (!/^[a-f0-9]{64}$/.test(String(assignment.queue_hash || ""))) throw new Error("queue_hash는 SHA-256 hex여야 합니다.");
    if (assignment.queue_hash_policy !== "canonical_ordered_task_identity_v1") {
      throw new Error("지원하지 않는 queue_hash_policy입니다.");
    }
    const boundary = requireObject(candidate.safety_boundary, "safety_boundary");
    if (boundary.payload_free !== true || boundary.raw_harmful_prompt_present !== false
      || boundary.raw_target_response_present !== false || boundary.judge_rationale_present !== false) {
      throw new Error("payload-free safety boundary를 통과하지 못했습니다.");
    }
    if (!Array.isArray(candidate.tasks) || !candidate.tasks.length || candidate.tasks.length > MAX_TASKS) {
      throw new Error(`tasks는 1–${MAX_TASKS}개여야 합니다.`);
    }
    const ids = new Set();
    candidate.tasks.forEach((task, index) => {
      requireObject(task, `tasks[${index}]`);
      if (!cleanText(task.task_id, 120) || ids.has(task.task_id)) throw new Error(`중복 또는 빈 task_id: ${task.task_id}`);
      ids.add(task.task_id);
      if (!BENCHMARKS.has(task.benchmark)) throw new Error(`${task.task_id}: benchmark는 T1–T4여야 합니다.`);
      if (!/^[a-f0-9]{64}$/.test(String(task.record_hash || ""))) throw new Error(`${task.task_id}: record_hash가 유효하지 않습니다.`);
      if (Boolean(task.claim_bearing) !== Boolean(candidate.claim_bearing)) throw new Error(`${task.task_id}: bundle claim mode와 일치하지 않습니다.`);
      if (candidate.mode === "claim_bearing_candidate" && task.split !== "blinded") {
        throw new Error(`${task.task_id}: claim-bearing split은 blinded여야 합니다.`);
      }
      if (!Array.isArray(task.evidence) || !task.evidence.length) throw new Error(`${task.task_id}: evidence가 필요합니다.`);
      const handles = new Set();
      task.evidence.forEach((item) => {
        requireObject(item, `${task.task_id}.evidence`);
        const handle = cleanText(item.handle, 160);
        if (!handle || handles.has(handle)) throw new Error(`${task.task_id}: evidence handle이 비었거나 중복입니다.`);
        handles.add(handle);
        if (!cleanText(item.label, 240) || !cleanText(item.value, 1000)) throw new Error(`${task.task_id}: evidence가 불완전합니다.`);
      });
      if (!Array.isArray(task.label_options) || task.label_options.length < 2) throw new Error(`${task.task_id}: label option이 부족합니다.`);
      const labels = new Set();
      task.label_options.forEach((option) => {
        requireObject(option, `${task.task_id}.label_options`);
        const label = cleanText(option.value, 120);
        if (!label || labels.has(label)) throw new Error(`${task.task_id}: label value가 비었거나 중복입니다.`);
        labels.add(label);
        if (!cleanText(option.label, 240) || !cleanText(option.help, 500)) throw new Error(`${task.task_id}: label 설명이 불완전합니다.`);
      });
      if (candidate.mode === "claim_bearing_candidate") {
        if (Object.prototype.hasOwnProperty.call(task, "llm_proposal")) {
          throw new Error(`${task.task_id}: claim-bearing task에 embedded proposal을 넣을 수 없습니다.`);
        }
      } else {
        const proposal = requireObject(task.llm_proposal, `${task.task_id}.llm_proposal`);
        if (!cleanText(proposal.proposal_id, 160) || !cleanText(proposal.version, 160)
          || !cleanText(proposal.rationale, 2000)) {
          throw new Error(`${task.task_id}: proposal provenance가 불완전합니다.`);
        }
        if (!labels.has(proposal.label)) throw new Error(`${task.task_id}: proposal label이 codebook에 없습니다.`);
        if (!Number.isInteger(proposal.confidence) || proposal.confidence < 0 || proposal.confidence > 100) {
          throw new Error(`${task.task_id}: proposal confidence가 유효하지 않습니다.`);
        }
        if (!Array.isArray(proposal.evidence_handles)
          || proposal.evidence_handles.some((handle) => !handles.has(handle))) {
          throw new Error(`${task.task_id}: proposal evidence handle이 task evidence에 없습니다.`);
        }
      }
      ["task_id", "benchmark_name", "record_handle", "split", "title", "question", "instructions"].forEach((key) => {
        if (!cleanText(task[key], 1200)) throw new Error(`${task.task_id}: ${key}가 비어 있습니다.`);
      });
    });
    return candidate;
  }

  async function verifyBundleHashes(candidate) {
    for (const task of candidate.tasks) {
      const actual = await sha256(publicTaskIdentity(task));
      if (actual !== task.record_hash) throw new Error(`${task.task_id}: record_hash 재계산 불일치`);
    }
    const actualCodebook = await sha256(codebookIdentity(candidate.tasks));
    if (actualCodebook !== candidate.codebook_hash) throw new Error("codebook_hash 재계산 불일치");
    const actualQueue = await sha256(queueIdentity(candidate.tasks));
    if (actualQueue !== candidate.assignment.queue_hash) throw new Error("queue_hash 재계산 불일치");
    const actualMask = await sha256(candidate.visibility_mask);
    if (actualMask !== candidate.visibility_mask_hash) throw new Error("visibility_mask_hash 재계산 불일치");
    return true;
  }

  function storageKey(localSession) {
    return `${STORAGE_PREFIX}${localSession.bundle_id}:${localSession.session_id}`;
  }

  function persistSession() {
    if (!session) return;
    const key = storageKey(session);
    localStorage.setItem(key, canonicalJson(session));
    localStorage.setItem(ACTIVE_POINTER_KEY, canonicalJson({
      bundle_id: session.bundle_id,
      bundle_hash: session.bundle_hash,
      session_key: key,
    }));
  }

  function restoreActiveSession() {
    if (!bundle || !bundleHash) return false;
    try {
      const pointer = JSON.parse(localStorage.getItem(ACTIVE_POINTER_KEY) || "null");
      if (!pointer || pointer.bundle_id !== bundle.bundle_id || pointer.bundle_hash !== bundleHash) return false;
      const restored = JSON.parse(localStorage.getItem(pointer.session_key) || "null");
      if (!restored || restored.bundle_id !== bundle.bundle_id || restored.bundle_hash !== bundleHash) return false;
      if (restored.queue_hash !== bundle.assignment.queue_hash || restored.codebook_hash !== bundle.codebook_hash
        || restored.visibility_mask_hash !== bundle.visibility_mask_hash) return false;
      if (!Array.isArray(restored.task_order)
        || restored.task_order.join("|") !== bundle.tasks.map((task) => task.task_id).join("|")) return false;
      session = restored;
      elements["aamd-reviewer"].value = session.reviewer;
      elements["aamd-reviewer"].disabled = true;
      elements["aamd-session-id"].textContent = session.session_id;
      setStatus(elements["aamd-session-status"], "이 브라우저의 활성 세션을 복원했습니다.", "ok");
      return true;
    } catch (error) {
      setStatus(elements["aamd-session-status"], `세션 복원 실패: ${error.message}`, "error");
      return false;
    }
  }

  function taskById(taskId) {
    return bundle && bundle.tasks.find((task) => task.task_id === taskId);
  }

  function isAllowedLabel(task, label) {
    return Boolean(task && label && task.label_options.some((option) => option.value === label));
  }

  function taskState(taskId) {
    if (!session) return null;
    if (!session.annotations[taskId]) {
      session.annotations[taskId] = {
        initial: null,
        proposal_reveal: null,
        final: null,
        second_vote: null,
        adjudication: null,
      };
    }
    return session.annotations[taskId];
  }

  function annotationStage(annotation) {
    if (!annotation) return "not_started";
    if (annotation.adjudication) return "adjudicated";
    if (annotation.second_vote) return "second_locked";
    if (annotation.final) return "final_locked";
    if (annotation.proposal_reveal) return "proposal_revealed";
    if (annotation.initial) return "initial_locked";
    return "not_started";
  }

  function firstPrimaryIncompleteIndex() {
    if (!session || !bundle) return -1;
    return bundle.tasks.findIndex((task) => !taskState(task.task_id).final);
  }

  function primaryQueueAccessible(task) {
    if (!session || !task || !bundle) return false;
    const taskIndex = bundle.tasks.findIndex((item) => item.task_id === task.task_id);
    const firstIncomplete = firstPrimaryIncompleteIndex();
    return firstIncomplete === -1 || taskIndex <= firstIncomplete;
  }

  function assertPrimaryQueuePosition(task) {
    if (!primaryQueueAccessible(task)) {
      const firstIncomplete = firstPrimaryIncompleteIndex();
      const expected = firstIncomplete >= 0 ? bundle.tasks[firstIncomplete].task_id : "none";
      throw new Error(`고정 queue 순서 위반: 먼저 ${expected}의 final을 잠그세요.`);
    }
  }

  function renderBundleHeader() {
    if (!bundle) return;
    const excluded = bundle.mode === "excluded_demo";
    const pilot = bundle.mode === "pilot_import";
    elements["aamd-mode-banner"].classList.toggle("excluded", excluded);
    elements["aamd-mode-banner"].classList.toggle("pilot", pilot);
    elements["aamd-mode-banner"].classList.toggle("candidate", !excluded && !pilot);
    elements["aamd-mode-badge"].textContent = excluded
      ? "EXCLUDED DEMO · NOT CLAIM-BEARING"
      : pilot
        ? "PILOT IMPORT · NOT CLAIM-BEARING"
        : "CLAIM-BEARING CANDIDATE · LOCAL CAPTURE ONLY";
    elements["aamd-bundle-title"].textContent = bundle.bundle_id;
    elements["aamd-mode-note"].textContent = excluded
      ? "안전한 추상 metadata fixture입니다. 이 브라우저 기록은 논문 원장이 아니며 export 후 별도 검증이 필요합니다."
      : pilot
        ? "가져온 파일럿 bundle입니다. codebook·UI·교육 검증 전용이며 claim-bearing split에 들어갈 수 없습니다."
        : canExecuteBundle(bundle)
          ? "통제 서버 capability가 연결된 claim-bearing 후보입니다. signed ingestion·중복 검사·append-only validator 전에는 논문 데이터가 아닙니다."
          : "공개 정적 사이트는 claim-bearing 세션을 시작하지 않습니다. initial lock 뒤 proposal을 전달하는 receipt-bound 통제 서버 capability가 필요합니다.";
    elements["aamd-bundle-id"].textContent = bundle.bundle_id;
    elements["aamd-bundle-hash"].textContent = bundleHash || "계산 중…";
    elements["aamd-queue-hash"].textContent = bundle.assignment.queue_hash;
    elements["aamd-codebook-hash"].textContent = bundle.codebook_hash;
    elements["aamd-visibility-mask-hash"].textContent = bundle.visibility_mask_hash;
    elements["aamd-proposer-version"].textContent = `${bundle.proposal_provider.model_id} @ ${bundle.proposal_provider.revision}`;
  }

  function renderProgress() {
    const states = session ? bundle.tasks.map((task) => taskState(task.task_id)) : [];
    const count = (field) => states.filter((state) => state && state[field]).length;
    elements["aamd-count-assigned"].textContent = String(bundle ? bundle.tasks.length : 0);
    elements["aamd-count-initial"].textContent = String(count("initial"));
    elements["aamd-count-final"].textContent = String(count("final"));
    elements["aamd-count-second"].textContent = String(count("second_vote"));
    elements["aamd-count-adjudicated"].textContent = String(count("adjudication"));
    const exportEnabled = Boolean(session);
    elements["aamd-export-json"].disabled = !exportEnabled;
    elements["aamd-export-csv"].disabled = !exportEnabled;
    elements["aamd-start-session"].disabled = Boolean(session) || !bundle || !canExecuteBundle(bundle);
    elements["aamd-reset-session"].disabled = !session;
  }

  function filteredTasks() {
    if (!bundle) return [];
    return benchmarkView === "ALL" ? bundle.tasks : bundle.tasks.filter((task) => task.benchmark === benchmarkView);
  }

  function renderQueue() {
    const tasks = filteredTasks();
    elements["aamd-task-queue"].replaceChildren();
    elements["aamd-queue-count"].textContent = `${tasks.length} / ${bundle ? bundle.tasks.length : 0} tasks`;
    tasks.forEach((task) => {
      const ordinal = bundle.tasks.findIndex((item) => item.task_id === task.task_id) + 1;
      const state = annotationStage(session ? taskState(task.task_id) : null);
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.taskId = task.task_id;
      button.classList.toggle("active", task.task_id === currentTaskId);
      button.disabled = !session || !primaryQueueAccessible(task);
      const ordinalLabel = document.createElement("span");
      ordinalLabel.textContent = String(ordinal).padStart(2, "0");
      const copy = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = `${task.benchmark} · ${task.title}`;
      const small = document.createElement("small");
      small.textContent = `${task.task_id} · ${state.replaceAll("_", " ")}`;
      copy.append(strong, small);
      button.append(ordinalLabel, copy);
      item.append(button);
      elements["aamd-task-queue"].append(item);
    });
  }

  function populateLabelSelect(select, task, selected = "") {
    select.replaceChildren();
    const empty = document.createElement("option");
    empty.value = "";
    empty.textContent = "선택하세요";
    select.append(empty);
    if (!task) return;
    task.label_options.forEach((option) => {
      const element = document.createElement("option");
      element.value = option.value;
      element.textContent = `${option.label} — ${option.help}`;
      element.selected = option.value === selected;
      select.append(element);
    });
  }

  function fillEvidenceList(task) {
    elements["aamd-evidence-list"].replaceChildren();
    task.evidence.forEach((evidence) => {
      const article = document.createElement("article");
      const header = document.createElement("div");
      const code = document.createElement("code");
      code.textContent = evidence.handle;
      const label = document.createElement("strong");
      label.textContent = evidence.label;
      header.append(code, label);
      const value = document.createElement("p");
      value.textContent = evidence.value;
      article.append(header, value);
      elements["aamd-evidence-list"].append(article);
    });
  }

  function setFieldsetLocked(fieldset, locked) {
    fieldset.disabled = locked;
    fieldset.classList.toggle("locked", locked);
  }

  function setValue(id, value = "") {
    elements[id].value = value === null || value === undefined ? "" : String(value);
  }

  function renderStages(annotation) {
    const pairs = [
      ["aamd-stage-initial", Boolean(annotation && annotation.initial)],
      ["aamd-stage-proposal", Boolean(annotation && annotation.proposal_reveal)],
      ["aamd-stage-final", Boolean(annotation && annotation.final)],
      ["aamd-stage-second", Boolean(annotation && annotation.second_vote)],
    ];
    pairs.forEach(([id, complete], index) => {
      elements[id].classList.toggle("complete", complete);
      const previousComplete = index === 0 || pairs[index - 1][1];
      elements[id].classList.toggle("active", !complete && previousComplete);
    });
  }

  function renderInitial(task, annotation) {
    const initial = annotation && annotation.initial;
    populateLabelSelect(elements["aamd-initial-label"], task, initial && initial.label);
    setValue("aamd-initial-confidence", initial ? initial.confidence : 50);
    elements["aamd-initial-confidence-output"].textContent = String(initial ? initial.confidence : 50);
    setValue("aamd-initial-evidence", initial ? initial.evidence_handles.join(", ") : "");
    setValue("aamd-initial-rationale", initial ? initial.rationale : "");
    elements["aamd-initial-abstain"].checked = Boolean(initial && initial.abstain);
    setValue("aamd-initial-abstain-reason", initial ? initial.abstain_reason : "");
    elements["aamd-initial-abstain-wrap"].hidden = !elements["aamd-initial-abstain"].checked;
    const isT4 = task.benchmark === "T4";
    elements["aamd-initial-t4"].hidden = !isT4;
    setValue("aamd-initial-invariant", initial && initial.affordance ? initial.affordance.defense_invariant : "");
    setValue("aamd-initial-benign", initial && initial.affordance ? initial.affordance.benign_exception : "");
    setValue("aamd-initial-probe", initial && initial.affordance ? initial.affordance.evaluation_probe : "");
    setValue("aamd-initial-readaptation", initial && initial.affordance ? initial.affordance.predicted_readaptation : "");
    const inOrder = primaryQueueAccessible(task);
    setFieldsetLocked(elements["aamd-initial-fields"], !session || !inOrder || Boolean(initial));
    setStatus(
      elements["aamd-initial-status"],
      initial ? `LOCKED · ${initial.event_hash.slice(0, 12)}…` : inOrder ? "LLM proposal은 숨겨져 있습니다." : "앞선 assignment의 final을 먼저 잠그세요.",
      initial ? "ok" : "",
    );
  }

  function renderProposal(task, annotation) {
    const revealed = annotation && annotation.proposal_reveal;
    const canReveal = Boolean(session && primaryQueueAccessible(task) && canRevealProposal(annotation));
    elements["aamd-reveal-proposal"].disabled = !canReveal;
    elements["aamd-proposal-panel"].classList.toggle("locked", !revealed);
    elements["aamd-proposal-lock"].textContent = revealed ? "REVEALED AFTER LOCK" : "HIDDEN";
    elements["aamd-proposal-content"].hidden = !revealed;
    if (!revealed) return;
    const proposal = revealed.proposal;
    elements["aamd-proposal-id"].textContent = proposal.proposal_id;
    elements["aamd-proposal-model"].textContent = `${bundle.proposal_provider.model_id} @ ${bundle.proposal_provider.revision}`;
    elements["aamd-proposal-label"].textContent = proposal.label;
    elements["aamd-proposal-confidence"].textContent = `${proposal.confidence}%`;
    elements["aamd-proposal-evidence"].textContent = proposal.evidence_handles.join(", ");
    elements["aamd-proposal-rationale"].textContent = proposal.rationale;
  }

  function renderFinal(task, annotation) {
    const final = annotation && annotation.final;
    populateLabelSelect(elements["aamd-final-label"], task, final && final.label);
    setValue("aamd-final-disposition", final ? final.disposition : "");
    setValue("aamd-final-confidence", final ? final.confidence : 50);
    elements["aamd-final-confidence-output"].textContent = String(final ? final.confidence : 50);
    setValue("aamd-final-evidence", final ? final.evidence_handles.join(", ") : "");
    setValue("aamd-final-note", final ? final.note : "");
    const isT4 = task.benchmark === "T4";
    elements["aamd-final-t4"].hidden = !isT4;
    setValue("aamd-final-invariant", final && final.affordance ? final.affordance.defense_invariant : "");
    setValue("aamd-final-benign", final && final.affordance ? final.affordance.benign_exception : "");
    setValue("aamd-final-probe", final && final.affordance ? final.affordance.evaluation_probe : "");
    setValue("aamd-final-readaptation", final && final.affordance ? final.affordance.predicted_readaptation : "");
    const available = Boolean(session && primaryQueueAccessible(task) && annotation && annotation.proposal_reveal);
    setFieldsetLocked(elements["aamd-final-fields"], !available || Boolean(final));
    setStatus(elements["aamd-final-status"], final ? `LOCKED · ${final.event_hash.slice(0, 12)}…` : (available ? "제안과 initial을 비교해 최종 판정하세요." : "제안 공개 후 활성화됩니다."), final ? "ok" : "");
  }

  function renderSecond(task, annotation) {
    const second = annotation && annotation.second_vote;
    const adjudication = annotation && annotation.adjudication;
    const inProgress = currentTaskId === secondVoteTaskId && !second;
    elements.taskPanel.classList.toggle("second-vote-focus", inProgress);
    elements["aamd-begin-second"].disabled = !session || !annotation || !annotation.final || Boolean(second);
    elements["aamd-second-form"].hidden = !inProgress;
    elements["aamd-adjudication-form"].hidden = !second || Boolean(adjudication);
    elements["aamd-second-lock"].textContent = adjudication ? "ADJUDICATED" : second ? "VOTE LOCKED" : inProgress ? "BLIND VOTE ACTIVE" : "WAITING";
    populateLabelSelect(elements["aamd-second-label"], task, second && second.label);
    populateLabelSelect(elements["aamd-adjudicated-label"], task, adjudication && adjudication.label);
    const isT4 = task.benchmark === "T4";
    elements["aamd-second-t4"].hidden = !isT4;
    setValue("aamd-second-invariant", second && second.affordance ? second.affordance.defense_invariant : "");
    setValue("aamd-second-benign", second && second.affordance ? second.affordance.benign_exception : "");
    setValue("aamd-second-probe", second && second.affordance ? second.affordance.evaluation_probe : "");
    setValue("aamd-second-readaptation", second && second.affordance ? second.affordance.predicted_readaptation : "");
    if (second) {
      setValue("aamd-second-reviewer", second.reviewer);
      setValue("aamd-second-confidence", second.confidence);
      elements["aamd-second-confidence-output"].textContent = String(second.confidence);
      setValue("aamd-second-evidence", second.evidence_handles.join(", "));
      elements["aamd-second-abstain"].checked = second.abstain;
      setFieldsetLocked(elements["aamd-second-fields"], true);
      setStatus(elements["aamd-second-status"], `LOCKED · ${second.event_hash.slice(0, 12)}…`, "ok");
    } else {
      setValue("aamd-second-reviewer", "");
      setValue("aamd-second-confidence", 50);
      elements["aamd-second-confidence-output"].textContent = "50";
      setValue("aamd-second-evidence", "");
      elements["aamd-second-abstain"].checked = false;
      setFieldsetLocked(elements["aamd-second-fields"], !inProgress);
      setStatus(elements["aamd-second-status"], inProgress ? "첫 판정과 proposal은 숨김 처리됐습니다." : "", "");
    }
    if (adjudication) {
      setValue("aamd-adjudicator", adjudication.adjudicator);
      setValue("aamd-adjudication-status", adjudication.status);
      setValue("aamd-adjudicated-label", adjudication.label);
      elements["aamd-adjudication-no-gold"].checked = adjudication.no_gold;
      setValue("aamd-adjudication-note", adjudication.note);
      setValue("aamd-adjudication-invariant", adjudication.affordance ? adjudication.affordance.defense_invariant : "");
      setValue("aamd-adjudication-benign", adjudication.affordance ? adjudication.affordance.benign_exception : "");
      setValue("aamd-adjudication-probe", adjudication.affordance ? adjudication.affordance.evaluation_probe : "");
      setValue("aamd-adjudication-readaptation", adjudication.affordance ? adjudication.affordance.predicted_readaptation : "");
      elements["aamd-adjudication-t4"].hidden = !(isT4 && adjudication.status === "resolved");
      setFieldsetLocked(elements["aamd-adjudication-fields"], true);
      setStatus(elements["aamd-adjudication-result"], `LOCKED · ${adjudication.event_hash.slice(0, 12)}…`, "ok");
    } else {
      setValue("aamd-adjudicator", "");
      setValue("aamd-adjudication-status", "pending");
      setValue("aamd-adjudicated-label", "");
      elements["aamd-adjudication-no-gold"].checked = true;
      setValue("aamd-adjudication-note", "");
      setValue("aamd-adjudication-invariant", "");
      setValue("aamd-adjudication-benign", "");
      setValue("aamd-adjudication-probe", "");
      setValue("aamd-adjudication-readaptation", "");
      elements["aamd-adjudication-t4"].hidden = true;
      setFieldsetLocked(elements["aamd-adjudication-fields"], !second);
      setStatus(elements["aamd-adjudication-result"], second ? "두 독립 판정을 비교해 상태를 기록하세요." : "", "");
    }
  }

  function renderTask() {
    const task = taskById(currentTaskId);
    if (!task) {
      elements["aamd-task-kind"].textContent = "SELECT A TASK";
      elements["aamd-task-title"].textContent = session ? "queue에서 task를 선택하세요" : "세션을 시작하고 task를 선택하세요";
      return;
    }
    const annotation = session ? taskState(task.task_id) : null;
    const ordinal = bundle.tasks.findIndex((item) => item.task_id === task.task_id) + 1;
    const state = annotationStage(annotation);
    elements["aamd-task-kind"].textContent = `${task.benchmark} · ${task.benchmark_name} · ASSIGNMENT ${String(ordinal).padStart(2, "0")}`;
    elements["aamd-task-title"].textContent = task.title;
    elements["aamd-task-state"].textContent = state.replaceAll("_", " ").toUpperCase();
    elements["aamd-task-question"].textContent = task.question;
    elements["aamd-task-instructions"].textContent = task.instructions;
    elements["aamd-task-record"].textContent = task.record_handle;
    elements["aamd-task-hash"].textContent = task.record_hash;
    elements["aamd-task-split"].textContent = task.claim_bearing
      ? "BLINDED · claim-bearing candidate"
      : `${task.split} · ${bundle.mode === "pilot_import" ? "pilot import" : "excluded demo"}`;
    fillEvidenceList(task);
    renderStages(annotation);
    renderInitial(task, annotation);
    renderProposal(task, annotation);
    renderFinal(task, annotation);
    renderSecond(task, annotation);
  }

  function renderAll() {
    renderBundleHeader();
    renderProgress();
    const visible = filteredTasks();
    const currentVisibleAndAccessible = visible.some((task) => task.task_id === currentTaskId && primaryQueueAccessible(task));
    if (!currentVisibleAndAccessible) {
      const nextAccessible = visible.find((task) => primaryQueueAccessible(task));
      currentTaskId = nextAccessible ? nextAccessible.task_id : null;
    }
    renderQueue();
    renderTask();
  }

  function validPseudonym(value) {
    return /^[A-Za-z0-9][A-Za-z0-9._-]{2,39}$/.test(value);
  }

  async function startSession() {
    if (!bundle || !bundleHash) return;
    if (!canExecuteBundle(bundle)) {
      setStatus(
        elements["aamd-session-status"],
        "claim-bearing 세션은 receipt-bound controlled delivery adapter 없이는 시작할 수 없습니다.",
        "error",
      );
      return;
    }
    const reviewer = cleanText(elements["aamd-reviewer"].value, 40);
    if (!validPseudonym(reviewer)) {
      setStatus(elements["aamd-session-status"], "pseudonym은 영문·숫자로 시작하는 3–40자이며 . _ - 만 사용할 수 있습니다.", "error");
      elements["aamd-reviewer"].focus();
      return;
    }
    const createdAt = new Date().toISOString();
    const idHash = await sha256(`${bundleHash}|${reviewer}|${createdAt}`);
    session = {
      schema_version: 1,
      protocol_version: bundle.protocol_version,
      session_id: `local-${idHash.slice(0, 16)}`,
      created_at: createdAt,
      storage_scope: "local_browser_only",
      authoritative_ledger: false,
      reviewer,
      bundle_id: bundle.bundle_id,
      bundle_hash: bundleHash,
      queue_hash: bundle.assignment.queue_hash,
      codebook_hash: bundle.codebook_hash,
      visibility_mask_hash: bundle.visibility_mask_hash,
      mode: bundle.mode,
      claim_bearing_candidate: bundle.claim_bearing,
      task_order: bundle.tasks.map((task) => task.task_id),
      annotations: {},
    };
    bundle.tasks.forEach((task) => taskState(task.task_id));
    elements["aamd-reviewer"].disabled = true;
    elements["aamd-session-id"].textContent = session.session_id;
    currentTaskId = filteredTasks()[0] ? filteredTasks()[0].task_id : bundle.tasks[0].task_id;
    persistSession();
    setStatus(elements["aamd-session-status"], "고정 reviewer·queue 세션을 시작했습니다.", "ok");
    renderAll();
  }

  function resetSession() {
    if (!session) return;
    const confirmed = window.confirm("이 로컬 세션의 잠긴 annotation을 삭제하시겠습니까? 먼저 JSON/CSV export를 권장합니다.");
    if (!confirmed) return;
    localStorage.removeItem(storageKey(session));
    localStorage.removeItem(ACTIVE_POINTER_KEY);
    session = null;
    currentTaskId = null;
    secondVoteTaskId = null;
    elements["aamd-reviewer"].disabled = false;
    elements["aamd-reviewer"].value = "";
    elements["aamd-session-id"].textContent = "세션 시작 전";
    setStatus(elements["aamd-session-status"], "로컬 세션을 삭제했습니다. task bundle은 유지됩니다.", "ok");
    renderAll();
  }

  function parseEvidenceHandles(text, task, { required = true } = {}) {
    const handles = [...new Set(String(text || "").split(/[\s,]+/).map((value) => value.trim()).filter(Boolean))].sort();
    const allowed = new Set(task.evidence.map((item) => item.handle));
    if (required && !handles.length) throw new Error("evidence handle을 하나 이상 입력하세요.");
    const unknown = handles.filter((handle) => !allowed.has(handle));
    if (unknown.length) throw new Error(`task에 없는 evidence handle: ${unknown.join(", ")}`);
    return handles;
  }

  function readAffordance(prefix, required) {
    const affordance = {
      defense_invariant: cleanText(elements[`aamd-${prefix}-invariant`].value, 2000),
      benign_exception: cleanText(elements[`aamd-${prefix}-benign`].value, 2000),
      evaluation_probe: cleanText(elements[`aamd-${prefix}-probe`].value, 2000),
      predicted_readaptation: cleanText(elements[`aamd-${prefix}-readaptation`].value, 2000),
    };
    if (required && Object.values(affordance).some((value) => !value)) {
      throw new Error("T4는 invariant, benign exception, evaluation probe, predicted re-adaptation을 모두 작성해야 합니다.");
    }
    return affordance;
  }

  function validateProposal(task, proposal) {
    requireObject(proposal, `${task.task_id}.proposal`);
    validateSafeObject(proposal, `${task.task_id}.proposal`);
    if (!cleanText(proposal.proposal_id, 160) || !cleanText(proposal.version, 160)
      || !cleanText(proposal.rationale, 2000)) {
      throw new Error(`${task.task_id}: proposal provenance가 불완전합니다.`);
    }
    if (!isAllowedLabel(task, proposal.label)) throw new Error(`${task.task_id}: proposal label이 codebook에 없습니다.`);
    if (!Number.isInteger(proposal.confidence) || proposal.confidence < 0 || proposal.confidence > 100) {
      throw new Error(`${task.task_id}: proposal confidence가 유효하지 않습니다.`);
    }
    const handles = new Set(task.evidence.map((item) => item.handle));
    if (!Array.isArray(proposal.evidence_handles)
      || proposal.evidence_handles.some((handle) => !handles.has(handle))) {
      throw new Error(`${task.task_id}: proposal evidence handle이 task evidence에 없습니다.`);
    }
    return stableClone(proposal);
  }

  async function lockInitial(event) {
    event.preventDefault();
    const task = taskById(currentTaskId);
    const annotation = task && taskState(task.task_id);
    if (!task || !annotation || annotation.initial) return;
    try {
      assertPrimaryQueuePosition(task);
      const abstain = elements["aamd-initial-abstain"].checked;
      const label = cleanText(elements["aamd-initial-label"].value, 120) || null;
      const abstainReason = cleanText(elements["aamd-initial-abstain-reason"].value, 500) || null;
      if (!abstain && !label) throw new Error("primary label을 선택하세요.");
      if (!abstain && !isAllowedLabel(task, label)) throw new Error("primary label이 현재 task codebook에 없습니다.");
      if (abstain && !abstainReason) throw new Error("abstain reason을 입력하세요.");
      const rationale = cleanText(elements["aamd-initial-rationale"].value, 2000);
      if (!rationale) throw new Error("초기 판단 rationale을 입력하세요.");
      const payload = {
        event_type: "human_initial_locked",
        task_id: task.task_id,
        record_hash: task.record_hash,
        visibility_mask_hash: bundle.visibility_mask_hash,
        reviewer: session.reviewer,
        label: abstain ? null : label,
        confidence: Number(elements["aamd-initial-confidence"].value),
        evidence_handles: parseEvidenceHandles(elements["aamd-initial-evidence"].value, task, { required: !abstain }),
        rationale,
        abstain,
        abstain_reason: abstainReason,
        affordance: task.benchmark === "T4" ? readAffordance("initial", !abstain) : null,
        visibility: {
          llm_proposal_visible: false,
          attack_method_visible: false,
          outcome_visible: false,
          split_name_visible: !task.claim_bearing,
        },
        locked_at: new Date().toISOString(),
      };
      payload.event_hash = await sha256(payload);
      annotation.initial = payload;
      persistSession();
      setStatus(elements["aamd-initial-status"], `LOCKED · ${payload.event_hash.slice(0, 12)}…`, "ok");
      renderAll();
    } catch (error) {
      setStatus(elements["aamd-initial-status"], error.message, "error");
    }
  }

  async function revealProposal() {
    const task = taskById(currentTaskId);
    const annotation = task && taskState(task.task_id);
    if (!task || !annotation || !canRevealProposal(annotation)) return;
    assertPrimaryQueuePosition(task);
    let proposal;
    let deliveryReceiptHash = null;
    if (bundle.mode === "claim_bearing_candidate") {
      const adapter = controlledDeliveryAdapter(bundle);
      if (!adapter) throw new Error("controlled delivery capability가 연결되지 않았습니다.");
      const response = requireObject(await adapter.fetchProposal({
        bundle_id: bundle.bundle_id,
        bundle_hash: bundleHash,
        task_id: task.task_id,
        record_hash: task.record_hash,
        initial_event_hash: annotation.initial.event_hash,
        visibility_mask_hash: bundle.visibility_mask_hash,
      }), "controlled proposal response");
      if (!/^[a-f0-9]{64}$/.test(String(response.delivery_receipt_hash || ""))) {
        throw new Error("controlled proposal response에 delivery receipt가 없습니다.");
      }
      deliveryReceiptHash = response.delivery_receipt_hash;
      proposal = validateProposal(task, response.proposal);
    } else {
      proposal = validateProposal(task, task.llm_proposal);
    }
    const proposalHash = await sha256({ provider: bundle.proposal_provider, proposal });
    const payload = {
      event_type: "llm_proposal_revealed",
      task_id: task.task_id,
      record_hash: task.record_hash,
      visibility_mask_hash: bundle.visibility_mask_hash,
      initial_event_hash: annotation.initial.event_hash,
      delivery_mode: bundle.proposal_delivery.mode,
      delivery_receipt_hash: deliveryReceiptHash,
      proposal_id: proposal.proposal_id,
      proposal_version: proposal.version,
      proposal_hash: proposalHash,
      proposal,
      revealed_at: new Date().toISOString(),
    };
    payload.event_hash = await sha256(payload);
    annotation.proposal_reveal = payload;
    persistSession();
    renderAll();
  }

  async function lockFinal(event) {
    event.preventDefault();
    const task = taskById(currentTaskId);
    const annotation = task && taskState(task.task_id);
    if (!task || !annotation || !annotation.proposal_reveal || annotation.final) return;
    try {
      assertPrimaryQueuePosition(task);
      const disposition = cleanText(elements["aamd-final-disposition"].value, 120);
      if (!FINAL_DISPOSITIONS.has(disposition)) throw new Error("최종 decision을 선택하세요.");
      const abstain = disposition === "abstain_after_proposal";
      const proposal = annotation.proposal_reveal.proposal;
      let label = cleanText(elements["aamd-final-label"].value, 120) || null;
      if (disposition === "accept") label = proposal.label;
      if (disposition === "retain_human") label = annotation.initial.label;
      if (!abstain && !label) throw new Error("final label을 선택하세요.");
      if (!abstain && !isAllowedLabel(task, label)) throw new Error("final label이 현재 task codebook에 없습니다.");
      const note = cleanText(elements["aamd-final-note"].value, 2000);
      if (!["accept"].includes(disposition) && !note) throw new Error("유지·수정·기각·abstain 이유를 입력하세요.");
      const payload = {
        event_type: "human_final_locked",
        task_id: task.task_id,
        record_hash: task.record_hash,
        visibility_mask_hash: bundle.visibility_mask_hash,
        reviewer: session.reviewer,
        initial_event_hash: annotation.initial.event_hash,
        proposal_event_hash: annotation.proposal_reveal.event_hash,
        disposition,
        label: abstain ? null : label,
        confidence: Number(elements["aamd-final-confidence"].value),
        evidence_handles: parseEvidenceHandles(elements["aamd-final-evidence"].value, task, { required: !abstain }),
        note,
        affordance: task.benchmark === "T4" ? readAffordance("final", !abstain) : null,
        label_shift: annotation.initial.label === label ? "unchanged" : "changed",
        locked_at: new Date().toISOString(),
      };
      payload.event_hash = await sha256(payload);
      annotation.final = payload;
      const taskIndex = bundle.tasks.findIndex((item) => item.task_id === task.task_id);
      const nextTask = bundle.tasks[taskIndex + 1];
      if (nextTask) currentTaskId = nextTask.task_id;
      persistSession();
      setStatus(elements["aamd-final-status"], `LOCKED · ${payload.event_hash.slice(0, 12)}…`, "ok");
      renderAll();
    } catch (error) {
      setStatus(elements["aamd-final-status"], error.message, "error");
    }
  }

  function beginSecondVote() {
    const annotation = currentTaskId && taskState(currentTaskId);
    if (!annotation || !annotation.final || annotation.second_vote) return;
    secondVoteTaskId = currentTaskId;
    renderTask();
    elements["aamd-second-reviewer"].focus();
  }

  async function lockSecond(event) {
    event.preventDefault();
    const task = taskById(currentTaskId);
    const annotation = task && taskState(task.task_id);
    if (!task || !annotation || !annotation.final || annotation.second_vote) return;
    try {
      const reviewer = cleanText(elements["aamd-second-reviewer"].value, 40);
      if (!validPseudonym(reviewer)) throw new Error("2차 reviewer pseudonym 형식을 확인하세요.");
      if (reviewer === session.reviewer) throw new Error("2차 reviewer는 1차 reviewer와 달라야 합니다.");
      const abstain = elements["aamd-second-abstain"].checked;
      const label = cleanText(elements["aamd-second-label"].value, 120) || null;
      if (!abstain && !label) throw new Error("2차 label을 선택하세요.");
      if (!abstain && !isAllowedLabel(task, label)) throw new Error("2차 label이 현재 task codebook에 없습니다.");
      const payload = {
        event_type: "independent_second_vote_locked",
        task_id: task.task_id,
        record_hash: task.record_hash,
        visibility_mask_hash: bundle.visibility_mask_hash,
        reviewer,
        label: abstain ? null : label,
        confidence: Number(elements["aamd-second-confidence"].value),
        evidence_handles: parseEvidenceHandles(elements["aamd-second-evidence"].value, task, { required: !abstain }),
        abstain,
        affordance: task.benchmark === "T4" ? readAffordance("second", !abstain) : null,
        primary_judgment_visible: false,
        proposal_visible: false,
        locked_at: new Date().toISOString(),
      };
      payload.event_hash = await sha256(payload);
      annotation.second_vote = payload;
      secondVoteTaskId = null;
      persistSession();
      renderAll();
    } catch (error) {
      setStatus(elements["aamd-second-status"], error.message, "error");
    }
  }

  async function lockAdjudication(event) {
    event.preventDefault();
    const task = taskById(currentTaskId);
    const annotation = task && taskState(task.task_id);
    if (!task || !annotation || !annotation.second_vote || annotation.adjudication) return;
    try {
      const adjudicator = cleanText(elements["aamd-adjudicator"].value, 40);
      if (!validPseudonym(adjudicator)) throw new Error("adjudicator pseudonym 형식을 확인하세요.");
      if (adjudicator === session.reviewer || adjudicator === annotation.second_vote.reviewer) {
        throw new Error("adjudicator는 1차·2차 reviewer와 달라야 합니다.");
      }
      const status = cleanText(elements["aamd-adjudication-status"].value, 120);
      if (!ADJUDICATION_STATUSES.has(status)) throw new Error("adjudication status를 선택하세요.");
      const noGold = elements["aamd-adjudication-no-gold"].checked;
      const label = cleanText(elements["aamd-adjudicated-label"].value, 120) || null;
      const labelsAgree = Boolean(annotation.final.label && annotation.final.label === annotation.second_vote.label);
      if (status === "agreement") {
        if (!labelsAgree) throw new Error("두 label이 다르므로 agreement로 잠글 수 없습니다.");
        if (noGold || label !== annotation.final.label) {
          throw new Error("agreement는 일치 label을 adjudicated label로 기록하고 no-gold를 해제해야 합니다.");
        }
      } else if (status === "resolved") {
        if (noGold || !isAllowedLabel(task, label)) throw new Error("resolved는 유효한 adjudicated label이 필요합니다.");
      } else if (!noGold || label) {
        throw new Error("pending/disagreement/escalated는 no-gold를 선택하고 adjudicated label을 비워야 합니다.");
      }
      if (label && !isAllowedLabel(task, label)) throw new Error("adjudicated label이 현재 task codebook에 없습니다.");
      const note = cleanText(elements["aamd-adjudication-note"].value, 2000);
      if (status !== "agreement" && !note) throw new Error("agreement 외 상태에는 reason/codebook note가 필요합니다.");
      const payload = {
        event_type: "adjudication_status_locked",
        task_id: task.task_id,
        record_hash: task.record_hash,
        visibility_mask_hash: bundle.visibility_mask_hash,
        adjudicator,
        status,
        label: noGold ? null : label,
        no_gold: noGold,
        note,
        primary_final_event_hash: annotation.final.event_hash,
        second_vote_event_hash: annotation.second_vote.event_hash,
        labels_agree: labelsAgree,
        affordance: task.benchmark === "T4" && status === "resolved"
          ? readAffordance("adjudication", true)
          : null,
        locked_at: new Date().toISOString(),
      };
      payload.event_hash = await sha256(payload);
      annotation.adjudication = payload;
      persistSession();
      renderAll();
    } catch (error) {
      setStatus(elements["aamd-adjudication-result"], error.message, "error");
    }
  }

  function exportRows() {
    return bundle.tasks.map((task, index) => {
      const annotation = taskState(task.task_id);
      return {
        schema_version: 1,
        bundle_id: bundle.bundle_id,
        bundle_hash: bundleHash,
        queue_hash: bundle.assignment.queue_hash,
        visibility_mask_hash: bundle.visibility_mask_hash,
        session_id: session.session_id,
        primary_reviewer: session.reviewer,
        assignment_ordinal: index + 1,
        task_id: task.task_id,
        benchmark: task.benchmark,
        record_handle: task.record_handle,
        record_hash: task.record_hash,
        split: task.split,
        claim_bearing: task.claim_bearing,
        initial_label: annotation.initial && annotation.initial.label,
        initial_confidence: annotation.initial && annotation.initial.confidence,
        initial_evidence_handles: annotation.initial ? annotation.initial.evidence_handles.join("|") : "",
        initial_abstain: annotation.initial && annotation.initial.abstain,
        initial_abstain_reason: annotation.initial && annotation.initial.abstain_reason,
        initial_rationale: annotation.initial && annotation.initial.rationale,
        initial_invariant: annotation.initial && annotation.initial.affordance && annotation.initial.affordance.defense_invariant,
        initial_benign_exception: annotation.initial && annotation.initial.affordance && annotation.initial.affordance.benign_exception,
        initial_evaluation_probe: annotation.initial && annotation.initial.affordance && annotation.initial.affordance.evaluation_probe,
        initial_predicted_readaptation: annotation.initial && annotation.initial.affordance
          && annotation.initial.affordance.predicted_readaptation,
        initial_event_hash: annotation.initial && annotation.initial.event_hash,
        proposal_revealed: Boolean(annotation.proposal_reveal),
        proposal_id: annotation.proposal_reveal && annotation.proposal_reveal.proposal_id,
        proposal_version: annotation.proposal_reveal && annotation.proposal_reveal.proposal_version,
        proposal_label: annotation.proposal_reveal ? annotation.proposal_reveal.proposal.label : "",
        proposal_hash: annotation.proposal_reveal && annotation.proposal_reveal.proposal_hash,
        final_disposition: annotation.final && annotation.final.disposition,
        final_label: annotation.final && annotation.final.label,
        final_confidence: annotation.final && annotation.final.confidence,
        final_evidence_handles: annotation.final ? annotation.final.evidence_handles.join("|") : "",
        final_note: annotation.final && annotation.final.note,
        final_invariant: annotation.final && annotation.final.affordance && annotation.final.affordance.defense_invariant,
        final_benign_exception: annotation.final && annotation.final.affordance && annotation.final.affordance.benign_exception,
        final_evaluation_probe: annotation.final && annotation.final.affordance && annotation.final.affordance.evaluation_probe,
        final_predicted_readaptation: annotation.final && annotation.final.affordance
          && annotation.final.affordance.predicted_readaptation,
        final_event_hash: annotation.final && annotation.final.event_hash,
        second_reviewer: annotation.second_vote && annotation.second_vote.reviewer,
        second_label: annotation.second_vote && annotation.second_vote.label,
        second_confidence: annotation.second_vote && annotation.second_vote.confidence,
        second_evidence_handles: annotation.second_vote ? annotation.second_vote.evidence_handles.join("|") : "",
        second_abstain: annotation.second_vote && annotation.second_vote.abstain,
        second_event_hash: annotation.second_vote && annotation.second_vote.event_hash,
        second_invariant: annotation.second_vote && annotation.second_vote.affordance
          && annotation.second_vote.affordance.defense_invariant,
        second_benign_exception: annotation.second_vote && annotation.second_vote.affordance
          && annotation.second_vote.affordance.benign_exception,
        second_evaluation_probe: annotation.second_vote && annotation.second_vote.affordance
          && annotation.second_vote.affordance.evaluation_probe,
        second_predicted_readaptation: annotation.second_vote && annotation.second_vote.affordance
          && annotation.second_vote.affordance.predicted_readaptation,
        adjudicator: annotation.adjudication && annotation.adjudication.adjudicator,
        adjudication_status: annotation.adjudication && annotation.adjudication.status,
        adjudicated_label: annotation.adjudication && annotation.adjudication.label,
        adjudication_no_gold: annotation.adjudication && annotation.adjudication.no_gold,
        adjudication_note: annotation.adjudication && annotation.adjudication.note,
        adjudication_event_hash: annotation.adjudication && annotation.adjudication.event_hash,
        adjudication_invariant: annotation.adjudication && annotation.adjudication.affordance
          && annotation.adjudication.affordance.defense_invariant,
        adjudication_benign_exception: annotation.adjudication && annotation.adjudication.affordance
          && annotation.adjudication.affordance.benign_exception,
        adjudication_evaluation_probe: annotation.adjudication && annotation.adjudication.affordance
          && annotation.adjudication.affordance.evaluation_probe,
        adjudication_predicted_readaptation: annotation.adjudication && annotation.adjudication.affordance
          && annotation.adjudication.affordance.predicted_readaptation,
      };
    });
  }

  async function validateEventChain() {
    if (!session || session.bundle_hash !== bundleHash || session.queue_hash !== bundle.assignment.queue_hash
      || session.codebook_hash !== bundle.codebook_hash
      || session.visibility_mask_hash !== bundle.visibility_mask_hash) {
      throw new Error("session provenance가 현재 bundle과 일치하지 않습니다.");
    }
    let eventCount = 0;
    for (let index = 0; index < bundle.tasks.length; index += 1) {
      const task = bundle.tasks[index];
      const annotation = taskState(task.task_id);
      if (annotation.initial && bundle.tasks.slice(0, index).some((prior) => !taskState(prior.task_id).final)) {
        throw new Error(`${task.task_id}: 고정 queue보다 먼저 시작된 event가 있습니다.`);
      }
      if (annotation.proposal_reveal && !annotation.initial) throw new Error(`${task.task_id}: initial 없는 proposal event`);
      if (annotation.final && !annotation.proposal_reveal) throw new Error(`${task.task_id}: proposal 없는 final event`);
      if (annotation.second_vote && !annotation.final) throw new Error(`${task.task_id}: final 없는 second vote`);
      if (annotation.adjudication && !annotation.second_vote) throw new Error(`${task.task_id}: second vote 없는 adjudication`);
      for (const stage of EVENT_STAGES) {
        const event = annotation[stage];
        if (!event) continue;
        eventCount += 1;
        if (event.task_id !== task.task_id || event.record_hash !== task.record_hash
          || event.visibility_mask_hash !== bundle.visibility_mask_hash) {
          throw new Error(`${task.task_id}.${stage}: provenance link 불일치`);
        }
        const actual = await sha256(eventPayloadForHash(event));
        if (actual !== event.event_hash) throw new Error(`${task.task_id}.${stage}: event_hash 재계산 불일치`);
      }
      if (annotation.proposal_reveal) {
        if (annotation.proposal_reveal.initial_event_hash !== annotation.initial.event_hash) {
          throw new Error(`${task.task_id}: proposal→initial link 불일치`);
        }
        validateProposal(task, annotation.proposal_reveal.proposal);
      }
      if (annotation.final) {
        if (annotation.final.initial_event_hash !== annotation.initial.event_hash
          || annotation.final.proposal_event_hash !== annotation.proposal_reveal.event_hash) {
          throw new Error(`${task.task_id}: final event chain link 불일치`);
        }
        if (annotation.final.label && !isAllowedLabel(task, annotation.final.label)) {
          throw new Error(`${task.task_id}: final label codebook 불일치`);
        }
      }
      if (annotation.second_vote && annotation.second_vote.label
        && !isAllowedLabel(task, annotation.second_vote.label)) {
        throw new Error(`${task.task_id}: second label codebook 불일치`);
      }
      if (task.benchmark === "T4") {
        const requiredAffordances = [
          ["initial", annotation.initial, annotation.initial && !annotation.initial.abstain],
          ["final", annotation.final, annotation.final && annotation.final.disposition !== "abstain_after_proposal"],
          ["second_vote", annotation.second_vote, annotation.second_vote && !annotation.second_vote.abstain],
          ["adjudication", annotation.adjudication,
            annotation.adjudication && annotation.adjudication.status === "resolved"],
        ];
        for (const [stage, event, required] of requiredAffordances) {
          if (required && !completeAffordance(event.affordance)) {
            throw new Error(`${task.task_id}.${stage}: T4 four-field affordance가 불완전합니다.`);
          }
        }
      }
      if (annotation.adjudication) {
        if (annotation.adjudication.primary_final_event_hash !== annotation.final.event_hash
          || annotation.adjudication.second_vote_event_hash !== annotation.second_vote.event_hash) {
          throw new Error(`${task.task_id}: adjudication event chain link 불일치`);
        }
        const actualAgreement = Boolean(annotation.final.label
          && annotation.final.label === annotation.second_vote.label);
        if (annotation.adjudication.labels_agree !== actualAgreement) {
          throw new Error(`${task.task_id}: adjudication agreement 상태 불일치`);
        }
        if (annotation.adjudication.status === "agreement"
          && (!actualAgreement || annotation.adjudication.no_gold
            || annotation.adjudication.label !== annotation.final.label)) {
          throw new Error(`${task.task_id}: false agreement 상태`);
        }
        if (annotation.adjudication.status === "resolved"
          && (annotation.adjudication.no_gold || !isAllowedLabel(task, annotation.adjudication.label))) {
          throw new Error(`${task.task_id}: resolved adjudication label 불일치`);
        }
      }
    }
    return { valid: true, event_count: eventCount };
  }

  async function buildExportEnvelope() {
    const chain = await validateEventChain();
    return {
      schema_version: 1,
      export_format: "aamd-annotation-export-v1",
      deterministic_serialization: "recursive_lexicographic_object_keys_arrays_preserve_manifest_order_lf_utf8",
      storage_scope: "local_browser_only",
      authoritative_ledger: false,
      blindness_enforcement: bundle.mode === "claim_bearing_candidate"
        ? "controlled_server_after_initial_lock"
        : "ui_phase_gate_only_not_authoritative",
      event_chain_validation: {
        algorithm: "sha256_canonical_stage_payload_without_event_hash_v1",
        valid: chain.valid,
        event_count: chain.event_count,
      },
      csv_projection: {
        lossy: true,
        omits_full_stage_payloads: true,
        use_json_for_event_hash_recomputation: true,
      },
      bundle: {
        bundle_id: bundle.bundle_id,
        bundle_hash: bundleHash,
        mode: bundle.mode,
        claim_bearing_candidate: bundle.claim_bearing,
        protocol_version: bundle.protocol_version,
        codebook_version: bundle.codebook_version,
        codebook_hash: bundle.codebook_hash,
        queue_id: bundle.assignment.queue_id,
        queue_hash: bundle.assignment.queue_hash,
        visibility_mask_policy: bundle.visibility_mask_policy,
        visibility_mask_hash: bundle.visibility_mask_hash,
        visibility_mask: bundle.visibility_mask,
        proposal_provider: bundle.proposal_provider,
        proposal_delivery: bundle.proposal_delivery,
        template_hash_verification: "manifest_declared_only_template_not_in_bundle",
      },
      session: {
        session_id: session.session_id,
        created_at: session.created_at,
        primary_reviewer: session.reviewer,
      },
      task_events: bundle.tasks.map((task, index) => ({
        assignment_ordinal: index + 1,
        task_id: task.task_id,
        record_handle: task.record_handle,
        record_hash: task.record_hash,
        visibility_mask_hash: bundle.visibility_mask_hash,
        stages: stableClone(taskState(task.task_id)),
      })),
      rows: exportRows(),
    };
  }

  function csvCell(value) {
    let text = value === null || value === undefined ? "" : String(value);
    if (/^\s*[=+\-@]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  }

  function csvExport(rows) {
    const lines = [CSV_COLUMNS.map(csvCell).join(",")];
    rows.forEach((row) => lines.push(CSV_COLUMNS.map((column) => csvCell(row[column])).join(",")));
    return `${lines.join("\n")}\n`;
  }

  function downloadText(filename, text, type) {
    const blob = new Blob([text], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  async function exportAnnotations(format) {
    if (!session) return;
    try {
      let text;
      let filename;
      let type;
      if (format === "json") {
        text = `${canonicalJson(await buildExportEnvelope(), 2)}\n`;
        filename = `${bundle.bundle_id}-${session.session_id}-annotations.json`;
        type = "application/json;charset=utf-8";
      } else {
        text = csvExport(exportRows());
        filename = `${bundle.bundle_id}-${session.session_id}-annotations.csv`;
        type = "text/csv;charset=utf-8";
      }
      const digest = await sha256(text);
      downloadText(filename, text, type);
      setStatus(elements["aamd-export-status"], `${format.toUpperCase()} SHA-256 ${digest}`, "ok");
    } catch (error) {
      setStatus(elements["aamd-export-status"], error.message, "error");
    }
  }

  async function loadBundle(candidate, sourceLabel) {
    const validated = validateBundle(candidate);
    await verifyBundleHashes(validated);
    const digest = await sha256(validated);
    bundle = validated;
    bundleHash = digest;
    session = null;
    currentTaskId = null;
    secondVoteTaskId = null;
    elements["aamd-reviewer"].disabled = false;
    elements["aamd-reviewer"].value = "";
    elements["aamd-session-id"].textContent = "세션 시작 전";
    const restored = restoreActiveSession();
    if (restored) currentTaskId = bundle.tasks[0].task_id;
    const statusMessage = restored
      ? "활성 세션을 복원했습니다."
      : !canExecuteBundle(validated)
        ? `${sourceLabel} bundle hash는 검증했지만 controlled delivery capability가 없어 세션 시작은 차단되었습니다.`
        : `${sourceLabel} task bundle과 provenance hash를 검증했습니다.`;
    setStatus(elements["aamd-session-status"], statusMessage, canExecuteBundle(validated) ? "ok" : "error");
    renderAll();
  }

  async function importBundle(event) {
    const file = event.target.files && event.target.files[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > MAX_IMPORT_BYTES) {
      setStatus(elements["aamd-session-status"], "task bundle은 1 MiB 이하여야 합니다.", "error");
      return;
    }
    if (session && !window.confirm("현재 세션을 화면에서 분리하고 새 task bundle을 불러오시겠습니까? 기존 로컬 세션은 삭제되지 않습니다.")) return;
    try {
      const text = await file.text();
      const candidate = JSON.parse(text);
      await loadBundle(candidate, `가져온 ${file.name}`);
    } catch (error) {
      setStatus(elements["aamd-session-status"], `가져오기 실패: ${error.message}`, "error");
    }
  }

  function wireEvents() {
    elements["aamd-start-session"].addEventListener("click", () => startSession().catch((error) => {
      setStatus(elements["aamd-session-status"], error.message, "error");
    }));
    elements["aamd-reset-session"].addEventListener("click", resetSession);
    elements["aamd-bundle-import"].addEventListener("change", importBundle);
    elements["aamd-task-queue"].addEventListener("click", (event) => {
      const button = event.target.closest("button[data-task-id]");
      if (!button || button.disabled) return;
      currentTaskId = button.dataset.taskId;
      secondVoteTaskId = null;
      renderAll();
    });
    elements.benchmarkTabs.forEach((tab) => tab.addEventListener("click", () => {
      benchmarkView = tab.dataset.aamdView;
      elements.benchmarkTabs.forEach((item) => {
        const active = item === tab;
        item.classList.toggle("active", active);
        item.setAttribute("aria-selected", String(active));
      });
      currentTaskId = null;
      secondVoteTaskId = null;
      renderAll();
    }));
    elements["aamd-initial-confidence"].addEventListener("input", () => {
      elements["aamd-initial-confidence-output"].textContent = elements["aamd-initial-confidence"].value;
    });
    elements["aamd-final-confidence"].addEventListener("input", () => {
      elements["aamd-final-confidence-output"].textContent = elements["aamd-final-confidence"].value;
    });
    elements["aamd-second-confidence"].addEventListener("input", () => {
      elements["aamd-second-confidence-output"].textContent = elements["aamd-second-confidence"].value;
    });
    elements["aamd-initial-abstain"].addEventListener("change", () => {
      elements["aamd-initial-abstain-wrap"].hidden = !elements["aamd-initial-abstain"].checked;
    });
    elements["aamd-final-disposition"].addEventListener("change", () => {
      const task = taskById(currentTaskId);
      const annotation = task && taskState(task.task_id);
      if (!task || !annotation) return;
      if (elements["aamd-final-disposition"].value === "accept" && annotation.proposal_reveal) {
        elements["aamd-final-label"].value = annotation.proposal_reveal.proposal.label;
      }
      if (elements["aamd-final-disposition"].value === "retain_human") elements["aamd-final-label"].value = annotation.initial.label || "";
    });
    elements["aamd-adjudication-status"].addEventListener("change", () => {
      const task = taskById(currentTaskId);
      elements["aamd-adjudication-t4"].hidden = !(task && task.benchmark === "T4"
        && elements["aamd-adjudication-status"].value === "resolved");
    });
    elements["aamd-initial-form"].addEventListener("submit", lockInitial);
    elements["aamd-reveal-proposal"].addEventListener("click", () => revealProposal().catch((error) => {
      setStatus(elements["aamd-initial-status"], error.message, "error");
    }));
    elements["aamd-final-form"].addEventListener("submit", lockFinal);
    elements["aamd-begin-second"].addEventListener("click", beginSecondVote);
    elements["aamd-second-form"].addEventListener("submit", lockSecond);
    elements["aamd-adjudication-form"].addEventListener("submit", lockAdjudication);
    elements["aamd-export-json"].addEventListener("click", () => exportAnnotations("json"));
    elements["aamd-export-csv"].addEventListener("click", () => exportAnnotations("csv"));
  }

  async function init() {
    cacheElements();
    if (!elements.workspace) return;
    wireEvents();
    try {
      const response = await fetch(DATA_URL, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      await loadBundle(await response.json(), "내장 excluded demo");
    } catch (error) {
      setStatus(elements["aamd-session-status"], `내장 task bundle 로드 실패: ${error.message}`, "error");
      elements["aamd-start-session"].disabled = true;
    }
  }

  window.__AAMD_TEST__ = Object.freeze({
    canonicalJson,
    queueIdentity,
    publicTaskIdentity,
    codebookIdentity,
    validateBundle,
    verifyBundleHashes,
    validateSafeObject,
    canRevealProposal,
    isAllowedLabel,
    csvExport,
    csvColumns: CSV_COLUMNS,
  });

  window.addEventListener("DOMContentLoaded", () => {
    init().catch((error) => setStatus(elements["aamd-session-status"], error.message, "error"));
  });
})();
