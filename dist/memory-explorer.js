(() => {
  "use strict";

  const DATA_URL = "./data/memory-explorer-v1.json";
  const STORAGE_PREFIX = "arms-memory-evidence-reviews-v1:";
  const RECORD_TYPES = new Set(["slots", "episodes", "transitions", "tasks"]);
  const REVIEW_STATUSES = new Set(["unreviewed", "actionable", "needs_evidence", "reviewed", "reject"]);
  const FIELD_LABELS = Object.freeze({
    slot_id: "slot ID", memory_slot_id: "memory slot", episode_id: "episode ID", transition_id: "transition ID",
    episode_ordinal: "episode ordinal", transition_ordinal: "transition ordinal", risk_category: "risk category",
    category: "category", source_dataset: "source dataset", strategy: "strategy", family: "strategy family",
    candidate_strategy: "candidate strategy", candidate_family: "candidate family", memory_decision: "memory decision",
    best_score: "best score", strict_success: "strict success", success: "success", used_memory: "used memory",
    retrieval_count: "retrieval count", query_count: "query count", queries: "queries", step_count: "step count",
    strategy_sequence: "strategy sequence", family_sequence: "family sequence", score_sequence: "score sequence",
    strategy_switches: "strategy switches", family_switches: "family switches", trajectory_present: "trajectory present",
    previous_slot_score: "previous slot score", candidate_finally_retained: "candidate retained", slot_version: "slot version",
    candidate_count: "candidate count", accepted_write_count: "accepted writes", replacement_count: "replacements",
    rejected_equal_count: "equal-score rejects", rejected_lower_count: "lower-score rejects",
    final_selected_episode_id: "selected episode", source_trace_matched: "source trace matched",
    from_query_id: "from query", to_query_id: "to query", from_strategy: "from strategy", to_strategy: "to strategy",
    from_family: "from family", to_family: "to family", operator: "adaptation operator", from_score: "from score",
    to_score: "to score", score_delta: "score delta", reached_strict_success: "reached strict success",
    target_response_exposed: "target response exposed", judge_score_exposed: "judge score exposed",
    judge_reason_exposed: "judge reason exposed", response_prefix_limit_chars: "response prefix limit",
    feedback_exposure_evidence: "feedback exposure evidence", dependency_evidence: "dependency evidence",
    task_id: "task ID", title: "work item", gap: "evidence gap", affected_count: "affected records", recommended_action: "recommended action",
    priority: "priority", scope: "scope",
  });
  const DETAIL_FIELDS = Object.freeze({
    slots: [
      "slot_id", "risk_category", "strategy", "family", "source_dataset", "best_score", "success", "queries",
      "step_count", "slot_version", "candidate_count", "accepted_write_count", "replacement_count",
      "rejected_equal_count", "rejected_lower_count", "final_selected_episode_id", "source_trace_matched",
    ],
    episodes: [
      "episode_id", "episode_ordinal", "source_dataset", "risk_category", "used_memory", "retrieval_count",
      "query_count", "strategy_sequence", "family_sequence", "score_sequence", "strategy_switches", "family_switches",
      "best_score", "strict_success", "trajectory_present", "candidate_strategy", "candidate_family", "memory_slot_id",
      "memory_decision", "previous_slot_score", "candidate_finally_retained",
    ],
    transitions: [
      "transition_id", "episode_id", "transition_ordinal", "from_query_id", "to_query_id", "from_strategy", "to_strategy",
      "from_family", "to_family", "operator", "from_score", "to_score", "score_delta", "reached_strict_success",
      "target_response_exposed", "judge_score_exposed", "judge_reason_exposed", "response_prefix_limit_chars",
      "feedback_exposure_evidence", "dependency_evidence",
    ],
    tasks: ["task_id", "title", "priority", "scope", "gap", "affected_count", "recommended_action", "family", "risk_category"],
  });

  const state = {
    packId: "unloaded",
    storageKey: `${STORAGE_PREFIX}unloaded`,
    data: { slots: [], episodes: [], transitions: [], tasks: [], limitations: [], counts: {} },
    type: "slots",
    filtered: [],
    selectedKey: null,
    reviews: {},
  };

  const byId = (id) => document.getElementById(id);
  const elements = {};
  const asArray = (value) => Array.isArray(value) ? value : [];
  const first = (...values) => values.find((value) => value !== undefined && value !== null && value !== "");
  const truthy = (value) => value === true || String(value).toLowerCase() === "true" || value === 1 || value === "1";
  const isMissing = (value) => value === undefined || value === null || value === "";
  const cleanText = (value) => {
    if (isMissing(value)) return "—";
    if (Array.isArray(value)) return value.map(cleanText).join(" → ");
    if (typeof value === "object") return "[structured metadata]";
    return String(value);
  };
  const fileSafe = (value) => String(value || "pack").replace(/[^A-Za-z0-9._-]+/g, "-").slice(0, 80);
  const recordId = (item, type) => String(first(
    item && item.slot_id,
    item && item.memory_slot_id,
    item && item.episode_id,
    item && item.transition_id,
    item && item.task_id,
    item && item.id,
    `${type}-unknown`,
  ));
  const recordKey = (item, type) => `${type}:${recordId(item, type)}`;
  const fieldValue = (item, names) => first(...names.map((name) => item && item[name]));
  const normalizedFacet = (item, facet) => {
    const aliases = {
      family: ["family", "candidate_family", "to_family", "from_family"],
      category: ["risk_category", "category", "canonical_category"],
      strategy: ["strategy", "candidate_strategy", "to_strategy", "from_strategy"],
      decision: ["memory_decision", "decision", "dependency_evidence"],
    };
    return cleanText(fieldValue(item, aliases[facet] || [facet]));
  };

  function safeJsonParse(value, fallback) {
    try { return JSON.parse(value); } catch (error) { return fallback; }
  }

  function normalizeRaw(raw) {
    const summary = raw && typeof raw.summary === "object" ? raw.summary : {};
    const source = raw && typeof raw.source === "object" ? raw.source : {};
    const provenance = raw && typeof raw.provenance === "object" ? raw.provenance : source;
    const packId = String(first(raw && raw.pack_id, summary.pack_id, source.pack_id, provenance.pack_id, raw && raw.id, "memory-pack-unidentified"));
    const slots = asArray(raw && first(raw.slots, raw.final_slots));
    const episodes = asArray(raw && raw.episodes);
    const transitions = asArray(raw && raw.transitions);
    const suppliedCounts = first(raw && raw.counts, summary.counts, {});
    const counts = suppliedCounts && typeof suppliedCounts === "object" ? suppliedCounts : {};
    const limitations = asArray(first(raw && raw.limitations, summary.limitations));
    const reviewQueue = raw && typeof raw.review_queue === "object" ? raw.review_queue : {};
    const suppliedTasks = asArray(first(raw && raw.tasks, reviewQueue.items)).map((item, index) => ({
      task_id: first(item.task_id, item.id, `evidence-gap-${index + 1}`),
      title: first(item.title, item.gap, item.evidence_gap, "Evidence review task"),
      priority: first(item.priority, "unassigned"),
      scope: first(item.scope, item.record_type, "global"),
      gap: first(item.gap, item.evidence_gap, item.title, "Evidence review required."),
      affected_count: first(item.affected_count, 0),
      recommended_action: first(item.recommended_action, item.recommended_next_action, item.completion_evidence, "Review the source evidence."),
      family: first(item.family, item.family_labels),
      risk_category: first(item.risk_category, item.category),
    }));
    return { raw, summary, source, provenance, packId, slots, episodes, transitions, counts, limitations, suppliedTasks };
  }

  function buildTasks(data) {
    const tasks = [];
    const noTrajectory = data.episodes.filter((item) => !truthy(item.trajectory_present));
    noTrajectory.forEach((item, index) => tasks.push({
      task_id: `trajectory-gap-${index + 1}`,
      priority: "high",
      scope: recordId(item, "episodes"),
      gap: "No selected trajectory is available for this episode.",
      affected_count: 1,
      recommended_action: "Inspect the sealed runtime ledger before using this episode as defense evidence.",
      family: cleanText(item.candidate_family),
      risk_category: cleanText(item.risk_category),
    }));

    const inferredTransitions = data.transitions.filter((item) => {
      const evidence = String(item.dependency_evidence || "").toLowerCase();
      return !evidence || evidence.includes("inferred") || evidence.includes("not_explicit");
    });
    if (inferredTransitions.length) tasks.push({
      task_id: "transition-edge-attestation",
      priority: "high",
      scope: "transition cohort",
      gap: "Adaptive dependencies are inferred from program order rather than an explicit runtime receipt.",
      affected_count: inferredTransitions.length,
      recommended_action: "Add an immutable parent-event receipt in a new run and compare the reconstructed edge set.",
    });

    const commit = first(
      data.provenance.producer_git_commit,
      data.provenance.git_commit,
      data.summary.producer_git_commit,
      data.raw && data.raw.producer_git_commit,
    );
    if (!commit) tasks.push({
      task_id: "producer-commit-attestation",
      priority: "high",
      scope: "pack provenance",
      gap: "The public explorer asset does not attest a producer source commit.",
      affected_count: 1,
      recommended_action: "Pin the exporter commit and rebuild the pack without rewriting the sealed source artifacts.",
    });

    if (data.slots.length) tasks.push({
      task_id: "survivor-bias-control",
      priority: "medium",
      scope: "final slot cohort",
      gap: "Final slots are survivor-biased and cannot estimate the frequency of the full attack universe.",
      affected_count: data.slots.length,
      recommended_action: "Pair slot-derived rules with all attempted episodes and a held-out leave-one-method-out test.",
    });

    return tasks;
  }

  function loadReviews() {
    let parsed = {};
    try { parsed = safeJsonParse(localStorage.getItem(state.storageKey) || "{}", {}); } catch (error) { parsed = {}; }
    state.reviews = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  }

  function persistReviews() {
    localStorage.setItem(state.storageKey, JSON.stringify(state.reviews));
    renderReviewCount();
  }

  function countFrom(names, fallback) {
    const value = first(...names.map((name) => state.data.counts[name]));
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  }

  function renderSummary() {
    elements.statSlots.textContent = String(countFrom(["slots", "final_slots", "memory_slots"], state.data.slots.length));
    elements.statEpisodes.textContent = String(countFrom(["episodes", "episode_count"], state.data.episodes.length));
    elements.statTransitions.textContent = String(countFrom(["transitions", "transition_count"], state.data.transitions.length));
    elements.packId.textContent = state.packId;
    renderReviewCount();
  }

  function renderReviewCount() {
    elements.statReviews.textContent = String(Object.keys(state.reviews).length);
  }

  function displayLimitations() {
    const defaults = [
      "Qwen2.5-VL-3B legacy 실행에서 나온 공개 가능 메타데이터입니다.",
      "최종 슬롯은 생존자 편향이 있으므로 전체 공격 우주의 빈도로 해석하지 않습니다.",
      "Transition은 runtime receipt가 아니라 event 순서에서 추론된 연결입니다.",
    ];
    const values = state.data.limitations.length ? state.data.limitations : defaults;
    elements.limitations.replaceChildren();
    values.forEach((value) => {
      const text = typeof value === "object" ? first(value.description, value.message, value.label, value.id) : value;
      const li = document.createElement("li");
      li.textContent = cleanText(text);
      elements.limitations.append(li);
    });
  }

  function currentRecords() {
    return RECORD_TYPES.has(state.type) ? asArray(state.data[state.type]) : [];
  }

  function facetValues(facet) {
    return [...new Set(currentRecords().map((item) => normalizedFacet(item, facet)).filter((value) => value && value !== "—"))]
      .sort((a, b) => a.localeCompare(b));
  }

  function fillSelect(select, values, previous) {
    select.replaceChildren();
    const all = document.createElement("option");
    all.value = "";
    all.textContent = "전체";
    select.append(all);
    values.forEach((value) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      select.append(option);
    });
    select.value = values.includes(previous) ? previous : "";
  }

  function refreshFacets() {
    fillSelect(elements.family, facetValues("family"), elements.family.value);
    fillSelect(elements.category, facetValues("category"), elements.category.value);
    fillSelect(elements.strategy, facetValues("strategy"), elements.strategy.value);
    fillSelect(elements.decision, facetValues("decision"), elements.decision.value);
  }

  function searchableText(item, type) {
    return DETAIL_FIELDS[type].map((key) => cleanText(item[key])).join(" ").toLowerCase();
  }

  function applyFilters() {
    const query = elements.search.value.trim().toLowerCase();
    const wanted = {
      family: elements.family.value,
      category: elements.category.value,
      strategy: elements.strategy.value,
      decision: elements.decision.value,
    };
    state.filtered = currentRecords().filter((item) => {
      if (query && !searchableText(item, state.type).includes(query)) return false;
      return Object.entries(wanted).every(([facet, value]) => !value || normalizedFacet(item, facet) === value);
    });
    renderRecordList();
  }

  function recordSubtitle(item, type) {
    if (type === "tasks") return `${cleanText(item.scope)} · ${cleanText(item.affected_count)} affected`;
    const values = [normalizedFacet(item, "family"), normalizedFacet(item, "category"), normalizedFacet(item, "strategy")]
      .filter((value, index, all) => value !== "—" && all.indexOf(value) === index);
    return values.join(" · ") || "metadata record";
  }

  function renderRecordList() {
    elements.list.replaceChildren();
    elements.resultCount.textContent = `${state.filtered.length} records`;
    if (!state.filtered.length) {
      const empty = document.createElement("li");
      empty.className = "memory-empty-record";
      empty.textContent = "현재 필터에 맞는 공개 메타데이터가 없습니다.";
      elements.list.append(empty);
      return;
    }
    state.filtered.forEach((item) => {
      const key = recordKey(item, state.type);
      const review = state.reviews[key] || {};
      const li = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.recordKey = key;
      button.classList.toggle("active", state.selectedKey === key);
      button.setAttribute("aria-pressed", String(state.selectedKey === key));
      const title = document.createElement("strong");
      title.textContent = state.type === "tasks" ? cleanText(first(item.title, item.task_id)) : recordId(item, state.type);
      const subtitle = document.createElement("small");
      subtitle.textContent = recordSubtitle(item, state.type);
      const badge = document.createElement("em");
      badge.textContent = REVIEW_STATUSES.has(review.status) ? review.status.replace(/_/g, " ") : "unreviewed";
      button.append(title, subtitle, badge);
      button.addEventListener("click", () => selectRecord(item, state.type));
      li.append(button);
      elements.list.append(li);
    });
  }

  function renderDetail(item, type) {
    elements.detailKind.textContent = type.toUpperCase();
    elements.detailTitle.textContent = recordId(item, type);
    elements.detailFields.replaceChildren();
    DETAIL_FIELDS[type].forEach((key) => {
      if (isMissing(item[key])) return;
      const wrapper = document.createElement("div");
      const term = document.createElement("dt");
      const value = document.createElement("dd");
      term.textContent = FIELD_LABELS[key] || key.replace(/_/g, " ");
      value.textContent = cleanText(item[key]);
      wrapper.append(term, value);
      elements.detailFields.append(wrapper);
    });
    if (!elements.detailFields.children.length) {
      const wrapper = document.createElement("div");
      const term = document.createElement("dt");
      const value = document.createElement("dd");
      term.textContent = "public metadata";
      value.textContent = "표시 가능한 필드가 없습니다.";
      wrapper.append(term, value);
      elements.detailFields.append(wrapper);
    }
  }

  function populateReview(key) {
    const review = state.reviews[key] || {};
    elements.reviewFields.disabled = false;
    elements.reviewStatus.value = REVIEW_STATUSES.has(review.status) ? review.status : "unreviewed";
    elements.reviewInvariant.value = review.defense_invariant || "";
    elements.reviewAdaptation.value = first(review.predicted_adaptation, review.expected_adaptation) || "";
    elements.reviewBenign.value = first(review.benign_exception, review.benign_preservation) || "";
    elements.reviewTask.value = review.evaluation_task || "";
    elements.reviewNote.value = review.note || "";
    updateReviewBadge(elements.reviewStatus.value);
    elements.saveState.textContent = "";
  }

  function updateReviewBadge(status) {
    const normalized = REVIEW_STATUSES.has(status) ? status : "unreviewed";
    elements.detailReviewState.textContent = normalized.replace(/_/g, " ").toUpperCase();
    elements.detailReviewState.dataset.status = normalized;
  }

  function selectRecord(item, type) {
    state.type = type;
    state.selectedKey = recordKey(item, type);
    renderDetail(item, type);
    populateReview(state.selectedKey);
    renderRecordList();
  }

  function resetSelection() {
    state.selectedKey = null;
    elements.detailKind.textContent = "SELECT A RECORD";
    elements.detailTitle.textContent = "검토할 기록을 선택하세요";
    elements.detailReviewState.textContent = "UNREVIEWED";
    elements.detailReviewState.dataset.status = "unreviewed";
    elements.detailFields.innerHTML = "<div><dt>공개 범위</dt><dd>유해 원문·응답·판정 사유를 제외한 메타데이터만 표시합니다.</dd></div>";
    elements.reviewFields.disabled = true;
    elements.reviewForm.reset();
    elements.saveState.textContent = "";
  }

  function changeType() {
    state.type = RECORD_TYPES.has(elements.recordType.value) ? elements.recordType.value : "slots";
    resetSelection();
    refreshFacets();
    applyFilters();
  }

  function saveReview(event) {
    event.preventDefault();
    if (!state.selectedKey) return;
    const status = REVIEW_STATUSES.has(elements.reviewStatus.value) ? elements.reviewStatus.value : "unreviewed";
    state.reviews[state.selectedKey] = {
      record_key: state.selectedKey,
      status,
      defense_invariant: elements.reviewInvariant.value.trim(),
      predicted_adaptation: elements.reviewAdaptation.value.trim(),
      benign_exception: elements.reviewBenign.value.trim(),
      evaluation_task: elements.reviewTask.value.trim(),
      note: elements.reviewNote.value.trim(),
      updated_at: new Date().toISOString(),
    };
    try {
      persistReviews();
      elements.saveState.textContent = "로컬 저장 완료";
      updateReviewBadge(status);
      renderRecordList();
    } catch (error) {
      elements.saveState.textContent = "브라우저 저장소를 사용할 수 없습니다.";
    }
  }

  function reviewEnvelope() {
    return {
      schema_version: 1,
      pack_id: state.packId,
      exported_at: new Date().toISOString(),
      storage_scope: "local_browser_only",
      payload_policy: "public_metadata_only_no_raw_attack_or_response",
      reviews: Object.values(state.reviews).sort((a, b) => a.record_key.localeCompare(b.record_key)),
    };
  }

  function download(content, type, filename) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function exportJson() {
    download(`${JSON.stringify(reviewEnvelope(), null, 2)}\n`, "application/json", `${fileSafe(state.packId)}-human-reviews.json`);
  }

  function csvCell(value) {
    const text = String(value === undefined || value === null ? "" : value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }

  function exportCsv() {
    const columns = ["record_key", "status", "defense_invariant", "predicted_adaptation", "benign_exception", "evaluation_task", "note", "updated_at"];
    const rows = Object.values(state.reviews).sort((a, b) => a.record_key.localeCompare(b.record_key));
    const csv = [columns.join(","), ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(","))].join("\n");
    download(`${csv}\n`, "text/csv;charset=utf-8", `${fileSafe(state.packId)}-human-reviews.csv`);
  }

  function clearReviews() {
    if (!Object.keys(state.reviews).length) {
      elements.loadState.textContent = "삭제할 로컬 검토가 없습니다.";
      return;
    }
    const confirmed = window.confirm("이 브라우저에 저장한 Memory Lab 검토를 모두 삭제할까요? 내보내지 않은 내용은 복구할 수 없습니다.");
    if (!confirmed) return;
    try { localStorage.removeItem(state.storageKey); } catch (error) { /* state is still cleared below */ }
    state.reviews = {};
    renderReviewCount();
    renderRecordList();
    if (state.selectedKey) populateReview(state.selectedKey);
    elements.loadState.textContent = "로컬 검토를 삭제했습니다. 원본 공개 메모리 데이터는 변경되지 않았습니다.";
  }

  function resetFilters() {
    elements.family.value = "";
    elements.category.value = "";
    elements.strategy.value = "";
    elements.decision.value = "";
    elements.search.value = "";
    applyFilters();
  }

  function wireEvents() {
    elements.recordType.addEventListener("change", changeType);
    [elements.family, elements.category, elements.strategy, elements.decision].forEach((select) => select.addEventListener("change", applyFilters));
    elements.search.addEventListener("input", applyFilters);
    elements.resetFilters.addEventListener("click", resetFilters);
    elements.reviewForm.addEventListener("submit", saveReview);
    elements.reviewStatus.addEventListener("change", () => updateReviewBadge(elements.reviewStatus.value));
    elements.exportJson.addEventListener("click", exportJson);
    elements.exportCsv.addEventListener("click", exportCsv);
    elements.clearReviews.addEventListener("click", clearReviews);
  }

  function collectElements() {
    Object.assign(elements, {
      statSlots: byId("memory-stat-slots"), statEpisodes: byId("memory-stat-episodes"),
      statTransitions: byId("memory-stat-transitions"), statReviews: byId("memory-stat-reviews"),
      packId: byId("memory-pack-id"), loadState: byId("memory-load-state"), recordType: byId("memory-record-type"),
      family: byId("memory-filter-family"), category: byId("memory-filter-category"), strategy: byId("memory-filter-strategy"),
      decision: byId("memory-filter-decision"), search: byId("memory-filter-search"), resultCount: byId("memory-result-count"),
      resetFilters: byId("memory-reset-filters"), list: byId("memory-record-list"), detailKind: byId("memory-detail-kind"),
      detailTitle: byId("memory-detail-title"), detailReviewState: byId("memory-detail-review-state"),
      detailFields: byId("memory-detail-fields"), reviewForm: byId("memory-review-form"), reviewFields: byId("memory-review-fields"),
      reviewStatus: byId("memory-review-status"), reviewInvariant: byId("memory-review-invariant"),
      reviewAdaptation: byId("memory-review-adaptation"), reviewBenign: byId("memory-review-benign"),
      reviewTask: byId("memory-review-task"), reviewNote: byId("memory-review-note"), saveState: byId("memory-review-save-state"),
      exportJson: byId("memory-export-json"), exportCsv: byId("memory-export-csv"), clearReviews: byId("memory-clear-reviews"),
      limitations: byId("memory-limitations-list"),
    });
    return Object.values(elements).every(Boolean);
  }

  async function loadData() {
    try {
      const response = await fetch(DATA_URL, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const normalized = normalizeRaw(await response.json());
      state.packId = normalized.packId;
      state.storageKey = `${STORAGE_PREFIX}${state.packId}`;
      state.data = { ...normalized, tasks: normalized.suppliedTasks };
      if (!state.data.tasks.length) state.data.tasks = buildTasks(state.data);
      loadReviews();
      renderSummary();
      displayLimitations();
      refreshFacets();
      applyFilters();
      elements.loadState.textContent = `${state.data.slots.length + state.data.episodes.length + state.data.transitions.length}개 payload-free record 로드 · 검토는 이 브라우저에만 저장됩니다.`;
    } catch (error) {
      elements.packId.textContent = "asset unavailable";
      elements.loadState.textContent = "Memory Explorer 데이터가 아직 생성되지 않았습니다. 공개 연구 pack을 빌드한 뒤 다시 확인하세요.";
      elements.list.innerHTML = '<li class="memory-empty-record">dist/data/memory-explorer-v1.json 생성 대기</li>';
      console.warn("Memory Explorer data unavailable", error);
    }
  }

  async function init() {
    if (!collectElements()) return;
    wireEvents();
    resetSelection();
    await loadData();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true });
  else init();
})();
