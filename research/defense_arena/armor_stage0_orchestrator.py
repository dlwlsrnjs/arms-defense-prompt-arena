"""Dependency-injected live orchestrator for a prepared ARMOR Stage-0 plan.

The orchestrator never starts a server, selects a device, or imports a model
runtime.  A caller supplies all experiment-specific resolution and execution
functions.  This layer only enforces frozen contracts, sequential arm order,
per-run filesystem isolation, fail-closed evidence adaptation, and result
writing.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from .armor_stage0 import (
    Stage0Plan,
    load_prepared,
    validate_result,
    write_result,
)
from .armor_stage0_adapter import (
    Stage0Adaptation,
    adapt_instrumented_arms_row,
    provenance_fields,
)
from .asset_hashing import asset_bytes_sha256, asset_file_sha256

if TYPE_CHECKING:
    from .instrumentation import FrozenFirstMove

SnapshotSource = bytes | Path
BehaviorResolver = Callable[[str], "ResolvedBehavior"]
ArmPromptResolver = Callable[[str], "ResolvedPrompt"]
MemorySnapshotResolver = Callable[[str], SnapshotSource]
LiveRunCallable = Callable[["LiveRunContext"], Mapping[str, Any]]


class Stage0OrchestrationError(RuntimeError):
    """Raised before evidence can be mistaken for a valid Stage-0 run."""


@dataclass(frozen=True)
class ResolvedBehavior:
    """Ephemeral behavior value plus verifiable initial asset sources."""

    behavior_id: str
    value: Any
    assets: Mapping[str, SnapshotSource]


@dataclass(frozen=True)
class ResolvedPrompt:
    """Exact prompt installed for one arm and its frozen tokenizer count."""

    text: str
    token_count: int


@dataclass(frozen=True)
class LiveRunContext:
    """Frozen inputs handed to the injected model-running callable."""

    contract: Mapping[str, Any]
    behavior: ResolvedBehavior
    installed_system_prompt: str
    output_dir: Path
    immutable_initial_memory_path: Path
    working_memory_path: Path
    attacker_seed: int
    target_call_budget: int
    decoding_config: Mapping[str, Any]
    expected_stage0_provenance: Mapping[str, Any]
    workers: int = 1
    frozen_first_move: FrozenFirstMove | None = None


@dataclass(frozen=True)
class LiveRunRecord:
    run_id: str
    pair_id: str
    arm: str
    arm_position: int
    status: str
    result_path: str | None
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ResolvedInputs:
    behavior: ResolvedBehavior
    prompt: ResolvedPrompt
    memory_source: SnapshotSource
    decoding_config: Mapping[str, Any]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_sha256(source: SnapshotSource, label: str) -> str:
    if isinstance(source, bytes):
        return _sha256_bytes(source)
    if isinstance(source, Path):
        if not source.is_file():
            raise Stage0OrchestrationError(f"{label} is not a file: {source}")
        return _sha256_file(source)
    raise Stage0OrchestrationError(f"{label} resolver must return bytes or pathlib.Path")


def _asset_source_sha256(source: SnapshotSource, label: str) -> str:
    """Hash decoded image content while preserving non-image fixture support."""

    if isinstance(source, bytes):
        return asset_bytes_sha256(source)
    if isinstance(source, Path):
        if not source.is_file():
            raise Stage0OrchestrationError(f"{label} is not a file: {source}")
        return asset_file_sha256(source)
    raise Stage0OrchestrationError(f"{label} resolver must return bytes or pathlib.Path")


def _copy_source(source: SnapshotSource, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(source, bytes):
        destination.write_bytes(source)
    else:
        shutil.copyfile(source, destination)


def _arm_metadata(plan: Stage0Plan) -> dict[str, Mapping[str, Any]]:
    return {str(item["id"]): item for item in plan.manifest["arms"]}


def _pair_metadata(plan: Stage0Plan) -> dict[str, Mapping[str, Any]]:
    return {str(item["pair_id"]): item for item in plan.manifest["pairs"]}


class Stage0LiveOrchestrator:
    """Run a prepared four-arm plan sequentially through injected dependencies."""

    def __init__(
        self,
        *,
        prepared_root: str | Path,
        behavior_resolver: BehaviorResolver,
        arm_prompt_resolver: ArmPromptResolver,
        memory_snapshot_resolver: MemorySnapshotResolver,
        run_callable: LiveRunCallable,
        workers: int = 1,
    ):
        if workers != 1:
            raise Stage0OrchestrationError("Stage-0 live orchestration requires workers=1")
        self.root = Path(prepared_root).expanduser().resolve()
        self.plan = load_prepared(self.root)
        self.behavior_resolver = behavior_resolver
        self.arm_prompt_resolver = arm_prompt_resolver
        self.memory_snapshot_resolver = memory_snapshot_resolver
        self.run_callable = run_callable
        self.workers = workers
        self.arms = _arm_metadata(self.plan)
        self.pairs = _pair_metadata(self.plan)

    def _verify_isolation_contract(self, contract: Mapping[str, Any]) -> Path:
        run_root = self.root / "runs" / str(contract["run_id"])
        isolation_path = run_root / "memory" / "isolation.json"
        try:
            isolation = json.loads(isolation_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise Stage0OrchestrationError(
                f"missing or invalid run-memory isolation contract: {contract['run_id']}"
            ) from exc
        expected = {
            "run_id": contract["run_id"],
            "run_memory_namespace": contract["run_memory_namespace"],
            "initial_memory_sha256": contract["initial_memory_sha256"],
            "sharing_policy": "no_cross_arm_reads_or_writes",
        }
        for field, value in expected.items():
            if isolation.get(field) != value:
                raise Stage0OrchestrationError(
                    f"run-memory isolation mismatch:{contract['run_id']}:{field}"
                )
        return run_root

    def _resolve_inputs(self, contract: Mapping[str, Any]) -> _ResolvedInputs:
        behavior = self.behavior_resolver(str(contract["behavior_id"]))
        if not isinstance(behavior, ResolvedBehavior):
            raise Stage0OrchestrationError("behavior_resolver must return ResolvedBehavior")
        if behavior.behavior_id != contract["behavior_id"]:
            raise Stage0OrchestrationError(f"behavior id mismatch:{contract['run_id']}")
        if not isinstance(behavior.assets, Mapping):
            raise Stage0OrchestrationError("ResolvedBehavior.assets must be a mapping")
        observed_assets = {
            str(asset_id): _asset_source_sha256(source, f"asset {asset_id}")
            for asset_id, source in behavior.assets.items()
        }
        if observed_assets != contract["asset_hashes"]:
            raise Stage0OrchestrationError(f"asset hash mismatch:{contract['run_id']}")

        prompt = self.arm_prompt_resolver(str(contract["arm"]))
        if not isinstance(prompt, ResolvedPrompt):
            raise Stage0OrchestrationError("arm_prompt_resolver must return ResolvedPrompt")
        if _sha256_text(prompt.text) != contract["arm_prompt_sha256"]:
            raise Stage0OrchestrationError(f"installed prompt hash mismatch:{contract['run_id']}")
        expected_tokens = self.arms[str(contract["arm"])]["prompt_token_count"]
        if prompt.token_count != expected_tokens:
            raise Stage0OrchestrationError(f"installed prompt token-count mismatch:{contract['run_id']}")

        memory_source = self.memory_snapshot_resolver(str(contract["initial_memory_sha256"]))
        if _source_sha256(memory_source, "initial memory snapshot") != contract["initial_memory_sha256"]:
            raise Stage0OrchestrationError(f"initial memory hash mismatch:{contract['run_id']}")
        pair = self.pairs[str(contract["pair_id"])]
        decoding_config = pair["decoding_config"]
        return _ResolvedInputs(
            behavior=behavior,
            prompt=prompt,
            memory_source=memory_source,
            decoding_config=MappingProxyType(dict(decoding_config)),
        )

    def dry_run(self) -> dict[str, Any]:
        """Resolve and hash every dependency without invoking the run callable."""

        order: list[dict[str, Any]] = []
        for contract in self.plan.runs:
            self._verify_isolation_contract(contract)
            self._resolve_inputs(contract)
            order.append(
                {
                    "run_id": contract["run_id"],
                    "pair_id": contract["pair_id"],
                    "arm": contract["arm"],
                    "arm_position": contract["arm_position"],
                    "attacker_seed": contract["attacker_seed"],
                    "target_call_budget": contract["target_call_budget"],
                    "run_memory_namespace": contract["run_memory_namespace"],
                }
            )
        return {
            "protocol": self.plan.manifest["protocol"],
            "experiment_id": self.plan.manifest["experiment_id"],
            "workers": 1,
            "run_count": len(order),
            "run_order": order,
            "model_calls": 0,
            "servers_started": False,
        }

    def _materialize_memory(
        self,
        contract: Mapping[str, Any],
        source: SnapshotSource,
        *,
        result_exists: bool,
    ) -> tuple[Path, Path]:
        run_root = self._verify_isolation_contract(contract)
        memory_root = run_root / "memory"
        initial = memory_root / "initial_memory.snapshot"
        working = memory_root / "working_memory.snapshot"
        if initial.exists():
            if _sha256_file(initial) != contract["initial_memory_sha256"]:
                raise Stage0OrchestrationError(f"immutable memory snapshot drift:{contract['run_id']}")
        else:
            _copy_source(source, initial)
            initial.chmod(0o444)
            if _sha256_file(initial) != contract["initial_memory_sha256"]:
                raise Stage0OrchestrationError(
                    f"immutable memory initialization drift:{contract['run_id']}"
                )
        if result_exists:
            return initial, working
        if working.exists():
            raise Stage0OrchestrationError(
                f"partial run has working memory but no result; blind recovery required:{contract['run_id']}"
            )
        _copy_source(source, working)
        working.chmod(0o600)
        if _sha256_file(working) != contract["initial_memory_sha256"]:
            raise Stage0OrchestrationError(f"working memory initialization drift:{contract['run_id']}")
        return initial, working

    def _expected_provenance(self, contract: Mapping[str, Any]) -> Mapping[str, Any]:
        return MappingProxyType(
            {field: contract[field] for field in provenance_fields(contract)}
        )

    def execute(self) -> tuple[LiveRunRecord, ...]:
        """Execute in frozen arm order; stop immediately on incomplete evidence."""

        records: list[LiveRunRecord] = []
        for contract in self.plan.runs:
            result_path = self.root / str(contract["result_path"])
            if result_path.is_file():
                existing = validate_result(
                    json.loads(result_path.read_text(encoding="utf-8")), contract
                )
                if existing["censored"]:
                    raise Stage0OrchestrationError(
                        f"existing result requires blind rerun in a new prepared plan:{contract['run_id']}"
                    )
                records.append(
                    LiveRunRecord(
                        run_id=str(contract["run_id"]),
                        pair_id=str(contract["pair_id"]),
                        arm=str(contract["arm"]),
                        arm_position=int(contract["arm_position"]),
                        status="resumed",
                        result_path=str(result_path),
                    )
                )
                continue

            resolved = self._resolve_inputs(contract)
            initial_memory, working_memory = self._materialize_memory(
                contract, resolved.memory_source, result_exists=False
            )
            runtime_output = self.root / "runs" / str(contract["run_id"]) / "runtime"
            runtime_output.mkdir(parents=True, exist_ok=True)
            context = LiveRunContext(
                contract=MappingProxyType(dict(contract)),
                behavior=resolved.behavior,
                installed_system_prompt=resolved.prompt.text,
                output_dir=runtime_output,
                immutable_initial_memory_path=initial_memory,
                working_memory_path=working_memory,
                attacker_seed=int(contract["attacker_seed"]),
                target_call_budget=int(contract["target_call_budget"]),
                decoding_config=resolved.decoding_config,
                expected_stage0_provenance=self._expected_provenance(contract),
                workers=1,
            )
            row = self.run_callable(context)
            if not isinstance(row, Mapping):
                raise Stage0OrchestrationError(
                    f"run callable must return an instrumented ARMS mapping:{contract['run_id']}"
                )
            if _sha256_file(initial_memory) != contract["initial_memory_sha256"]:
                raise Stage0OrchestrationError(
                    f"run callable modified immutable initial memory:{contract['run_id']}"
                )
            final_memory_sha256 = _sha256_file(working_memory)
            adaptation: Stage0Adaptation = adapt_instrumented_arms_row(
                row,
                contract,
                final_run_memory_sha256=final_memory_sha256,
            )
            if adaptation.result is None:
                raise Stage0OrchestrationError(
                    f"run evidence rejected:{contract['run_id']}:{','.join(adaptation.reasons)}"
                )
            destination = write_result(self.root, adaptation.result, contract)
            records.append(
                LiveRunRecord(
                    run_id=str(contract["run_id"]),
                    pair_id=str(contract["pair_id"]),
                    arm=str(contract["arm"]),
                    arm_position=int(contract["arm_position"]),
                    status=adaptation.status,
                    result_path=str(destination),
                    reasons=adaptation.reasons,
                )
            )
            if not adaptation.stage0_eligible:
                raise Stage0OrchestrationError(
                    f"incomplete evidence written for audit and execution stopped:{contract['run_id']}"
                )
        return tuple(records)
