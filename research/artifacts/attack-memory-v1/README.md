# Payload-free attack-memory flow pack v1

> **Publication status:** this pack is an excluded legacy pilot, not the
> claim-bearing dataset. The prospective collection, validation, annotation,
> split, and release requirements are defined in
> [`Adaptive Attack Memory Dataset v1`](../../docs/DEFENSE_EVALUATED_ADAPTIVE_ATTACK_MEMORY_DATASET_V1.md).

이 디렉터리는 Qwen2.5-VL-3B `public-v2` warm-up의 legacy 메모리 수집
과정을 원문 없이 재구성한 공개 감사 자료다. 공격 요청, 이미지 경로, 타깃
응답, judge 이유, step 문자열, reflection, 로컬 경로, 원래 behavior ID는
포함하지 않는다.

이 자료는 다음 두 질문에 답하기 위한 것이다.

1. 각 에피소드가 검색, 질의, 전략 전이, trajectory 선택을 거쳐 메모리
   슬롯에 저장·교체·폐기되는 과정은 무엇인가?
2. 최종 101개 winner slot이 전체 220개 에피소드 중 어떤 선택 과정을
   거쳐 남았는가?

## 검증된 규모

```text
220 episodes
  -> 555 retrieved labels
  -> 520 target queries
  -> 307 ordered query-to-query transitions
  -> 213 trajectory candidates + 7 no-trajectory episodes
  -> 101 new slots
     + 15 strictly-higher replacements
     + 53 equal-score rejections
     + 44 lower-score rejections
  -> 101 final slots
```

- 실제 episode 성공: `80/220 = 36.36%`
- 최종 성공 slot: `53/101 = 52.48%`
- 두 값은 다른 통계다. 후자는 max-per-slot 선택 이후의 생존자 비율이며
  공격성공률로 보고하면 안 된다.
- `results.jsonl`의 append 순서로 strict-score 규칙을 재생하면 최종 101개
  slot과 정확히 일치한다.
- 원 실행은 `workers=4`였고 insert sequence/timestamp가 없으므로 append
  순서는 wall-clock 삽입 순서의 증명값이 아니라 가장 강한 replay proxy다.

## 파일 선택

| 형식 | 파일 | 용도 |
|---|---|---|
| CSV | `csv/episodes.csv` | 한 행에 한 에피소드; 검색량, 전략·점수 sequence, 최종 삽입 결정 |
| CSV | `csv/retrievals.csv` | 순서가 보존된 검색 category/strategy label; item ID와 similarity는 미기록 |
| CSV | `csv/queries.csv` | 520개 질의의 전략, family, turn 수, image reference 수, 점수 |
| CSV | `csv/transitions.csv` | 연속 질의 사이의 전략/family 전환과 score delta |
| CSV | `csv/memory_updates.csv` | 신규·교체·동점폐기·저점폐기·trajectory 없음 결정 |
| CSV | `csv/final_slots.csv` | 최종 winner slot 101개와 생존 과정 통계 |
| JSON | `json/collection_summary.json` | provenance, 집계값, 분포, 한계, 검증 결과 |
| JSON | `json/memory_flow.json` | 220개 에피소드를 retrieval/query/transition/update로 중첩한 전체 view |
| JSONL | `jsonl/memory_flow.jsonl` | 2,042개 payload-free reconstruction event의 순차 replay/hash chain |
| JSON Schema | `schemas/*.schema.json` | episode 및 event envelope의 최소 구조 |
| Manifest | `manifest.json` | 공개 파일별 SHA-256, 크기, 레코드 수 |

## 사용 예시

CSV는 spreadsheet, Pandas, Polars, DuckDB에서 바로 읽을 수 있다.

```python
import pandas as pd

episodes = pd.read_csv("csv/episodes.csv")
updates = pd.read_csv("csv/memory_updates.csv")

print(updates["memory_decision"].value_counts())
print(episodes.groupby("risk_category")["strict_success"].mean())
```

JSON은 사이트나 분석 notebook의 계층형 episode 탐색에 적합하다.

```python
import json

flow = json.load(open("json/memory_flow.json", encoding="utf-8"))
episode = flow["episodes"][0]
print(episode["episode"])
print(episode["transitions"])
```

JSONL은 메모리 상태를 순서대로 재생하거나 event type별로 스트리밍할 때
사용한다.

```python
import json

with open("jsonl/memory_flow.jsonl", encoding="utf-8") as handle:
    for line in handle:
        event = json.loads(line)
        if event["event_type"] == "memory_update_decided":
            print(event["memory_decision"], event["memory_slot_id"])
```

파일 무결성, 레코드 수, JSONL hash chain, 형식 간 count 일치를 한 명령으로
검사한다. 이 검사는 private source 내용을 다시 검사하는 명령은 아니다.

```bash
python research/scripts/verify_attack_memory_audit.py \
  research/artifacts/attack-memory-v1
```

사이트의 **Memory Evidence Lab**은 이 pack의 payload-free projection을
슬롯·에피소드·전이·증거 공백 작업으로 보여준다. 사람 검토는 브라우저에만
저장되며 JSON/CSV로 내보낼 수 있다. 방어 불변식, 예상 적응, 정상 예외와
평가 과제를 작성하는 기준은
[`../../docs/MEMORY_EVIDENCE_REVIEW_GUIDE.md`](../../docs/MEMORY_EVIDENCE_REVIEW_GUIDE.md)에
정리돼 있다.

사람과 LLM이 함께 category를 만들 때 이 파일럿을 논문용 데이터로 승격할 수 있는
조건, blind-first annotation, anchoring 측정, fold별 taxonomy 격리와 downstream
검증 기준은
[`../../docs/HUMAN_LLM_ATTACK_DYNAMICS_DATA_PROTOCOL_V1.md`](../../docs/HUMAN_LLM_ATTACK_DYNAMICS_DATA_PROTOCOL_V1.md)에
상세히 정리돼 있다.

## 공개 정보의 의미

- `episode-*`, `entry-*`는 behavior ID나 원문을 encode하지 않는 공개용 순차
  occurrence ID다. 다만 append ordinal과 `instance_index`는 정확한 flow 감사를
  위한 linkage key이므로 private source 보유자는 결합할 수 있다. 이 pack은
  익명성 보장을 주장하지 않는다.
- `memory_head_*_sha256`는 category, strategy, family, score, query 수,
  success, 공개 entry ID와 slot version만 해시한 값이다. 원문 메모리의
  content hash가 아니다.
- retrieval에는 당시 저장된 category/strategy label과 rank만 있다. 원
  legacy 로그에 item ID, snapshot, similarity score, 실제 consumed receipt가
  없으므로 해당 필드는 비어 있고 `label_only_not_attested`로 표시된다.
- transition은 프로그램 순서로 추론한 edge다. 현재 확보된 unversioned 구현은
  이전 응답과 judge feedback을 다음 planner 입력에 넣지만, legacy producer
  commit과 runtime exposure receipt가 없다. 따라서 exposure boolean은
  `implementation_inferred_unversioned_not_runtime_attested`, edge는
  `program_order_inferred_not_explicit_edge`로 함께 한정한다.
- JSONL hash chain은 수집 당시 생성된 원장이 아니라 **export 시 재구성한 공개
  projection의 변조 탐지 체인**이다. 공개 event의 순서·내용 무결성은 검사하지만
  wall-clock insert 순서나 causal lineage를 증명하지 않는다.
- `exposure_label=unlabeled_legacy`는 의도적이다. 응답 의미를 사후 추측해
  성공 결과에 맞추지 않는다.

## 재생성

private source artifact를 합법적으로 보유한 환경에서만 다음 exporter를
사용한다.

```bash
python research/scripts/export_attack_memory_audit.py \
  --memory /path/to/memory.json \
  --results /path/to/results.jsonl \
  --manifest /path/to/memory_manifest.json \
  --out /path/to/public-pack
```

Exporter는 다음 조건을 모두 확인하지 못하면 실패한다.

- source memory hash가 promotion manifest와 일치
- strict-score replay가 canonical memory와 정확히 일치
- duplicate slot 없음
- JSONL event hash chain 유효
- raw behavior, turn, response, judge reason, step, reflection 및 behavior ID가
  공개 산출물에 나타나지 않음

## 활용 경계

이 공개 pack은 분포 감사, survivor bias 분석, taxonomy 검토, 사이트
시각화, 통계 코드 개발에 사용할 수 있다. 원문 공격 경험이 제거됐으므로
이 pack만으로 방어 시스템 프롬프트를 동일하게 재생성할 수는 없다. 실제
prompt compilation은 접근 통제된 private memory와 고정된 compiler를 사용한
뒤, prompt와 compiler manifest만 별도 공개해야 한다.

수집 provenance, claim 경계, 선행연구, memory-to-prompt compiler, adaptive
re-attack 실험 계획은
[`../../docs/ATTACK_MEMORY_COLLECTION_AND_DEFENSE_PLAN.md`](../../docs/ATTACK_MEMORY_COLLECTION_AND_DEFENSE_PLAN.md)에 정리돼 있다.

저장소 전체의 오픈소스 라이선스는 아직 확정되지 않았다. 따라서 이
자료를 재배포 가능한 독립 데이터셋으로 간주하지 말고 현재는 연구 감사와
재현 검토 용도로 사용해야 한다. 원 데이터셋과 모델의 라이선스·이용 조건도
각 upstream을 따른다.
