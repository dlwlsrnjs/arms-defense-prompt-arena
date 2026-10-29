# ARMS Defense Prompt Arena

ARMS Defense Prompt Arena는 메모리 기반 적응형 공격자에 맞서, 사람이 작성한 시스템 프롬프트와 학습 에이전트가 작성한 시스템 프롬프트를 동일 조건에서 비교하기 위한 정적 연구 인터페이스입니다.

이 저장소는 ARMS 논문을 참고한 clean-room 재구현 프로젝트의 공개 사이트입니다. 공식 ARMS upstream 코드가 아닙니다.

## 무엇을 보여주나요?

- Qwen2.5-VL 3B, 7B, 32B 타깃별 public-v2 memory warm 상태
- 사람이 작성하는 방어 시스템 프롬프트와 재현 가능한 실행 계획
- 고정된 read-only memory snapshot에서 측정하는 ASR@1/3/5/10/30
- 기존 합성 데이터 결과와 public-v2 결과의 명확한 분리
- 공격 성공률뿐 아니라 정상 응답과 과잉 거부를 함께 보는 평가 프로토콜

사이트에는 유해 원문, 공격 payload, 타깃 모델의 원문 응답을 공개하지 않습니다. 표시되는 결과는 집계값과 provenance 정보로 제한됩니다.

## 공개 벤치마크 프로토콜

| 역할 | 데이터셋 |
| --- | --- |
| Memory warm | AdvBench, HarmBench validation, SALAD-Bench stratified sample |
| Sealed text evaluation | HarmBench test, StrongREJECT, JailbreakBench comparison track |
| Sealed VLM evaluation | MM-SafetyBench Tiny |
| Benign utility | XSTest, OR-Bench hard benign subset |

공식 평가는 warm memory를 read-only로 동결합니다. 평가 중 memory write를 허용하는 온라인 적응 실험은 별도 adaptive track으로 취급합니다. 여기서 held-out은 ARMS warm 및 방어 학습 절차로부터의 절차적 분리를 뜻하며, 타깃 모델의 사전학습 미포함을 보장하지 않습니다.

## 로컬에서 보기

별도 빌드 과정은 없습니다. 저장소 루트에서 정적 서버를 실행한 뒤 `dist/`를 열면 됩니다.

```bash
python3 -m http.server 8000 --directory dist
```

브라우저에서 `http://localhost:8000`으로 접속합니다. `file://`로 직접 열면 상태 JSON 요청이 브라우저 보안 정책에 의해 차단될 수 있습니다.

## 상태 데이터

사이트는 `dist/data/arena-status.json`을 읽습니다. 데이터가 없거나 아직 준비되지 않은 필드는 숫자를 추정하지 않고 `pending`으로 표시합니다.

공개 상태 파일에는 다음 정보만 포함해야 합니다.

- benchmark pack의 aggregate provenance와 row count
- 타깃별 memory readiness와 SHA-256
- frozen post-warm 집계 결과
- historical synthetic 결과라는 명시적 provenance

로컬 체크포인트 경로, 비밀값, 유해 원문 또는 개별 모델 응답을 커밋하지 마세요.

## GitHub Pages 배포

`.github/workflows/pages.yml`은 `main` 브랜치에 push될 때 `dist/`를 그대로 GitHub Pages artifact로 배포합니다. 공개 저장소를 만든 뒤 저장소의 **Settings → Pages → Source**를 **GitHub Actions**로 선택하면 됩니다.

워크플로는 GitHub 공식 Pages Actions만 사용합니다.

- `actions/configure-pages`
- `actions/upload-pages-artifact`
- `actions/deploy-pages`

이 공개 저장소에는 GitHub Pages 배포에 필요한 파일만 포함하며, 별도 호스팅 서비스의 내부 프로젝트 식별자는 포함하지 않습니다.

## 저장소 구조

```text
dist/                         배포되는 정적 사이트
  data/arena-status.json      공개 가능한 집계 상태
.github/workflows/pages.yml   GitHub Pages 배포
```

## 라이선스와 데이터셋

이 저장소에는 벤치마크 원문 데이터가 아니라 집계 메타데이터만 포함됩니다. 각 벤치마크의 이름과 출처는 원 프로젝트의 라이선스 및 사용 조건을 따르며, 프로젝트 전체에 적용할 오픈소스 라이선스는 아직 지정하지 않았습니다.
