# 🐝 bee-verifier

**Project Bee S4 정산 영수증 독립 검증기** — 영수증 PDF와 인스크립션 ID(reveal txid)만으로,
그 영수증이 Bitcoin에 봉인된 바로 그 문서인지 **공개 Bitcoin 체인과 SHA-256만으로** 확인합니다.
검증 과정에서 **BitCert/Bee 서버에 일절 접속하지 않습니다.**

**📦 소스 / 다운로드:** <https://github.com/BetweenBits-org/bee-verifier>
· [ZIP 다운로드](https://github.com/BetweenBits-org/bee-verifier/archive/refs/heads/main.zip)
· `git clone https://github.com/BetweenBits-org/bee-verifier.git`

> 참조 설계: [`github.com/BetweenBits-org/bitcert-verifier`](https://github.com/BetweenBits-org/bitcert-verifier).
> 그 프로젝트는 `OP_RETURN + Merkle` 스킴을 검증하지만, **bee-verifier는 Project Bee S4가 실제로 쓰는
> Taproot commit/reveal witness 인스크립션("beecert" envelope) 스킴 전용으로 새로 구현한 별개 프로젝트**입니다.

---

## 무엇을 검증하나

Project Bee S4는 정산이 끝나면 **영수증 PDF 원본 바이트를 그대로** Bitcoin Taproot reveal 트랜잭션의
**witness(tapscript)** 안에 인스크립션합니다(`"beecert"` envelope). bee-verifier는 이를 역산합니다.

| # | 검사 | 의미 |
|---|------|------|
| ① | **영수증 PDF 지문** | 제출한 PDF의 SHA-256 계산 (원본 바인딩) |
| ② | **witness 인스크립션 추출 & 해시 대조** | reveal tx witness에서 봉인된 바이트를 꺼내 `sha256(witness) == sha256(PDF)` 대조 |

①은 정보, ②가 핵심 판정입니다. ②가 통과하면 **그 영수증은 체인 witness에 봉인된 진본**이고,
한 바이트라도 다르면 즉시 불일치로 잡힙니다.

---

## 필요한 것

1. **영수증 PDF** — 감사기관/제3자가 보유한 정산 영수증 파일
2. **인스크립션 ID** — reveal txid (64 hex). 데모 대시보드의 정산기록에서 확인 가능

그리고 **공개 Bitcoin 익스플로러 URL** 하나(esplora/mempool API 호환). 예: `https://mempool.space`,
또는 데모 환경의 자체 멤풀 익스플로러.

---

## 실행 방법

### A. 브라우저 (의존성 0)

`index.html` 한 파일을 내려받아 브라우저로 엽니다 — `file://`로 열어도 동작합니다(외부 라이브러리 없음).

1. 인스크립션 ID, 공개 익스플로러 URL 입력
2. 영수증 PDF를 드래그&드롭
3. **검증 실행**

> 모든 SHA-256 계산은 브라우저 안에서 순수 JS로 수행됩니다. 일반 HTTP(비-secure context)나 `file://`에서도
> 동작하도록 `crypto.subtle`에 의존하지 않습니다. 네트워크 요청은 사용자가 지정한 **공개 익스플로러**로만 나갑니다.

### B. 커맨드라인 (Python 표준 라이브러리만)

```bash
# 온라인 — 공개 익스플로러에서 reveal tx 조회
python3 verify-cli/verify.py <reveal_txid> --pdf receipt.pdf --explorer https://mempool.space

# 오프라인 — 동봉한 raw tx hex로만 (네트워크 불필요)
python3 verify-cli/verify.py --pdf examples/sample-receipt.pdf --reveal-hex-file examples/sample-reveal.hex
```

종료 코드 `0` = 검증 성공, `1` = 실패/오류. `--json`으로 기계 판독 출력.
브라우저와 CLI는 **동일한 알고리즘의 독립 구현**이며 같은 결과를 냅니다(교차 검산).

---

## 신뢰 모델 / 왜 독립적인가

- **서버 비의존**: 검증에 BitCert/Bee API를 호출하지 않습니다. 사용자가 고른 공개 익스플로러(또는 자신의 Bitcoin 노드)에서
  인스크립션 ID로 reveal 트랜잭션을 받아, witness에 봉인된 바이트와 제출 PDF의 SHA-256을 **로컬에서** 대조합니다.
  raw tx hex를 직접 넣으면(오프라인 모드) 네트워크조차 불필요합니다.
- **영수증 출처와 무관**: 영수증 PDF는 감사기관이 어디서 받았든 상관없습니다. 한 바이트라도 다르면 ②가 잡습니다.
- **위변조 탐지**: 익스플로러가 거짓 witness를 주더라도 사용자의 진짜 PDF와는 해시가 어긋나므로 거짓 "성공"을 만들 수 없습니다.
  더 확실히 하려면 익스플로러 자리에 자신의 풀노드 esplora 엔드포인트를 넣으세요.

---

## 디렉토리

```
bee-verifier/
├── index.html            # 브라우저 검증기 (zero-dep 단일 파일)
├── verify-cli/verify.py  # Python CLI (표준 라이브러리만)
├── docs/scheme.md        # 인스크립션 와이어 포맷 + 검증 알고리즘 스펙
├── examples/             # 오프라인 재현용 캡처 벡터 (PDF + raw tx hex + 기대값)
├── LICENSE               # MIT
└── README.md
```

자세한 와이어 포맷은 [`docs/scheme.md`](docs/scheme.md) 참고.
