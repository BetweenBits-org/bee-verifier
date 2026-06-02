# beecert 인스크립션 스킴 & 검증 알고리즘

Project Bee S4가 정산 영수증을 Bitcoin에 봉인하는 방식과, bee-verifier가 이를 검증하는 절차의 규격.

## 1. 인스크립션 방식 — Taproot commit/reveal

정산 1건이 끝나면 영수증 **PDF 바이트 전체**를 ordinals 스타일 envelope에 담아 Taproot
tapscript로 만들고, commit→reveal 두 트랜잭션으로 체인에 공개한다. (OP_RETURN이 아니라 **witness**.)

### 1.1 tapleaf 스크립트 (envelope)

```
<32B x-only internal pubkey> OP_CHECKSIG
OP_FALSE OP_IF
  "beecert"            ; 프로토콜 마커 (7바이트 push)
  OP_0                 ; 본문 시작 구분자
  <body chunk 0>       ; 각 push ≤ 520바이트 (OP_PUSHDATA2)
  <body chunk 1>
  ...
OP_ENDIF
```

- `body chunk`들을 이어붙이면 **영수증 PDF 원본 바이트**가 된다.
- 리프 버전 `0xc0` (tapscript). 단일 리프 트리.

### 1.2 reveal tx

- commit 출력을 **script-path**로 소비한다. 입력 witness 스택:
  ```
  [ schnorr_sig(64B), tapscript, control_block ]
  ```
  - `tapscript` = 위 envelope (끝에서 두 번째 항목)
- reveal txid가 **인스크립션 ID**다.

## 2. 검증 알고리즘

입력: 영수증 PDF 바이트 `R`, 인스크립션 ID `txid`, (온라인 시) 공개 익스플로러 base URL.
해시 표기: `H(x)=SHA256(x)`.

온라인 모드:
1. `GET {base}/api/tx/{txid}/hex` → reveal raw tx
2. reveal 파싱 → `vin[0].witness[-2]` = tapscript

오프라인 모드: reveal raw tx hex를 직접 입력(네트워크 불필요).

### 검사

- **① 영수증 지문** — `h_R = H(R)`.
- **② witness 인스크립션** — tapscript의 `OP_IF` 이후 `"beecert"` 마커와 `OP_0` 구분자 다음의
  push들을 이어 `body`를 복원. 통과 조건: `H(body) == h_R` (그리고 `body`가 `%PDF-`로 시작).

②가 PASS면 **VERIFIED** — 제출한 PDF가 reveal tx witness에 봉인된 바로 그 문서다. 한 바이트라도 다르면 FAIL.

## 3. 신뢰 경계

- `H(body)`·`H(R)` 비교는 전부 **로컬 계산**이다. 익스플로러는 reveal tx 바이트를 전달할 뿐이며,
  거짓 witness를 주더라도 사용자의 진짜 PDF와 해시가 어긋나 거짓 "성공"을 만들 수 없다.
- 서버(BitCert/Bee) API는 검증 어디에도 사용되지 않는다. 익스플로러 자리에 자신의 풀노드(esplora) 엔드포인트를 넣으면
  제3자 의존도 사라진다.

## 4. 참고: 봉인 대상

체인에 봉인되는 것은 **PDF 바이트 자체**이므로 ②는 JSON 정규화가 필요 없다 — 바이트 단위 SHA-256 비교다.
