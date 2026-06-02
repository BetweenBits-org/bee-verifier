# 예제 — 오프라인 재현 벡터

Project Bee S4 regtest에서 **실제 인스크립션된 정산 영수증 1건**을 캡처한 것입니다.
regtest 체인은 데모 리셋 시 초기화되므로 온라인 조회는 불가할 수 있지만,
동봉한 reveal raw hex로 **오프라인 검증은 항상 재현**됩니다.

| 파일 | 설명 |
|------|------|
| `sample-receipt.pdf` | 체인에 봉인된 영수증 PDF (3,014 bytes) |
| `sample-reveal.hex`  | reveal 트랜잭션 원시 hex (witness에 PDF 인스크립션) |
| `expected.json`      | 인스크립션 ID·해시 등 기대값 |

## 검증해 보기

```bash
# 저장소 루트(bee-verifier/)에서:
python3 verify-cli/verify.py --pdf examples/sample-receipt.pdf --reveal-hex-file examples/sample-reveal.hex
```

기대 결과: ② witness 일치 → **검증 성공**(exit 0).

## 변조 테스트

PDF를 한 바이트라도 고치면 ②가 즉시 불일치로 잡습니다(exit 1):

```bash
cp examples/sample-receipt.pdf /tmp/t.pdf
printf '\x00' | dd of=/tmp/t.pdf bs=1 seek=1500 count=1 conv=notrunc
python3 verify-cli/verify.py --pdf /tmp/t.pdf --reveal-hex-file examples/sample-reveal.hex
```

## 브라우저에서

`index.html`을 열고 → **고급(오프라인 모드)** 펼치기 → `sample-reveal.hex` 내용 붙여넣기
→ `sample-receipt.pdf` 드롭 → 검증 실행.
