#!/usr/bin/env python3
"""bee-verifier CLI — Project Bee S4 정산 영수증 독립 검증기 (Python 표준 라이브러리만 사용).

영수증 PDF + 인스크립션 ID(reveal txid)만으로, 공개 Bitcoin 익스플로러에서 트랜잭션을 받아
Taproot commit/reveal witness에 봉인된 "beecert" 인스크립션과 대조한다. BitCert 서버에 접속하지 않는다.

사용법:
  # 온라인 (공개 익스플로러에서 tx 조회)
  python3 verify.py <reveal_txid> --pdf receipt.pdf --explorer https://mempool.space

  # 오프라인 (reveal raw hex 파일로만 — 네트워크 불필요)
  python3 verify.py --pdf examples/sample-receipt.pdf \\
      --reveal-hex-file examples/sample-reveal.hex

종료 코드 0 = 검증 성공, 1 = 실패/오류.
"""
import argparse, hashlib, json, sys, urllib.request

# ───────────────────────── 해시 ─────────────────────────
def sha256(b: bytes) -> bytes: return hashlib.sha256(b).digest()
def sha256hex(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def dsha(b: bytes) -> bytes: return sha256(sha256(b))

# ──────────────────── Bitcoin script / "beecert" envelope ────────────────────
def tokenize(buf: bytes):
    out, i = [], 0
    while i < len(buf):
        op = buf[i]; i += 1
        if 0x01 <= op <= 0x4b:
            out.append((op, buf[i:i+op])); i += op
        elif op == 0x4c:
            n = buf[i]; i += 1; out.append((op, buf[i:i+n])); i += n
        elif op == 0x4d:
            n = buf[i] | (buf[i+1] << 8); i += 2; out.append((op, buf[i:i+n])); i += n
        elif op == 0x4e:
            n = int.from_bytes(buf[i:i+4], "little"); i += 4; out.append((op, buf[i:i+n])); i += n
        else:
            out.append((op, None))
    return out

def extract_envelope(script: bytes):
    """OP_IF "beecert" OP_0 <chunks...> OP_ENDIF → 본문 바이트 복원."""
    toks = tokenize(script)
    if_idx = next((i for i, t in enumerate(toks) if t[0] == 0x63), -1)  # OP_IF
    if if_idx < 0: return None, None
    marker, started, parts = None, False, []
    for t in toks[if_idx + 1:]:
        if t[0] == 0x68: break          # OP_ENDIF
        if not started:
            if marker is None and t[1] is not None: marker = t[1]
            if t[0] == 0x00: started = True   # 본문 시작 구분자(OP_0)
            continue
        if t[1] is not None: parts.append(t[1])
    return (b"".join(parts) if parts else None), marker

# ──────────────────── varint + tx 파서 ────────────────────
def read_varint(buf, o):
    f = buf[o]
    if f < 0xfd: return f, o + 1
    if f == 0xfd: return int.from_bytes(buf[o+1:o+3], "little"), o + 3
    if f == 0xfe: return int.from_bytes(buf[o+1:o+5], "little"), o + 5
    return int.from_bytes(buf[o+1:o+9], "little"), o + 9

def write_varint(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff: return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def parse_tx(buf: bytes):
    o = 0; version = buf[o:o+4]; o += 4
    segwit = buf[o] == 0x00 and buf[o+1] == 0x01
    if segwit: o += 2
    legacy = [version]
    nin, o = read_varint(buf, o); legacy.append(write_varint(nin))
    vin = []
    for _ in range(nin):
        start = o
        prev_le = buf[o:o+32]; o += 32
        vout = int.from_bytes(buf[o:o+4], "little"); o += 4
        sl, o = read_varint(buf, o); o += sl; o += 4
        legacy.append(buf[start:o])
        vin.append({"prev_txid": prev_le[::-1].hex(), "vout": vout, "witness": None})
    nout, o = read_varint(buf, o); legacy.append(write_varint(nout))
    vout_list = []
    for _ in range(nout):
        start = o; value = int.from_bytes(buf[o:o+8], "little"); o += 8
        sl, o = read_varint(buf, o); spk = buf[o:o+sl]; o += sl
        legacy.append(buf[start:o]); vout_list.append({"value": value, "spk": spk})
    if segwit:
        for k in range(nin):
            ni, o = read_varint(buf, o); items = []
            for _ in range(ni):
                il, o = read_varint(buf, o); items.append(buf[o:o+il]); o += il
            vin[k]["witness"] = items
    locktime = buf[o:o+4]; o += 4; legacy.append(locktime)
    txid = dsha(b"".join(legacy))[::-1].hex()
    return {"version": version, "segwit": segwit, "vin": vin, "vout": vout_list, "txid": txid}

# ──────────────────── 검증 코어 ────────────────────
PASS, FAIL, WARN, SKIP, INFO = "PASS", "FAIL", "WARN", "SKIP", "INFO"

def run_verification(pdf, reveal_bytes):
    checks, dump = [], {}
    def add(s, t, d="", kv=""): checks.append({"status": s, "t": t, "d": d, "kv": kv})

    # ① 영수증 PDF 지문
    pdf_hash = sha256hex(pdf)
    dump["receiptSha256"], dump["receiptBytes"] = pdf_hash, len(pdf)
    add(INFO, "① 영수증 PDF 지문 (원본 바인딩)",
        f"제출한 영수증 PDF({len(pdf)} bytes)의 SHA-256.", f"sha256(receipt) = {pdf_hash}")

    try:
        reveal = parse_tx(reveal_bytes)
    except Exception as e:
        add(FAIL, "reveal 트랜잭션 파싱", f"해석 실패: {e}"); return finalize(checks, dump)

    w = reveal["vin"][0]["witness"]
    if not w or len(w) < 2:
        add(FAIL, "② witness 인스크립션 추출", "tapscript witness 없음 (인스크립션 tx가 아님).")
        return finalize(checks, dump)
    tapscript = w[-2]

    # ② witness envelope → PDF 복원 + 해시 대조
    body, marker = extract_envelope(tapscript)
    marker_str = marker.decode("latin1") if marker else "(없음)"
    if not body:
        add(FAIL, "② witness 인스크립션 추출", '"beecert" envelope 본문을 찾지 못함.', f"marker={marker_str}")
    else:
        is_pdf = body[:5] == b"%PDF-"
        chain_hash = sha256hex(body)
        dump.update(witnessSha256=chain_hash, witnessBytes=len(body), marker=marker_str)
        match = chain_hash == pdf_hash
        add(PASS if match else FAIL, "② witness 인스크립션 추출 & 해시 대조",
            ("witness에서 추출한 %s(%d bytes) 해시가 제출 영수증과 일치 — 체인에 봉인된 그 문서." % ("PDF" if is_pdf else "데이터", len(body)))
            if match else "witness 추출 데이터 해시가 제출 영수증과 다름 — 변조/불일치.",
            f'marker="{marker_str}" · sha256(witness) = {chain_hash}')

    return finalize(checks, dump)

def finalize(checks, dump):
    hard = [c for c in checks if c["status"] in (PASS, FAIL)]
    ok = len(hard) > 0 and all(c["status"] == PASS for c in hard)
    return {"checks": checks, "dump": dump, "ok": ok}

# ──────────────────── 네트워크 (공개 익스플로러) ────────────────────
def api_base(url): return url.strip().rstrip("/").removesuffix("/api")
def fetch_text(url):
    with urllib.request.urlopen(url, timeout=20) as r: return r.read().decode().strip()

# ──────────────────── CLI ────────────────────
ICONS = {PASS: "✓", FAIL: "✗", WARN: "!", SKIP: "–", INFO: "•"}

def main():
    ap = argparse.ArgumentParser(description="bee-verifier — 정산 영수증 독립 검증 (서버 비의존)")
    ap.add_argument("txid", nargs="?", help="인스크립션 ID = reveal txid (온라인 모드)")
    ap.add_argument("--pdf", required=True, help="검증할 영수증 PDF 경로")
    ap.add_argument("--explorer", default="https://mempool.space", help="공개 Bitcoin 익스플로러 base URL")
    ap.add_argument("--reveal-hex-file", help="오프라인: reveal tx raw hex 파일")
    ap.add_argument("--json", action="store_true", help="결과를 JSON으로 출력")
    a = ap.parse_args()

    pdf = open(a.pdf, "rb").read()

    if a.txid:
        txid = a.txid.strip().lower().split("i")[0]
        base = api_base(a.explorer)
        try:
            reveal_bytes = bytes.fromhex(fetch_text(f"{base}/api/tx/{txid}/hex"))
        except Exception as e:
            print(f"[오류] reveal tx 조회 실패: {e}", file=sys.stderr); sys.exit(1)
        res = run_verification(pdf, reveal_bytes)
    elif a.reveal_hex_file:
        reveal_bytes = bytes.fromhex(open(a.reveal_hex_file).read().strip())
        res = run_verification(pdf, reveal_bytes)
    else:
        ap.error("txid(온라인) 또는 --reveal-hex-file(오프라인) 중 하나가 필요합니다.")

    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=2)); sys.exit(0 if res["ok"] else 1)

    print("\n  bee-verifier — 독립 정산 영수증 검증\n  " + "─" * 52)
    for c in res["checks"]:
        print(f"  [{ICONS[c['status']]}] {c['t']}")
        if c["d"]:  print(f"        {c['d']}")
        if c["kv"]:
            for ln in c["kv"].split("\n"): print(f"        {ln}")
    print("  " + "─" * 52)
    print("  " + ("✓ 검증 성공 — 진본 영수증 (공개 체인과 일치, 서버 비의존)"
                   if res["ok"] else "✗ 검증 실패 — 불일치/변조 의심") + "\n")
    sys.exit(0 if res["ok"] else 1)

if __name__ == "__main__":
    main()
