#!/usr/bin/env python3
"""MaeGuard - 파일 검사 / 폴더 감시 / 격리"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

APP_NAME = "매가드"
HOME = Path.home() / ".maeguard"
QUARANTINE_DIR = HOME / "quarantine"
INDEX_FILE = QUARANTINE_DIR / "index.json"
LOG_FILE = HOME / "log.txt"
SIGNATURE_NAME = "signatures.txt"


def _signature_paths():
    if getattr(sys, "frozen", False):
        yield Path(sys.executable).parent / SIGNATURE_NAME
        yield Path(getattr(sys, "_MEIPASS", ".")) / SIGNATURE_NAME
    yield Path(__file__).with_name(SIGNATURE_NAME)

SUSPICIOUS_THRESHOLD = 50
MAX_CONTENT_SCAN = 5 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 300
XOR_KEY = 0xA5
ONLINE_SIG_FILE = HOME / "signatures_online.txt"
ONLINE_SIG_URL = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"

DANGEROUS_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".msi", ".jar", ".lnk",
    ".cpl", ".dll", ".reg", ".iso", ".img", ".vhd", ".vhdx", ".sh", ".appx",
    ".msix", ".application", ".url", ".chm", ".xll", ".wsc", ".sct", ".inf",
    ".msc", ".gadget", ".scf", ".appref-ms",
}
EXE_EXT = {".exe", ".dll", ".scr", ".com", ".sys", ".cpl", ".msi", ".ocx", ".xll", ".efi"}
SCRIPT_EXT = {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".psm1", ".hta", ".sh", ".py", ".sct", ".wsc"}
MACRO_EXT = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam"}
HTML_EXT = {".html", ".htm", ".svg", ".xhtml", ".shtml"}
ARCHIVE_EXT = {".zip", ".jar", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".apk", ".appx", ".msix"}
DECOY_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".hwp", ".hwpx",
    ".txt", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi",
    ".mkv", ".zip", ".rar", ".7z", ".csv", ".rtf",
}
PARTIAL_EXT = {".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload"}

LURE_NAME = re.compile(
    r"(?i)(crack|keygen|patch|activator|kms|loader|cheat|hack|aimbot|wallhack|esp[_ -]|"
    r"injector|unlocker|free[_ -]?(robux|vbucks|skins?|nitro)|robux|vbucks|nitro[_ -]?gen|"
    r"치트|핵|크랙|무료[_ ]?(캐시|코인))")

CONTENT_PATTERNS = [
    (("powershell", "pwsh"), rb"(?i)(powershell|pwsh)[^\n]{0,80}\s-(e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", 40, "인코딩된 PowerShell 실행"),
    (("frombase64string",), None, 20, "Base64 디코딩 후 실행"),
    (("invoke-expression", "iex"), rb"(?i)invoke-expression|\biex\s*[\(\$]", 25, "동적 코드 실행 (IEX)"),
    (("hidden",), rb"(?i)\s-w(indowstyle)?\s+hidden", 20, "창을 숨기고 실행"),
    (("bypass",), rb"(?i)\s-(ep|exec(utionpolicy)?)\s+bypass", 20, "실행 정책 우회"),
    (("download", "invoke-webrequest", "iwr ", "bitstransfer"),
     rb"(?i)downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\s+http|start-bitstransfer", 20, "인터넷에서 파일 다운로드"),
    (("wscript.shell", "shell.application"), None, 20, "Windows 셸 직접 제어"),
    (("certutil",), rb"(?i)certutil[^\n]{0,30}-(decode|urlcache)", 40, "certutil로 몰래 다운로드/디코딩"),
    (("bitsadmin",), rb"(?i)bitsadmin[^\n]{0,30}/transfer", 35, "bitsadmin 몰래 다운로드"),
    (("mshta",), rb"(?i)mshta(\.exe)?\s+[\"']?(https?:|javascript:|vbscript:)", 45, "mshta로 원격 스크립트 실행"),
    (("rundll32",), rb"(?i)rundll32(\.exe)?[^\n]{0,40}javascript:", 45, "rundll32 스크립트 실행 악용"),
    (("regsvr32",), rb"(?i)regsvr32[^\n]{0,40}/i:\s*https?:", 45, "regsvr32 원격 실행 (Squiblydoo)"),
    (("curl", "wget"), rb"(?i)(curl|wget)[^\n]{0,120}\|\s*(ba)?sh\b", 35, "다운로드 후 바로 셸 실행"),
    (("currentversion\\run",), rb"(?i)currentversion\\run(once)?\b", 25, "시작프로그램 레지스트리 등록"),
    (("schtasks",), rb"(?i)schtasks(\.exe)?\s+/create", 20, "예약 작업 등록"),
    (("programs\\startup",), None, 20, "시작프로그램 폴더에 복사"),
    (("set-mppreference",), rb"(?i)set-mppreference[^\n]{0,60}-disable(realtimemonitoring|behaviormonitoring|ioavprotection)", 50, "윈도우 디펜더 끄기"),
    (("add-mppreference",), rb"(?i)add-mppreference[^\n]{0,30}-exclusion(path|process|extension)", 45, "디펜더 검사 제외 등록"),
    (("netsh",), rb"(?i)netsh\s+(adv)?firewall[^\n]{0,40}(state\s+off|opmode\s+disable)", 40, "방화벽 끄기"),
    (("wevtutil", "clear-eventlog"), rb"(?i)wevtutil(\.exe)?\s+cl\b|clear-eventlog", 30, "이벤트 로그 삭제 (흔적 지우기)"),
    (("disableantispyware",), None, 35, "디펜더 비활성화 레지스트리"),
    (("vssadmin", "shadowcopy"), rb"(?i)vssadmin[^\n]{0,30}delete\s+shadows|shadowcopy\s+delete", 50, "백업(섀도 복사본) 삭제 - 랜섬웨어 특징"),
    (("recoveryenabled",), rb"(?i)bcdedit[^\n]{0,40}recoveryenabled\s+no", 45, "윈도우 복구 기능 끄기 - 랜섬웨어 특징"),
    (("wbadmin",), rb"(?i)wbadmin[^\n]{0,20}delete\s+catalog", 45, "백업 카탈로그 삭제 - 랜섬웨어 특징"),
    (("encrypted",), rb"(?i)your\s+(important\s+)?files\s+(have\s+been|are|were)\s+encrypted", 50, "랜섬웨어 협박 문구"),
    ((".onion",), rb"(?i)\b[a-z2-7]{56}\.onion\b", 20, "다크웹(.onion) 주소"),
    (("/api/webhooks/",), rb"(?i)discord(app)?\.com/api/webhooks/\d+", 35, "디스코드 웹훅으로 데이터 전송"),
    (("leveldb",), rb"(?i)discord[^\n]{0,80}local storage[\\/]+leveldb", 50, "디스코드 토큰 탈취"),
    ((".roblosecurity",), None, 45, "로블록스 계정 쿠키 탈취"),
    (("login data", "web data"), rb"(?i)user data[\\/]+default[\\/]+(login data|cookies|web data)", 45, "브라우저 저장 비밀번호/쿠키 탈취"),
    (("cryptunprotectdata", "login data"), None, 30, "브라우저 비밀번호 복호화"),
    (("nkbihfbeogaeaoehlefnkodbefgpgknn", "exodus.wallet", "wallet.dat"), rb"(?i)nkbihfbeogaeaoehlefnkodbefgpgknn|exodus[\\/]+exodus\.wallet|\bwallet\.dat\b", 40, "암호화폐 지갑 탈취"),
    (("api.telegram.org/bot",), rb"(?i)api\.telegram\.org/bot\d+:", 35, "텔레그램 봇으로 데이터 전송"),
    (("loginusers.vdf", "ssfn"), rb"(?i)config[\\/]+loginusers\.vdf|steam[^\n]{0,40}\bssfn", 35, "스팀 계정 파일 탈취"),
    (("virtualallocex", "writeprocessmemory", "createremotethread"), None, 35, "다른 프로세스에 코드 주입"),
    (("unmapviewofsection",), rb"(?i)\b(nt|zw)unmapviewofsection", 30, "프로세스 할로잉 (정상 프로그램으로 위장)"),
    (("setwindowshookex", "getasynckeystate"), None, 25, "키보드 입력 가로채기 (키로거)"),
    (("amsiscanbuffer", "amsiinitfailed"), rb"(?i)amsiinitfailed|amsiscanbuffer[\s\S]{0,300}(virtualprotect|patch)", 45, "백신 검사 인터페이스(AMSI) 우회"),
    (("xmrig", "stratum+tcp", "cryptonight"), rb"(?i)\b(xmrig|stratum\+tcp://|cryptonight)\b", 45, "몰래 채굴 (코인 마이너)"),
    (("njrat", "asyncrat", "quasar", "remcos", "darkcomet", "nanocore", "redline", "lummac", "vidar", "raccoon"),
     rb"(?i)\b(njrat|asyncrat|quasarrat|remcos|darkcomet|nanocore|redline\s?stealer|lummac2?|vidar\s?stealer|raccoon\s?stealer)\b", 40, "알려진 해킹툴/악성코드 이름"),
    (("rm -rf",), rb"(?i)rm\s+-rf\s+(--no-preserve-root\s+)?/(\s|\*|$)", 50, "시스템 전체 삭제 명령"),
    (("system32", "c:\\windows"), rb"(?i)del\s+/[fsq]\s+/[fsq][^\n]{0,20}(c:\\windows|system32)", 50, "윈도우 시스템 파일 삭제"),
    (("physicaldrive0",), None, 35, "디스크 직접 접근 (MBR 파괴 가능)"),
]
CONTENT_PATTERNS = [(tuple(k.encode() for k in kw),
                     re.compile(rx.replace(b"(?i)", b"")) if rx else None, sc, d)
                    for kw, rx, sc, d in CONTENT_PATTERNS]


def _search_near(rx, low: bytes, kws) -> bool:
    for k in kws:
        start = 0
        for _ in range(64):
            i = low.find(k, start)
            if i < 0:
                break
            if rx.search(low, max(0, i - 300), i + 600):
                return True
            start = i + 1
    return False

RTLO = "\u202e"


def startup_folders():
    out = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        out.append(Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup")
    progdata = os.environ.get("PROGRAMDATA")
    if progdata:
        out.append(Path(progdata) / "Microsoft/Windows/Start Menu/Programs/StartUp")
    return out


def default_watch_folders():
    home = Path.home()
    cands = [home / "Downloads", home / "Desktop", home / "Documents"]
    one = os.environ.get("OneDrive")
    if one:
        cands += [Path(one) / "Desktop", Path(one) / "Documents", Path(one) / "바탕 화면", Path(one) / "문서"]
    cands += startup_folders()
    seen, out = set(), []
    for p in cands:
        try:
            key = p.resolve()
        except OSError:
            continue
        if p.is_dir() and key not in seen:
            seen.add(key)
            out.append(p)
    return out


def log(msg: str) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _parse_signatures(text: str, default_name: str, sigs: dict) -> None:
    for line in text.splitlines():
        line = line.strip().strip('"')
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            sigs[parts[0].lower()] = parts[1] if len(parts) > 1 else default_name


def load_signatures() -> dict:
    sigs = {}
    if ONLINE_SIG_FILE.exists():
        _parse_signatures(ONLINE_SIG_FILE.read_text(encoding="utf-8", errors="ignore"),
                          "MalwareBazaar 악성코드", sigs)
    sig_file = next((p for p in _signature_paths() if p.exists()), None)
    if sig_file:
        _parse_signatures(sig_file.read_text(encoding="utf-8"), "알 수 없는 악성코드", sigs)
    return sigs


class NoAuthKey(Exception):
    pass


def _parse_bazaar_csv(text: str) -> dict:
    import csv
    out = {}
    hash_col, sig_col = None, None
    for line in text.splitlines():
        if line.startswith("#"):
            head = [c.strip().strip('"') for c in line.lstrip("# ").split(",")]
            if "sha256_hash" in head:
                hash_col = head.index("sha256_hash")
                sig_col = head.index("signature") if "signature" in head else None
            continue
        if not line.strip():
            continue
        row = [c.strip() for c in next(csv.reader([line], skipinitialspace=True))]
        h = row[hash_col] if hash_col is not None and hash_col < len(row) else \
            next((c for c in row if re.fullmatch(r"[0-9a-fA-F]{64}", c)), None)
        if not h or not re.fullmatch(r"[0-9a-fA-F]{64}", h):
            continue
        name = row[sig_col] if sig_col is not None and sig_col < len(row) else ""
        if not name or name.lower() in ("n/a", "none", "null"):
            name = "MalwareBazaar"
        out[h.lower()] = name
    return out


def update_signatures(auth_key: str = "", timeout: float = 30) -> int:
    import io
    import urllib.error
    import urllib.request
    import zipfile
    auth_key = (auth_key or "").strip()
    if not auth_key:
        raise NoAuthKey("abuse.ch Auth-Key 가 없습니다")
    req = urllib.request.Request(ONLINE_SIG_URL.format(key=auth_key), headers={"User-Agent": "MaeGuard/1.4"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise ValueError("abuse.ch Auth-Key 가 올바르지 않습니다") from None
        raise ValueError(f"MalwareBazaar 응답 오류 HTTP {e.code}") from None
    if raw[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            raw = z.read(z.namelist()[0])
    new = _parse_bazaar_csv(raw.decode("utf-8", errors="ignore"))
    if not new:
        raise ValueError("받은 목록이 비어 있습니다")
    old = {}
    if ONLINE_SIG_FILE.exists():
        _parse_signatures(ONLINE_SIG_FILE.read_text(encoding="utf-8", errors="ignore"), "", old)
    added = [h for h in new if h not in old]
    HOME.mkdir(parents=True, exist_ok=True)
    with open(ONLINE_SIG_FILE, "a", encoding="utf-8") as f:
        for h in added:
            f.write(f"{h} {new[h]}\n")
    log(f"시그니처 업데이트: {len(added)}개 추가 (총 {len(old) + len(added)}개)")
    return len(added)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def zone_identifier(path: Path):
    if os.name != "nt":
        return None
    try:
        with open(str(path) + ":Zone.Identifier", "r", errors="ignore") as f:
            m = re.search(r"ZoneId=(\d)", f.read())
            return int(m.group(1)) if m else None
    except OSError:
        return None


class ScanResult:
    def __init__(self, path: Path):
        self.path = path
        self.score = 0
        self.reasons = []
        self.malware_name = None

    def add(self, score: int, reason: str):
        self.score += score
        self.reasons.append(reason)
        self._scores = getattr(self, "_scores", []) + [score]

    @property
    def top_reason(self) -> str:
        if not self.reasons:
            return ""
        scores = getattr(self, "_scores", [0] * len(self.reasons))
        return self.reasons[max(range(len(self.reasons)), key=lambda i: scores[i])]

    @property
    def verdict(self) -> str:
        if self.malware_name:
            return "악성"
        if self.score >= SUSPICIOUS_THRESHOLD:
            return "의심"
        return "안전"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    from collections import Counter
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def check_name(name: str, r: ScanResult, where: str = "", ext_score: bool = True) -> bool:
    p = Path(name)
    suffixes = [s.lower() for s in p.suffixes]
    ext = suffixes[-1] if suffixes else ""
    if RTLO in name:
        r.add(60, f"{where}파일명에 글자 뒤집기 문자(RTLO) 사용 - 확장자 위장")
    if len(suffixes) >= 2 and suffixes[-2] in DECOY_EXT and ext in DANGEROUS_EXT:
        r.add(50, f"{where}이중 확장자 위장 ({suffixes[-2]}{ext})")
    if re.search(r"\s{5,}\.\w+$", name):
        r.add(30, f"{where}확장자 앞에 공백을 길게 넣어 숨김")
    if ext in DANGEROUS_EXT:
        if ext_score:
            r.add(20, f"{where}실행 가능한 파일 형식 ({ext})")
        if LURE_NAME.search(p.stem):
            r.add(30, f"{where}크랙/치트/무료 재화 미끼 이름")
    if ext in MACRO_EXT:
        r.add(15, f"{where}매크로 포함 문서 형식 ({ext})")
    return ext in DANGEROUS_EXT


def check_content(data: bytes, ext: str, r: ScanResult, where: str = "") -> None:
    if data[:2] == b"MZ" and ext not in EXE_EXT:
        r.add(60, f"{where}실행파일(EXE)인데 다른 확장자로 위장")
    if data[:4] == b"\x7fELF" and ext in DECOY_EXT:
        r.add(40, f"{where}리눅스 실행파일인데 다른 확장자로 위장")
    if ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".txt"} and data[:4] == b"PK\x03\x04":
        r.add(30, f"{where}압축파일인데 이미지/문서 확장자로 위장")

    if data[:2] == b"MZ":
        if b"UPX0" in data[:4096] or b"UPX!" in data[:4096]:
            r.add(15, f"{where}UPX로 압축(패킹)된 실행파일")
        if entropy(data[:1024 * 1024]) > 7.4:
            r.add(15, f"{where}내용이 암호화/난독화된 실행파일")

    variants = [data]
    if b"\x00" in data[:4096]:
        variants.append(data.replace(b"\x00", b""))
    lowered = [v.lower() for v in variants]
    total = 0
    for kws, rx, sc, desc in CONTENT_PATTERNS:
        hit = False
        for low in lowered:
            if rx is None:
                hit = all(k in low for k in kws)
            else:
                hit = _search_near(rx, low, kws)
            if hit:
                break
        if hit:
            r.add(sc, f"{where}위험 코드: {desc}")
            total += 1
            if total >= 6:
                break

    if ext in SCRIPT_EXT or ext in HTML_EXT:
        if re.search(rb"[A-Za-z0-9+/]{3000,}={0,2}", data):
            r.add(20, f"{where}스크립트 안에 거대한 Base64 덩어리")
        if len(re.findall(rb"(?i)\[char\]\s*\d+|chr\(\s*\d+\s*\)|chrw\(\s*\d+\s*\)", data)) > 30:
            r.add(25, f"{where}문자 코드로 난독화된 스크립트")
        if len(re.findall(rb"\^", data)) > 80 and ext in {".bat", ".cmd"}:
            r.add(20, f"{where}^ 기호로 난독화된 배치파일")

    if ext == ".lnk" or data[:4] == b"L\x00\x00\x00":
        flat = data.replace(b"\x00", b"").lower()
        if re.search(rb"powershell|cmd(\.exe)?\s*/c|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin", flat):
            r.add(45, f"{where}바로가기가 명령어/스크립트를 실행함")

    if ext in HTML_EXT:
        if re.search(rb"(?i)mssaveoropenblob|navigator\.msSaveBlob", data) or \
                (re.search(rb"(?i)atob\s*\(", data) and re.search(rb"(?i)new\s+blob", data)
                 and re.search(rb"(?i)\.download\s*=", data)):
            r.add(55, f"{where}웹페이지에서 파일을 몰래 만들어 내려받게 함 (HTML smuggling)")
        if ext == ".svg" and re.search(rb"(?i)<script", data):
            r.add(30, f"{where}이미지(SVG) 안에 스크립트")
        if re.search(rb"(?i)<input[^>]+type=[\"']?password", data) and \
                (re.search(rb"(?i)(microsoft|office|outlook|naver|kakao|google|paypal|bank)", data)
                 or "은행".encode() in data):
            r.add(35, f"{where}로그인 화면을 흉내 낸 피싱 페이지")

    if data[:5] == b"%PDF-":
        if re.search(rb"/Launch\b", data):
            r.add(45, f"{where}PDF가 프로그램 실행을 시도함")
        if re.search(rb"/(JavaScript|JS)\b", data):
            sc = 50 if re.search(rb"/(OpenAction|AA)\b", data) else 20
            r.add(sc, f"{where}PDF 안에 자바스크립트")
        if re.search(rb"/EmbeddedFile\b", data):
            r.add(15, f"{where}PDF 안에 숨겨진 첨부파일")

    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and b"Attribute VB_" in data:
        r.add(25, f"{where}문서에 매크로 포함")
        if re.search(rb"(?i)auto_?open|document_open|workbook_open", data):
            r.add(20, f"{where}문서를 열면 매크로 자동 실행")
        if re.search(rb"(?i)shell|createobject|urldownloadtofile", data):
            r.add(25, f"{where}매크로가 프로그램 실행/다운로드")


MAX_ARCHIVE_DEPTH = 3


def check_archive(path, ext: str, r: ScanResult, sigs: dict, depth: int = 1, prefix: str = "") -> None:
    import io
    import zipfile
    try:
        zf = zipfile.ZipFile(io.BytesIO(path) if isinstance(path, (bytes, bytearray)) else path)
    except Exception:
        return
    with zf:
        infos = zf.infolist()[:MAX_ARCHIVE_MEMBERS]
        encrypted_exec = False
        exe_counted = False
        for info in infos:
            if info.is_dir():
                continue
            mname = info.filename
            mext = Path(mname).suffix.lower()
            where = f"[압축 안 {prefix}{Path(mname).name}] "
            if info.flag_bits & 0x1:
                if mext in DANGEROUS_EXT:
                    encrypted_exec = True
                continue
            if mname.lower().endswith("vbaproject.bin"):
                r.add(25, "문서에 매크로 포함")
                try:
                    vba = zf.read(info)[:MAX_CONTENT_SCAN]
                except Exception:
                    vba = b""
                if re.search(rb"(?i)auto_?open|document_open|workbook_open", vba):
                    r.add(20, "문서를 열면 매크로 자동 실행")
                if re.search(rb"(?i)shell|createobject|urldownloadtofile|powershell", vba):
                    r.add(25, "매크로가 프로그램 실행/다운로드")
                continue
            if ext not in {".zip", ".jar"} and mext in {".xml", ".rels", ".png", ".jpeg", ".jpg", ".emf", ".wmf"}:
                continue
            exe_counted |= check_name(mname, r, where, ext_score=not exe_counted)
            if info.file_size > 50 * 1024 * 1024:
                continue
            try:
                with zf.open(info) as f:
                    member = f.read(MAX_CONTENT_SCAN)
            except Exception:
                continue
            if info.file_size <= MAX_CONTENT_SCAN:
                h = hashlib.sha256(member).hexdigest()
                if h in sigs and not r.malware_name:
                    r.malware_name = sigs[h]
                    r.add(100, f"{where}알려진 악성코드: {sigs[h]}")
            check_content(member, mext, r, where)
            if member[:4] == b"PK\x03\x04" and depth < MAX_ARCHIVE_DEPTH and info.file_size <= MAX_CONTENT_SCAN:
                check_archive(member, mext, r, sigs, depth + 1, prefix=f"{prefix}{Path(mname).name} > ")
        if encrypted_exec:
            r.add(40, "암호 걸린 압축파일 안에 실행파일 (백신 검사 회피 수법)")
        if 0 < len(infos) <= 3 and any(Path(i.filename).suffix.lower() in DANGEROUS_EXT for i in infos) \
                and ext == ".zip":
            r.add(10, "실행파일 1~3개만 든 압축파일")


def is_risky(ext: str, data_head: bytes) -> bool:
    return (ext in DANGEROUS_EXT or ext in SCRIPT_EXT or ext in MACRO_EXT or ext in HTML_EXT
            or ext in ARCHIVE_EXT or ext in {".pdf", ".doc", ".xls", ".ppt", ".rtf", ".rar", ".7z", ".py",
                                                   ".php", ".asp", ".aspx", ".jsp", ".ashx", ".cs", ".vb", ".pl"}
            or data_head[:2] == b"MZ" or data_head[:4] in (b"\x7fELF", b"PK\x03\x04")
            or data_head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")


def scan_file(path: Path, sigs: dict, engines=None, vt_wait: float = 65, deep: bool = False) -> ScanResult:
    r = ScanResult(path)
    suffixes = [s.lower() for s in path.suffixes]
    ext = suffixes[-1] if suffixes else ""

    if getattr(sys, "frozen", False):
        try:
            if path.resolve() == Path(sys.executable).resolve():
                return r
        except OSError:
            pass

    try:
        digest = sha256_of(path)
        size = path.stat().st_size
    except OSError as e:
        r.add(0, f"읽기 실패: {e}")
        return r
    if digest in sigs:
        r.malware_name = sigs[digest]
        r.add(100, f"알려진 악성코드: {sigs[digest]}")

    check_name(path.name, r)

    try:
        parent = path.parent.resolve()
        if any(parent == s.resolve() for s in startup_folders()) and path.name.lower() != "desktop.ini":
            r.add(30, "시작프로그램 폴더에 생긴 파일 (컴퓨터 켤 때마다 실행)")
    except OSError:
        pass

    try:
        with open(path, "rb") as f:
            data = f.read(MAX_CONTENT_SCAN)
    except OSError:
        data = b""
    check_content(data, ext, r)
    if data[:4] == b"PK\x03\x04" or ext in ARCHIVE_EXT:
        check_archive(path, ext, r, sigs)

    if ext in EXE_EXT and size > 300 * 1024 * 1024:
        r.add(15, "비정상적으로 큰 실행파일 (검사 회피 가능성)")

    if zone_identifier(path) == 3 and ext in DANGEROUS_EXT:
        r.add(10, "인터넷에서 다운로드한 실행파일")

    risky = r.score > 0 or is_risky(ext, data[:8])
    if engines is not None and not r.malware_name and (deep or risky):
        try:
            engines.apply(path, digest, r, vt_wait=vt_wait, use_vt=risky)
        except Exception as e:
            log(f"엔진 오류: {path}: {e}")

    return r


def iter_files(target: Path):
    if target.is_file():
        yield target
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if Path(root, d).resolve() != QUARANTINE_DIR.resolve()]
        for fn in files:
            yield Path(root, fn)


class Asker:
    def __init__(self, auto_yes=False, gui=False):
        self.auto_yes = auto_yes
        self.tk = None
        if gui:
            try:
                import tkinter
                from tkinter import messagebox
                root = tkinter.Tk()
                root.withdraw()
                root.attributes("-topmost", True)
                self.tk = messagebox
            except Exception:
                print("GUI를 쓸 수 없어 콘솔로 물어봅니다.")

    def ask_block(self, r: ScanResult) -> bool:
        if self.auto_yes:
            return True
        title = f"{APP_NAME} - {'악성코드 발견!' if r.verdict == '악성' else '의심스러운 파일'}"
        body = (f"파일: {r.path}\n위험 점수: {r.score}\n\n이유:\n"
                + "\n".join(f" - {x}" for x in r.reasons)
                + "\n\n이 파일을 차단(격리)할까요?")
        if self.tk:
            return self.tk.askyesno(title, body, icon="warning")
        print("\n" + "=" * 60)
        print(f"[!] {title}")
        print(body)
        while True:
            ans = input("  [y] 차단  [n] 허용 > ").strip().lower()
            if ans in ("y", "yes", "ㅛ", "예", "네"):
                return True
            if ans in ("n", "no", "ㅜ", "아니오", "아니요"):
                return False


def _load_index() -> dict:
    if INDEX_FILE.exists():
        return json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    return {}


def _save_index(idx: dict) -> None:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    INDEX_FILE.write_text(json.dumps(idx, ensure_ascii=False, indent=2), encoding="utf-8")


def _xor_copy(src: Path, dst: Path) -> None:
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        for chunk in iter(lambda: fi.read(1024 * 1024), b""):
            fo.write(bytes(b ^ XOR_KEY for b in chunk))


def quarantine(r: ScanResult) -> str:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    qid = uuid.uuid4().hex[:8]
    dst = QUARANTINE_DIR / f"{qid}.qtn"
    _xor_copy(r.path, dst)
    os.remove(r.path)
    idx = _load_index()
    idx[qid] = {
        "original": str(r.path.resolve()),
        "date": f"{datetime.now():%Y-%m-%d %H:%M:%S}",
        "verdict": r.verdict,
        "score": r.score,
        "reasons": r.reasons,
    }
    _save_index(idx)
    log(f"차단: {r.path} (ID {qid}, {r.verdict}, 점수 {r.score})")
    return qid


def list_quarantine() -> dict:
    return _load_index()


def restore_quarantine(qid: str) -> Path:
    idx = _load_index()
    item = idx[qid]
    qfile = QUARANTINE_DIR / f"{qid}.qtn"
    dst = Path(item["original"])
    if dst.exists():
        dst = dst.with_name(dst.stem + "_복원됨" + dst.suffix)
    dst.parent.mkdir(parents=True, exist_ok=True)
    _xor_copy(qfile, dst)
    qfile.unlink(missing_ok=True)
    del idx[qid]
    _save_index(idx)
    log(f"복원: {dst} (ID {qid})")
    return dst


def delete_quarantine(qid: str) -> None:
    idx = _load_index()
    item = idx.pop(qid)
    (QUARANTINE_DIR / f"{qid}.qtn").unlink(missing_ok=True)
    _save_index(idx)
    log(f"영구 삭제: {item['original']} (ID {qid})")


def cmd_quarantine(action: str, qid=None) -> None:
    idx = _load_index()
    if action == "list":
        if not idx:
            print("격리된 파일이 없습니다.")
        for k, v in idx.items():
            print(f"[{k}] {v['date']}  {v['verdict']}({v['score']})  {v['original']}")
        return
    if not qid or qid not in idx:
        print("해당 ID가 없습니다. 'quarantine list'로 확인하세요.")
        return
    if action == "restore":
        print(f"복원 완료: {restore_quarantine(qid)}")
    elif action == "delete":
        print(f"영구 삭제: {idx[qid]['original']}")
        delete_quarantine(qid)


def handle(r: ScanResult, asker: Asker) -> str:
    if r.verdict == "안전":
        return "안전"
    if asker.ask_block(r):
        qid = quarantine(r)
        print(f"  차단됨 (격리 ID: {qid})")
        return "차단"
    log(f"허용: {r.path} ({r.verdict}, 점수 {r.score})")
    print("  → 허용했습니다.")
    return "허용"


def load_engines():
    try:
        import maeguard_engines
        return maeguard_engines.Engines()
    except Exception as e:
        log(f"엔진 불러오기 실패: {e}")
        return None


def cmd_scan(target: Path, asker: Asker) -> int:
    if not target.exists():
        print(f"경로가 없습니다: {target}")
        return 2
    sigs = load_signatures()
    engines = load_engines()
    names = ", ".join(engines.active_names()) if engines else ""
    print(f"{APP_NAME} 검사 시작: {target}  (시그니처 {len(sigs)}개{' · ' + names if names else ''})")
    stats = {"검사": 0, "안전": 0, "차단": 0, "허용": 0}
    start = time.time()
    for p in iter_files(target):
        if p.is_symlink() or not p.is_file():
            continue
        r = scan_file(p, sigs, engines, vt_wait=0)
        stats["검사"] += 1
        stats[handle(r, asker)] += 1
    print("\n" + "-" * 60)
    print(f"검사 완료 ({time.time() - start:.1f}초)  "
          f"검사 {stats['검사']}개 · 안전 {stats['안전']} · 차단 {stats['차단']} · 허용 {stats['허용']}")
    log(f"검사 완료: {target} {stats}")
    return 1 if stats["차단"] + stats["허용"] else 0


class Watcher:
    def __init__(self, folder: Path, on_result, interval: float = 2.0, engines=None):
        self.folder = folder
        self.on_result = on_result
        self.interval = interval
        self.engines = engines
        self.sigs = load_signatures()

    MAX_DEPTH = 3
    MAX_ENTRIES = 20000
    SKIP_DIRS = {"node_modules", ".git", "__pycache__", "$recycle.bin", ".maeguard"}

    def _snapshot(self) -> dict:
        out = {}
        stack = [(self.folder, 0)]
        while stack and len(out) < self.MAX_ENTRIES:
            d, depth = stack.pop()
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if depth < self.MAX_DEPTH and e.name.lower() not in self.SKIP_DIRS \
                                    and not e.name.startswith("."):
                                stack.append((Path(e.path), depth + 1))
                        elif e.is_file(follow_symlinks=False):
                            st = e.stat()
                            out[Path(e.path)] = (st.st_size, st.st_mtime)
                    except OSError:
                        continue
        return out

    @staticmethod
    def _real_stat(p: Path):
        # 윈도우는 폴더 목록의 크기/시간이 쓰는 중에 늦게 갱신되므로 파일을 직접 stat
        try:
            st = os.stat(p)
        except OSError:
            return None
        return st.st_size, st.st_mtime_ns

    def run(self, stop_event=None) -> None:
        listed = self._snapshot()
        scanned = {}
        pending = {}
        while not (stop_event and stop_event.is_set()):
            if stop_event:
                stop_event.wait(self.interval)
                if stop_event.is_set():
                    break
            else:
                time.sleep(self.interval)
            now = self._snapshot()
            for p in list(pending):
                if p not in now:
                    pending.pop(p)
            for p, sig in now.items():
                if p.suffix.lower() in PARTIAL_EXT:
                    continue
                if listed.get(p) == sig and p not in pending:
                    continue
                real = self._real_stat(p)
                if real is None:
                    continue
                if scanned.get(p) == real:
                    listed[p] = sig
                    pending.pop(p, None)
                    continue
                if pending.get(p) != real:
                    pending[p] = real
                    continue
                pending.pop(p, None)
                listed[p] = sig
                scanned[p] = real
                self.on_result(scan_file(p, self.sigs, self.engines, deep=True))


def cmd_watch(folder: Path, asker: Asker, interval: float = 2.0) -> None:
    if not folder.is_dir():
        print(f"폴더가 없습니다: {folder}")
        return
    print(f"{APP_NAME} 감시 중: {folder}")
    print("   (종료: Ctrl+C)")
    log(f"감시 시작: {folder}")

    def on_result(r):
        print(f"\n새 파일: {r.path.name} - {r.verdict} (점수 {r.score})")
        handle(r, asker)

    try:
        engines = load_engines()
        if engines:
            print(f"   엔진: {', '.join(engines.active_names()) or '없음'}")
        Watcher(folder, on_result, interval, engines).run()
    except KeyboardInterrupt:
        print("\n감시를 종료합니다.")
        log("감시 종료")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="maeguard", description=f"{APP_NAME} - 간단한 백신 프로그램")
    ap.add_argument("--yes", action="store_true", help="묻지 않고 자동 차단")
    ap.add_argument("--gui", action="store_true", help="팝업창으로 물어보기")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="파일/폴더 바이러스 검사")
    s.add_argument("path", type=Path)

    w = sub.add_parser("watch", help="다운로드 폴더 감시")
    w.add_argument("folder", type=Path, nargs="?", default=Path.home() / "Downloads")
    w.add_argument("--interval", type=float, default=2.0, help="확인 주기(초)")

    sub.add_parser("update", help="악성코드 DB + YARA 규칙 업데이트")
    ak = sub.add_parser("abuse-key", help="abuse.ch(MalwareBazaar) Auth-Key 저장")
    ak.add_argument("key")
    k = sub.add_parser("vt-key", help="VirusTotal API 키 저장")
    k.add_argument("key")

    q = sub.add_parser("quarantine", help="격리소 관리")
    q.add_argument("action", choices=["list", "restore", "delete"])
    q.add_argument("id", nargs="?")

    args = ap.parse_args(argv)
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    asker = Asker(auto_yes=args.yes, gui=args.gui)
    if args.cmd == "scan":
        return cmd_scan(args.path, asker)
    if args.cmd == "watch":
        cmd_watch(args.folder, asker, args.interval)
        return 0
    if args.cmd == "update":
        import maeguard_engines as me
        try:
            print(f"악성코드 해시: {update_signatures(me.load_config().get('abusech_key', ''))}개 추가")
        except NoAuthKey:
            print("악성코드 해시: abuse.ch 키가 없어 건너뜀 (python maeguard.py abuse-key <키>)")
        except ValueError as e:
            print(f"악성코드 해시: {e}")
        y = me.YaraEngine()
        print(f"YARA 규칙: {y.update()}개" if y.yara else f"YARA 건너뜀: {y.error}")
        return 0
    if args.cmd == "abuse-key":
        import maeguard_engines as me
        cfg = me.load_config()
        cfg["abusech_key"] = args.key.strip()
        me.save_config(cfg)
        try:
            print(f"저장했습니다. 악성코드 해시 {update_signatures(cfg['abusech_key'])}개 추가")
        except ValueError as e:
            print(f"저장했지만 업데이트 실패: {e}")
        return 0
    if args.cmd == "vt-key":
        import maeguard_engines as me
        ok, msg = me.test_vt_key(args.key)
        print(msg)
        if ok:
            cfg = me.load_config()
            cfg["vt_api_key"] = args.key.strip()
            me.save_config(cfg)
            print("저장했습니다.")
        return 0 if ok else 1
    cmd_quarantine(args.action, args.id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
