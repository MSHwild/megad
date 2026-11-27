"""외부 검사 엔진 (Defender, VirusTotal, YARA)"""

import json
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

HOME = Path.home() / ".maeguard"
CONFIG_FILE = HOME / "config.json"
VT_CACHE_FILE = HOME / "vt_cache.json"
YARA_DIR = HOME / "yara"
YARA_SOURCE = YARA_DIR / "rules.yar"
YARA_COMPILED = YARA_DIR / "rules.yarc"
YARA_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
YARA_MAX_AGE = 7 * 24 * 3600

DEFAULT_CONFIG = {
    "use_defender": True,
    "use_virustotal": True,
    "use_yara": True,
    "vt_api_key": "",
    "abusech_key": "",
}

NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg: dict) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


class DefenderEngine:
    name = "Defender"

    def __init__(self):
        self.exe = self._find()

    @staticmethod
    def _find():
        if os.name != "nt":
            return None
        plat = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft/Windows Defender/Platform"
        try:
            versions = sorted((p for p in plat.iterdir() if (p / "MpCmdRun.exe").exists()),
                              key=lambda p: [int(x) if x.isdigit() else 0 for x in p.name.split("-")[0].split(".")],
                              reverse=True)
            if versions:
                return versions[0] / "MpCmdRun.exe"
        except OSError:
            pass
        legacy = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender/MpCmdRun.exe"
        return legacy if legacy.exists() else None

    @property
    def available(self) -> bool:
        return self.exe is not None

    def scan(self, path: Path):
        if not self.exe:
            return None
        try:
            proc = subprocess.run(
                [str(self.exe), "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"],
                capture_output=True, timeout=120, creationflags=NO_WINDOW)
        except (OSError, subprocess.TimeoutExpired) as e:
            return None if isinstance(e, OSError) else (False, "시간 초과")
        res = parse_defender_output(proc.returncode, proc.stdout + proc.stderr)
        if res is None:
            _log_engine(f"Defender 결과를 읽지 못함 (코드 {proc.returncode}): {path}")
        return res


def parse_defender_output(returncode: int, raw: bytes):
    if b"\x00" in raw[:200]:
        out = raw.decode("utf-16-le", "ignore")
    else:
        out = raw.decode("utf-8", "ignore") + "\n" + raw.decode("cp949", "ignore")
    name = re.search(r"Threat\s*:\s*(\S+)", out) or re.search(r"위협\s*:\s*(\S+)", out)
    found = re.search(r"found\s+(\d+)\s+threat", out, re.I)
    if name or (found and int(found.group(1)) > 0):
        return True, (name.group(1) if name else "Defender 탐지")
    if returncode in (0, 2) and (found or "Scan finished" in out or "no threats" in out):
        return False, ""
    return None


def _log_engine(msg: str) -> None:
    try:
        from datetime import datetime
        HOME.mkdir(parents=True, exist_ok=True)
        with open(HOME / "log.txt", "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}\n")
    except OSError:
        pass


class VirusTotalEngine:
    name = "VirusTotal"
    PER_MINUTE = 4
    CACHE_TTL = 3 * 24 * 3600
    UNKNOWN_TTL = 6 * 3600

    def __init__(self, api_key: str):
        self.api_key = (api_key or "").strip()
        self.lock = threading.Lock()
        self.calls = []
        try:
            self.cache = json.loads(VT_CACHE_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.cache = {}
        self.disabled_reason = None

    @property
    def available(self) -> bool:
        return bool(self.api_key) and self.disabled_reason is None

    def _save_cache(self):
        try:
            HOME.mkdir(parents=True, exist_ok=True)
            VT_CACHE_FILE.write_text(json.dumps(self.cache), encoding="utf-8")
        except OSError:
            pass

    def _wait_rate_limit(self, max_wait: float):
        while True:
            now = time.time()
            self.calls = [t for t in self.calls if now - t < 60]
            if len(self.calls) < self.PER_MINUTE:
                self.calls.append(now)
                return True
            wait = 60 - (now - self.calls[0]) + 0.5
            if wait > max_wait:
                return False
            time.sleep(wait)

    def lookup(self, sha256: str, max_wait: float = 65):
        if not self.available:
            return None
        with self.lock:
            c = self.cache.get(sha256)
            if c and time.time() - c["t"] < (self.UNKNOWN_TTL if c.get("unknown") else self.CACHE_TTL):
                return c
            if not self._wait_rate_limit(max_wait):
                return None
            req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}",
                                         headers={"x-apikey": self.api_key, "User-Agent": "MaeGuard"})
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    attrs = json.load(resp)["data"]["attributes"]
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    res = {"unknown": True, "t": time.time()}
                    self.cache[sha256] = res
                    self._save_cache()
                    return res
                if e.code in (401, 403):
                    self.disabled_reason = "API 키가 올바르지 않습니다"
                elif e.code == 429:
                    self.calls = [time.time()] * self.PER_MINUTE
                return None
            except (OSError, ValueError, KeyError):
                return None
            st = attrs.get("last_analysis_stats", {})
            label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
            res = {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
                   "total": sum(v for v in st.values() if isinstance(v, int)), "label": label, "t": time.time()}
            self.cache[sha256] = res
            self._save_cache()
            return res


def test_vt_key(api_key: str):
    eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{eicar}",
                                 headers={"x-apikey": api_key.strip(), "User-Agent": "MaeGuard"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            json.load(resp)
        return True, "API 키가 정상입니다"
    except urllib.error.HTTPError as e:
        return False, "API 키가 올바르지 않습니다" if e.code in (401, 403) else f"오류 {e.code}"
    except OSError as e:
        return False, f"연결 실패: {e}"


class YaraEngine:
    name = "YARA"

    def __init__(self):
        self.rules = None
        self.count = 0
        self.error = None
        try:
            import yara
            self.yara = yara
        except Exception:
            self.yara = None
            self.error = "yara-python 이 설치되어 있지 않습니다"
            return
        self.reload()

    @property
    def available(self) -> bool:
        return self.rules is not None

    def reload(self):
        if not self.yara:
            return
        try:
            if YARA_COMPILED.exists() and YARA_SOURCE.exists() and \
                    YARA_COMPILED.stat().st_mtime >= YARA_SOURCE.stat().st_mtime:
                self.rules = self.yara.load(str(YARA_COMPILED))
            elif YARA_SOURCE.exists():
                self.rules = self.yara.compile(str(YARA_SOURCE))
                self.rules.save(str(YARA_COMPILED))
            if YARA_SOURCE.exists():
                self.count = sum(1 for line in open(YARA_SOURCE, encoding="utf-8", errors="ignore")
                                 if line.startswith("rule "))
        except Exception as e:
            self.rules = None
            self.error = f"규칙 불러오기 실패: {e}"

    def needs_update(self) -> bool:
        return not YARA_SOURCE.exists() or time.time() - YARA_SOURCE.stat().st_mtime > YARA_MAX_AGE

    def update(self, timeout: float = 120) -> int:
        if not self.yara:
            raise RuntimeError(self.error)
        req = urllib.request.Request(YARA_URL, headers={"User-Agent": "MaeGuard"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            blob = resp.read()
        YARA_DIR.mkdir(parents=True, exist_ok=True)
        tmp_zip = YARA_DIR / "download.zip"
        tmp_zip.write_bytes(blob)
        with zipfile.ZipFile(tmp_zip) as z:
            name = next(n for n in z.namelist() if n.endswith(".yar"))
            text = z.read(name)
        tmp_zip.unlink(missing_ok=True)
        new_src = YARA_DIR / "rules.new.yar"
        new_src.write_bytes(text)
        compiled = self.yara.compile(str(new_src))
        os.replace(new_src, YARA_SOURCE)
        compiled.save(str(YARA_COMPILED))
        self.rules = compiled
        self.count = text.count(b"\nrule ")
        self.error = None
        return self.count

    def scan(self, path: Path):
        if not self.rules:
            return []
        try:
            matches = self.rules.match(str(path), timeout=20)
        except Exception:
            return []
        out = []
        for m in matches:
            meta = m.meta or {}
            try:
                score = int(meta.get("score", 70))
            except (TypeError, ValueError):
                score = 70
            out.append((m.rule, score, str(meta.get("description", ""))[:80]))
        out.sort(key=lambda x: -x[1])
        return out


class Engines:
    def __init__(self, cfg: dict = None):
        self.cfg = cfg or load_config()
        self.defender = DefenderEngine() if self.cfg.get("use_defender") else None
        self.vt = VirusTotalEngine(self.cfg.get("vt_api_key", "")) if self.cfg.get("use_virustotal") else None
        self.yara = YaraEngine() if self.cfg.get("use_yara") else None

    def active_names(self):
        names = []
        if self.defender and self.defender.available:
            names.append("Defender")
        if self.vt and self.vt.available:
            names.append("VirusTotal")
        if self.yara and self.yara.available:
            names.append(f"YARA 규칙 {self.yara.count:,}개")
        return names

    def apply(self, path: Path, sha256: str, r, vt_wait: float = 65, use_vt: bool = True) -> None:
        if self.yara and self.yara.available:
            hits = self.yara.scan(path)
            if hits:
                rule, score, desc = hits[0]
                r.add(min(score, 100), f"YARA 규칙 탐지: {rule}" + (f" ({desc})" if desc else ""))
                if score >= 80 and not r.malware_name:
                    r.malware_name = f"YARA:{rule}"
                for rule, score, _ in hits[1:3]:
                    r.add(10, f"YARA 규칙 추가 탐지: {rule}")

        if use_vt and self.vt and self.vt.available:
            res = self.vt.lookup(sha256, max_wait=vt_wait)
            if res and not res.get("unknown"):
                mal, tot, label = res["malicious"], res["total"], res.get("label") or ""
                tag = f"VirusTotal {mal}/{tot} 백신 탐지" + (f" ({label})" if label else "")
                if mal >= 5:
                    r.add(100, tag)
                    if not r.malware_name:
                        r.malware_name = label or f"VirusTotal {mal}/{tot}"
                elif mal >= 2:
                    r.add(40, tag)
                elif mal == 1 or res.get("suspicious", 0) >= 2:
                    r.add(15, tag)

        if self.defender and self.defender.available:
            res = self.defender.scan(path)
            if res and res[0]:
                r.add(100, f"Windows Defender 탐지: {res[1]}")
                if not r.malware_name:
                    r.malware_name = res[1]
