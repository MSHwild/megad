# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

## Signed artifacts

Only the Windows installer (`MaeGuard_Setup_*.exe`) and the program it installs (`MaeGuard.exe`) are signed.
They are built from this repository by the GitHub Actions workflow in `.github/workflows/build.yml`
and published on the [Releases](https://github.com/MSHwild/megad/releases) page. Nothing is built or signed on a personal machine.

## Team roles

| Role | Members |
|---|---|
| Committers and reviewers | [MSHwild](https://github.com/MSHwild) |
| Approvers | [MSHwild](https://github.com/MSHwild) |

All members use multi-factor authentication for GitHub and SignPath.
Every signing request is approved manually by an approver before a release is published.

## Privacy policy

This program will not transfer any information to other networked systems unless the user turns the feature on and enters their own API key:

- **VirusTotal**: sends the SHA-256 hash of new files (never the file itself) to look up existing scan results.
- **MalwareBazaar (abuse.ch)**: downloads the list of recent malware hashes using the user's Auth-Key.
- **YARA Forge (GitHub)**: downloads public detection rules once a week. No user data is sent.

The developer does not run any server and does not collect user data. Details: [PRIVACY.md](PRIVACY.md).

## Third-party components

All bundled components are open source: Python, yara-python, pystray, Pillow, and the NSIS installer runtime.

---

## 한국어 요약

- 서명은 SignPath Foundation의 오픈소스 무료 서명을 사용합니다.
- 서명되는 파일은 GitHub Actions에서 자동으로 빌드한 설치 파일과 프로그램뿐이며, 개인 PC에서 빌드하거나 서명하지 않습니다.
- 서명 요청은 관리자(MSHwild)가 직접 승인한 뒤에만 릴리스됩니다.
- 사용자가 직접 켜고 키를 입력한 기능(VirusTotal, MalwareBazaar)만 인터넷과 통신하며, 개발자는 사용자 데이터를 수집하지 않습니다.
