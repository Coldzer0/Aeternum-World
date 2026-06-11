"""
nw_capture — capture NewWorld.exe HTTPS auth bootstrap traffic & DTLS Decrypted.

Two-stage pipeline (runs both stages by default; pass --no-extract to skip the second):

  1. Spawn NewWorld.exe via the no-EAC trick, attach Frida pre-resume,
     load nw_https_tap.js, write the raw JSONL log to logs/.
  2. Run scripts/extract_https_pairs.py on that log to reassemble per-
     request bundles under captures/<session>/<family>/. Default
     session name = dd_mm_yyyy_HH_MM of extraction.

Primary target: POST tokenservice.amazongames.com/games/new-world/tokens
to capture Amazon's real CreateToken response — this is what unblocks
the OmniSDK 203 wall at IDA 0x1479C9F00.

Timeout default is 10 minutes, well past the auth bootstrap timing in
first-light/docs/connection-flow.md (~50s to world entry), with margin
for slow auth or queue waits.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from _runner import FridaRunner  # noqa: E402


DEFAULT_NW_EXE = r"G:\SteamLibrary\steamapps\common\New World\Bin64\NewWorld.exe"
DEFAULT_TIMEOUT_S = 60000.0

NETWORKTOOLS_ROOT = HERE
EXTRACTOR        = HERE / "extract_https_pairs.py"
CAPTURES_ROOT    = NETWORKTOOLS_ROOT / "captures"


class HttpsTapRunner(FridaRunner):
    def __init__(self, target_path: str, timeout_s: float, session_name: str):
        super().__init__(
            target_path=target_path,
            scripts=["nw_https_tap.js"],
            timeout_s=timeout_s,
            log_stem="nw_https_tap",
            session=session_name
        )
        self._tokenservice_seen = False

    def on_payload(self, payload: dict) -> None:
        # Highlight tokenservice events in the console so the operator
        # can see when the OmniSDK path is exercised without grepping
        # through the JSONL afterwards.
        host = payload.get("host", "")
        path = payload.get("path", "")
        if "tokenservice.amazongames.com" in host:
            self._tokenservice_seen = True
            kind = payload.get("type", "?")
            print(f"  [!] tokenservice event: {kind} path={path}", flush=True)


def run_extractor(log_path: Path, session: str | None,
                  one_per_endpoint: bool) -> int:
    if not EXTRACTOR.is_file():
        print(f"-- WARN: extractor not found at {EXTRACTOR}; skipping extract")
        return 0
    cmd = [
        sys.executable, str(EXTRACTOR),
        str(log_path),
        "--out", str(CAPTURES_ROOT),
    ]
    if session:
        cmd += ["--session", session]
    if one_per_endpoint:
        cmd += ["--one-per-endpoint"]
    print()
    print(f"-- extracting bundles to {CAPTURES_ROOT}/")
    return subprocess.call(cmd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target",
        default=DEFAULT_NW_EXE,
        help=f"path to NewWorld.exe (default: {DEFAULT_NW_EXE})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help=f"timeout seconds before killing the spawn (default: {DEFAULT_TIMEOUT_S})",
    )
    parser.add_argument(
        "--no-extract",
        action="store_true",
        help="skip the auto-extract pass; just write the raw JSONL log",
    )
    parser.add_argument(
        "--session",
        default=None,
        help="session name passed to extract_https_pairs.py "
             "(default: dd_mm_yyyy_HH_MM of extraction time)",
    )
    parser.add_argument(
        "--one-per-endpoint",
        action="store_true",
        help="keep only the FIRST request per (verb, host, path). Use for "
             "building a canonical mock-response catalog. Default is to "
             "save every request, since repeated POSTs often carry "
             "differing state (e.g. each tokenservice CreateToken has a "
             "fresh Steam ticket + nonce).",
    )
    args = parser.parse_args()

    runner = HttpsTapRunner(args.target, args.timeout, args.session)
    rc = runner.run()

    if runner.log_path is None or not runner.log_path.is_file():
        print("-- no log file produced; nothing to extract")
        return rc
    if args.no_extract:
        print(f"-- skipped extract (--no-extract). log: {runner.log_path}")
        return rc

    ext_rc = run_extractor(
        runner.log_path,
        session=args.session,
        one_per_endpoint=args.one_per_endpoint,
    )
    return rc or ext_rc


if __name__ == "__main__":
    raise SystemExit(main())
