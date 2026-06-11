"""
Shared Frida wrapper for NewWorld.exe agent scripts.

Spawns the target suspended, attaches Frida, loads the agent (always
prefixed with _common.js + _dtls_ledger.js), explicitly arms hooks via
rpc.exports.install *before* resume, then waits up to timeout_s for
events. Routes every agent send() to a per-run JSONL log under logs/
and pretty-prints to stdout.

Always-on DTLS ledger:
  Every Frida session now captures SSL_read / SSL_write plaintext +
  TLS keylog automatically. Output lands in
  captures/<session>/dtls/{ledger.bin, keylog.txt, meta.json}.
  Probe-specific data lives under captures/<session>/<probe_dir>/
  (subclasses choose their own dir).

Subclass `FridaRunner` to add per-script payload handling (override
on_payload) or pass/fail criteria (set self.exit_code).
"""
from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import frida

HERE          = Path(__file__).parent
LOGS_DIR      = HERE / "logs"
COMMON_JS     = HERE / "_common.js"
DTLS_LEDGER_JS = HERE / "_dtls_ledger.js"
CAPTURES_ROOT = HERE / "captures"


class FridaRunner:
    def __init__(self, target_path: str, scripts: list[str],
                 timeout_s: float = 30.0,
                 log_stem: str | None = None,
                 session: str | None = None,
                 with_dtls_ledger: bool = True):
        self.target_path = target_path
        self.script_paths = [HERE / s for s in scripts]
        self.timeout_s = timeout_s
        self.log_stem = log_stem or self.script_paths[-1].stem
        self.with_dtls_ledger = with_dtls_ledger
        self.session = session or datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
        self.session_dir = CAPTURES_ROOT / self.session
        self.session_dir.mkdir(parents=True, exist_ok=True)

        self.exit_code = 0
        self.log_path: Path | None = None
        self._device = None
        self._session = None
        self._script = None
        self._pid = None
        self._detached = threading.Event()
        self._detached_reason: str | None = None
        self._detached_crash: object | None = None
        self._log_file = None

        # Auto-ledger sinks (deferred to _open_dtls_sinks, called from
        # run() AFTER subclasses have had a chance to override
        # self.session / self.session_dir in their own __init__).
        self._dtls_dir: Path | None = None
        self._ledger_path: Path | None = None
        self._keylog_path: Path | None = None
        self._meta_path: Path | None = None
        self._ledger_f = None
        self._keylog_f = None
        self._dtls_meta: dict = {}
        self._ledger_bytes   = 0
        self._ledger_batches = 0
        self._keylog_lines   = 0
        self._last_flush_ts  = time.time()

    # --- public lifecycle ------------------------------------------------

    def run(self) -> int:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.log_path = LOGS_DIR / f"{ts}_{self.log_stem}.log"
        print(f"-- log file: {self.log_path}")
        print(f"-- session:  {self.session}")
        # Open auto-ledger sinks NOW (after subclass __init__ ran and may
        # have overridden self.session). The ledger lives at
        # captures/<session>/dtls/ regardless of any subclass-specific
        # subdir under captures/<session>/.
        self._open_dtls_sinks()
        if self.with_dtls_ledger:
            print(f"-- auto-ledger: {self._ledger_path}")
        self._log_file = self.log_path.open("w", encoding="utf-8", buffering=1)

        try:
            self._spawn_and_load()
            self._install_hooks_and_resume()
            self._wait_for_exit()
        except Exception as e:
            self._record("runner_error", {"msg": repr(e)})
            self.exit_code = 99
            raise
        finally:
            self._cleanup()
            if self._log_file:
                self._log_file.close()
                self._log_file = None

        return self.exit_code

    # --- deferred sink setup --------------------------------------------

    def _open_dtls_sinks(self) -> None:
        """Open the always-on DTLS ledger sinks. Called from run() so that
        subclasses can override self.session in their __init__ before the
        capture path gets locked in. Resolves the dtls/ dir based on
        captures/<self.session>/, which is the canonical session root --
        even if the subclass uses a different self.session_dir for its
        own probe data."""
        # Always anchor to captures/<session>/dtls regardless of any
        # subclass-specific session_dir override.
        dtls_root = CAPTURES_ROOT / self.session / "dtls"
        dtls_root.mkdir(parents=True, exist_ok=True)
        self._dtls_dir    = dtls_root
        self._ledger_path = dtls_root / "ledger.bin"
        self._keylog_path = dtls_root / "keylog.txt"
        self._meta_path   = dtls_root / "meta.json"
        if self.with_dtls_ledger:
            self._ledger_f = self._ledger_path.open("ab")
            self._keylog_f = self._keylog_path.open("a", encoding="ascii")
        self._dtls_meta = {
            "session": self.session,
            "started_at_utc": datetime.utcnow().isoformat() + "Z",
            "target": self.target_path,
            "ledger_path": str(self._ledger_path),
            "keylog_path": str(self._keylog_path),
            "with_dtls_ledger": self.with_dtls_ledger,
            "hooks": None,
        }

    # --- overridable hooks for subclasses -------------------------------

    def on_payload(self, payload: dict) -> None:
        """Called for every Frida send() event whose payload is a dict.
        Subclasses override to check pass/fail criteria. The message has
        already been logged + printed by the time we get here, so
        subclasses only deal with semantics."""
        return

    # --- internal -------------------------------------------------------

    def _spawn_and_load(self) -> None:
        if not Path(self.target_path).is_file():
            raise FileNotFoundError(self.target_path)
        if not COMMON_JS.is_file():
            raise FileNotFoundError(COMMON_JS)
        for p in self.script_paths:
            if not p.is_file():
                raise FileNotFoundError(p)

        # Drop steam_appid.txt next to the exe right before spawn.
        # NW (or Steam) deletes this file between runs, so we recreate
        # it on every launch. Without it, the SteamAPI minidump SDK init
        # fails noisily and you also lose the breakpad appid binding.
        try:
            appid_path = Path(self.target_path).with_name("steam_appid.txt")
            appid_path.write_text("1063730\n", encoding="ascii")
        except OSError as e:
            print(f"-- warning: couldn't write steam_appid.txt: {e}")

        # Build the agent script. Order matters:
        #   1. _common.js (defines nwInit, nwRva, nwSend, nwHexdump)
        #   2. _dtls_ledger.js if enabled (self-arms SSL hooks at top)
        #   3. user scripts (define their own hooks via rpc.exports.install)
        chunks = [COMMON_JS.read_text(encoding="utf-8")]
        if self.with_dtls_ledger and DTLS_LEDGER_JS.is_file():
            chunks.append(DTLS_LEDGER_JS.read_text(encoding="utf-8"))
        chunks.extend(p.read_text(encoding="utf-8") for p in self.script_paths)
        agent_src = "\n".join(chunks)

        self._device = frida.get_local_device()
        print(f"-- spawning {self.target_path}")
        self._pid = frida.spawn(self.target_path)
        print(f"   pid={self._pid}")
        self._session = self._device.attach(self._pid)
        self._session.on("detached", self._on_detached)

        self._script = self._session.create_script(agent_src)
        self._script.on("message", self._on_message)
        self._script.load()
        print(f"-- script loaded")

    def _install_hooks_and_resume(self) -> None:
        # rpc.exports method names are lowercased by Frida. Scripts MUST
        # export an `install` method that arms all their hooks; the
        # wrapper resumes only after install() returns. This eliminates
        # any load-vs-resume race for hooks targeting the entry stub.
        if not hasattr(self._script.exports_sync, "install"):
            raise RuntimeError(
                "agent script must export rpc.exports.install; "
                "found exports: " + repr(dir(self._script.exports_sync)))
        self._script.exports_sync.install()
        print(f"-- install() returned, resuming pid {self._pid}")
        frida.resume(self._pid)

    def _wait_for_exit(self) -> None:
        if not self._detached.wait(timeout=self.timeout_s):
            print(f"-- timeout after {self.timeout_s}s, killing pid {self._pid}")
            try:
                frida.kill(self._pid)
            except frida.ProcessNotFoundError:
                pass
            self._detached.wait(timeout=2.0)

    def _cleanup(self) -> None:
        # Auto-ledger flush + close
        if self.with_dtls_ledger and self._ledger_f is not None:
            try:
                self._ledger_f.flush()
                self._ledger_f.close()
            except Exception:
                pass
            try:
                self._keylog_f.flush()
                self._keylog_f.close()
            except Exception:
                pass
            self._dtls_meta["stopped_at_utc"] = datetime.utcnow().isoformat() + "Z"
            self._dtls_meta["ledger_bytes_received"]   = self._ledger_bytes
            self._dtls_meta["ledger_batches_received"] = self._ledger_batches
            self._dtls_meta["keylog_lines_received"]   = self._keylog_lines
            try:
                self._meta_path.write_text(json.dumps(self._dtls_meta, indent=2))
            except Exception as e:
                print(f"-- warning: failed to write dtls/meta.json: {e}")
            print()
            print("-- auto-ledger summary")
            print(f"   ledger        = {self._ledger_path}")
            print(f"   ledger bytes  = {self._ledger_bytes}")
            print(f"   ledger batches= {self._ledger_batches}")
            print(f"   keylog lines  = {self._keylog_lines}")

        for closer in (self._script, self._session):
            try:
                if closer is not None:
                    closer.unload() if hasattr(closer, "unload") else closer.detach()
            except Exception:
                pass

    # --- frida callbacks ------------------------------------------------

    def _on_message(self, message: dict, data) -> None:
        if message.get("type") == "send":
            payload = message.get("payload")
            if not isinstance(payload, dict):
                self._record("non_dict_payload", {"raw": repr(payload)})
                return
            ptype = payload.get("type")

            # Auto-ledger: bypass JSONL trace for the hot-path ledger
            # batches, write straight to disk. Other dtls events keep
            # the JSONL trace.
            if self.with_dtls_ledger:
                if ptype == "dtls_ledger" and data is not None:
                    if self._ledger_f is not None:
                        self._ledger_f.write(data)
                    self._ledger_bytes   += len(data)
                    self._ledger_batches += 1
                    now = time.time()
                    if now - self._last_flush_ts > 1.0 and self._ledger_f is not None:
                        self._ledger_f.flush()
                        self._last_flush_ts = now
                    return
                if ptype == "dtls_keylog":
                    line = (f'{payload.get("label", "")} '
                            f'{payload.get("cr_hex", "")} '
                            f'{payload.get("sec_hex", "")}\n')
                    if self._keylog_f is not None:
                        self._keylog_f.write(line)
                        self._keylog_f.flush()
                    self._keylog_lines += 1
                    # fall through to JSONL trace below
                elif ptype == "dtls_hook_installed":
                    self._dtls_meta["hooks"] = {
                        k: payload.get(k) for k in (
                            "ssl_read", "ssl_write", "nss_keylog",
                            "first16_ssl_read", "first16_ssl_write",
                            "first16_nss_keylog",
                        )
                    }
                    # fall through

            self._record(ptype or "?", payload, raw_payload=True)
            try:
                self.on_payload(payload)
            except Exception as e:
                self._record("on_payload_error", {"msg": repr(e)})
        elif message.get("type") == "error":
            self._record("agent_error", {
                "description": message.get("description"),
                "stack":       message.get("stack"),
                "fileName":    message.get("fileName"),
                "lineNumber":  message.get("lineNumber"),
            })
            self.exit_code = max(self.exit_code, 2)
        else:
            self._record("frida_message", {"raw": message})

    def _on_detached(self, reason: str, crash) -> None:
        self._detached_reason = reason
        self._detached_crash = crash
        self._record("detached", {
            "reason": reason,
            "crash":  repr(crash) if crash else None,
        })
        self._detached.set()

    # --- logging --------------------------------------------------------

    def _record(self, event_type: str, payload: dict,
                raw_payload: bool = False) -> None:
        # If the agent already sent a fully-formed event, log it verbatim
        # so phase-2 tooling sees the original schema. Otherwise wrap it
        # in our local envelope.
        if raw_payload:
            entry = payload
        else:
            entry = {
                "ts_ms": int(time.time() * 1000),
                "type":  event_type,
                **(payload or {}),
            }
        line = json.dumps(entry, default=str)
        print(line, flush=True)
        if self._log_file:
            self._log_file.write(line + "\n")
