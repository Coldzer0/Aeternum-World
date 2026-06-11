"""
extract_https_pairs.py — reassemble nw_https_tap JSONL events into
per-request bundles.

Output layout (default):
    <out>/<session>/<family>/<seq>_<verb>_<host>__<path>.{meta.json,req.{body,json},resp.{body,json,hex}}

  <session>  — `--session` arg, default = dd_mm_yyyy_HH_MM of the
               extraction run. Lets us keep multiple capture sessions
               distinct without clobbering each other.
  <seq>      — 5-digit zero-padded request sequence number assigned by
               started_ms order across the *whole* capture session.
               Preserved across --one-per-endpoint dedup so the number
               reflects the original first-occurrence position.
  <family>   — bucket name from `slugify_host`: tokenservice,
               channel_config, gateway_cf, content_motd, entitlements,
               catalog, … (matches first-light/auth_mock.py ROUTES).
  body files — `.req.body` / `.resp.body` if any chunk arrived as UTF-8,
               `.req.bin`  / `.resp.bin`  if any arrived as hex (binary
               fallback when WinHTTP's payload wasn't valid UTF-8).
               `.bin` files contain **real binary bytes**, hex-decoded
               from the JS-side capture — so e.g. a DDS image can be
               renamed `.dds` and opened in an image viewer.
               `.req.json` / `.resp.json` only when the joined text
               parses as JSON.

A separate `summary.json` is written under <session>/ enumerating the
session, seq range, host/path catalog, and per-endpoint occurrences.

The script also supports `--summary` (no writes) for quick triage.
"""
from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class BodyData:
    """Accumulated chunks for one request or response body.

    text_chunks holds the contents of `kind: utf8` chunks (the typical
    case for JSON request/response bodies). hex_chunks holds the
    contents of `kind: hex` chunks — these arrive when the WinHTTP
    payload wasn't valid UTF-8 (binary response, e.g. DDS image, or
    encrypted blob). Keeping them apart prevents us from interleaving
    bytes and chars and corrupting both."""
    text_chunks: list[str] = dataclasses.field(default_factory=list)
    hex_chunks:  list[str] = dataclasses.field(default_factory=list)
    wire_bytes:     int = 0  # sum of `total` (bytes-on-wire) reported per chunk
    captured_bytes: int = 0  # sum of `captured` (bytes the tap actually saved)

    @property
    def joined_text(self) -> str:
        return "".join(self.text_chunks)

    @property
    def joined_hex(self) -> str:
        return "".join(self.hex_chunks)

    @property
    def has_text(self) -> bool:
        return any(self.text_chunks)

    @property
    def has_hex(self) -> bool:
        return any(self.hex_chunks)

    @property
    def truncated(self) -> bool:
        """True if any chunk was capped by BODY_CAP_BYTES in the JS tap
        (i.e. captured_bytes < wire_bytes for at least one chunk)."""
        return self.wire_bytes > 0 and self.captured_bytes < self.wire_bytes


@dataclasses.dataclass
class Request:
    handle:        str
    host:          str
    port:          int
    verb:          str
    path:          str
    headers_extra: str
    started_ms:    int
    seq:           int = 0  # 1-indexed, assigned post-parse by started_ms order
    closed_ms:     int = 0
    response_status_line: str = ""
    response_headers:     str = ""
    request_body:  BodyData = dataclasses.field(default_factory=BodyData)
    response_body: BodyData = dataclasses.field(default_factory=BodyData)

    def endpoint_slug(self) -> str:
        host_slug = re.sub(r"[^A-Za-z0-9._-]", "_", self.host)
        path_slug = re.sub(r"[^A-Za-z0-9._-]", "_", self.path).strip("_") or "root"
        return f"{host_slug}__{path_slug[:120]}"


# ---------------------------------------------------------------------------
# Family routing — keeps captures grouped to match auth_mock.py ROUTES
# ---------------------------------------------------------------------------

def slugify_host(host: str) -> str:
    if "tokenservice.amazongames.com" in host:
        return "tokenservice"
    if host.endswith(".cloudfront.net"):
        if "d1hkbwzm1bktgo" in host:
            return "content_motd"
        if "d2c74t4zimux3r" in host:
            return "channel_config"
        return "gateway_cf"
    if "execute-api" in host and "amazonaws.com" in host:
        return "gateway_apigw"
    if "ags-javelin-remote-config" in host:
        return "remote_config"
    if "entitlementservice" in host:
        return "entitlements"
    if "catalogservice" in host:
        return "catalog"
    if "content-service" in host:
        return "content_service"
    if "agsprivacysettingsservice" in host:
        return "privacy"
    if "vivox" in host:
        return "vivox"
    if "dynamodb" in host:
        return "dynamodb"
    if "kinesis" in host:
        return "kinesis"
    if "sts" in host:
        return "sts"
    return re.sub(r"[^A-Za-z0-9._-]", "_", host)


# ---------------------------------------------------------------------------
# Chunk absorption helpers — single source of truth for how chunk events
# update a BodyData (used by both request and response paths so they
# can't diverge).
# ---------------------------------------------------------------------------

def _absorb_chunk_event(body: BodyData, ev: dict) -> None:
    """For *_body_chunk events (one per WinHttpReadData/WriteData call).

    Drops duplicates emitted when NW invokes both WinHttpReadData and
    WinHttpReadDataEx sequentially with identical data. The dup signal
    is specific: a DIFFERENT `via` tag than the previous chunk + same
    first-16-bytes fingerprint + within 10ms. Matching `via` with
    matching fingerprint is NOT a dup — that legitimately happens when
    a chunk-aligned run of identical bytes (e.g. zero padding in a DDS
    file) crosses a sync_read_ex chunk boundary."""
    kind = ev.get("kind", "")
    via  = ev.get("via", "")
    payload = ev.get("text", "") if kind == "utf8" \
              else (ev.get("hex", "") if kind == "hex" else "")
    if payload and via:
        fp_len = 16 if kind == "utf8" else 32  # 16 bytes = 32 hex chars
        fp = payload[:fp_len]
        ts = int(ev.get("ts_ms", 0))
        if (via != getattr(body, "_last_via", None)
                and fp == getattr(body, "_last_fp", None)
                and (ts - getattr(body, "_last_ts", 0)) < 10):
            return  # paired duplicate
        body._last_via = via
        body._last_fp  = fp
        body._last_ts  = ts
    if kind == "utf8":
        body.text_chunks.append(payload)
    elif kind == "hex":
        body.hex_chunks.append(payload)
    # 'empty' (or unknown) → contribute counters but no payload
    body.wire_bytes     += int(ev.get("total", 0) or 0)
    body.captured_bytes += int(ev.get("captured", 0) or 0)


def _absorb_aggregated_body(body: BodyData, ev: dict) -> None:
    """For the http_request_body event the JS emits at WinHttpReceiveResponse
    time. It's a JS-side join of all chunks; if it arrives, it is the
    canonical full body so we discard any partial chunk state."""
    kind     = ev.get("kind", "")
    body_str = ev.get("body", "")
    total    = int(ev.get("totalBytes", 0) or 0)
    body.text_chunks = []
    body.hex_chunks  = []
    if kind == "utf8":
        body.text_chunks = [body_str]
    elif kind == "hex":
        body.hex_chunks = [body_str]
    body.wire_bytes     = total
    # len(str) approximates captured bytes for utf8; for hex, each
    # captured byte is 2 chars on the wire.
    body.captured_bytes = (len(body_str) // 2) if kind == "hex" else len(body_str)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse(log_path: Path) -> list[Request]:
    """Walk the JSONL log and return a list of completed Request records
    in start-time order. WinHTTP recycles request handles aggressively,
    so we cannot use {handle: Request} as a long-lived index — we flush
    each Request from the in-flight map on http_request_closed, with
    handle-collision detection on http_request as a safety net."""
    completed: list[Request] = []
    in_flight: dict[str, Request] = {}

    def flush(handle: str) -> None:
        r = in_flight.pop(handle, None)
        if r is not None:
            completed.append(r)

    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = ev.get("type")
            h = ev.get("h", "")

            if t == "http_request":
                if h in in_flight:
                    flush(h)
                in_flight[h] = Request(
                    handle=h,
                    host=ev.get("host", ""),
                    port=int(ev.get("port", 443)),
                    verb=ev.get("verb", "?"),
                    path=ev.get("path", "/"),
                    headers_extra=ev.get("headers", ""),
                    started_ms=int(ev.get("ts_ms", 0)),
                )
            elif t == "http_request_body":
                r = in_flight.get(h)
                if r:
                    _absorb_aggregated_body(r.request_body, ev)
            elif t == "http_request_body_chunk":
                r = in_flight.get(h)
                if r:
                    _absorb_chunk_event(r.request_body, ev)
            elif t == "http_response_headers":
                r = in_flight.get(h)
                if r:
                    r.response_headers = ev.get("headers", "")
                    r.response_status_line = r.response_headers.split("\r\n", 1)[0]
            elif t == "http_response_body_chunk":
                r = in_flight.get(h)
                if r:
                    _absorb_chunk_event(r.response_body, ev)
            elif t == "http_request_closed":
                r = in_flight.get(h)
                if r:
                    r.closed_ms = int(ev.get("ts_ms", 0))
                flush(h)

    # Drain leftover requests that never received a close event (e.g.
    # process exited mid-request). Don't drop the trailing capture.
    for r in list(in_flight.values()):
        completed.append(r)
    in_flight.clear()

    completed.sort(key=lambda r: (r.started_ms, r.handle))
    for i, r in enumerate(completed, start=1):
        r.seq = i
    return completed


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def summarize(requests: list[Request]) -> None:
    by_endpoint: dict[tuple[str, str, str], int] = collections.Counter()
    for r in requests:
        by_endpoint[(r.verb, r.host, r.path)] += 1
    print(f"Total completed requests: {len(requests)}")
    if requests:
        first = requests[0]
        last  = requests[-1]
        print(f"Seq range: {first.seq}..{last.seq}  "
              f"(elapsed {(last.started_ms - first.started_ms) / 1000:.1f}s)")
    print()
    print(f"{'verb':<6} {'count':>5}  {'host':<55} path")
    print("-" * 120)
    for (verb, host, path), n in sorted(by_endpoint.items(), key=lambda kv: -kv[1]):
        print(f"{verb:<6} {n:>5}  {host:<55} {path}")


def _build_meta(r: Request) -> dict:
    return {
        "seq":      r.seq,
        "handle":   r.handle,
        "host":     r.host,
        "port":     r.port,
        "verb":     r.verb,
        "path":     r.path,
        "headers_extra_on_send": r.headers_extra,
        "started_ms":            r.started_ms,
        "closed_ms":             r.closed_ms,
        "duration_ms":           max(0, r.closed_ms - r.started_ms),
        "response_status_line":  r.response_status_line,
        "response_headers":      r.response_headers,
        "request": {
            "wire_bytes":     r.request_body.wire_bytes,
            "captured_bytes": r.request_body.captured_bytes,
            "has_text":       r.request_body.has_text,
            "has_hex":        r.request_body.has_hex,
            "truncated":      r.request_body.truncated,
        },
        "response": {
            "wire_bytes":     r.response_body.wire_bytes,
            "captured_bytes": r.response_body.captured_bytes,
            "has_text":       r.response_body.has_text,
            "has_hex":        r.response_body.has_hex,
            "truncated":      r.response_body.truncated,
        },
    }


def _write_body_files(family_dir: Path, stem: str, side: str, body: BodyData) -> None:
    """Write up to three files per side ('req' or 'resp'):
       <stem>.<side>.body  — joined UTF-8 text  (only if has_text)
       <stem>.<side>.bin   — real binary bytes  (only if has_hex; hex-decoded)
       <stem>.<side>.json  — pretty-parsed JSON (only if joined_text is JSON)"""
    if body.has_text:
        text = body.joined_text
        (family_dir / f"{stem}.{side}.body").write_text(text, encoding="utf-8")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if parsed is not None:
            (family_dir / f"{stem}.{side}.json").write_text(
                json.dumps(parsed, indent=2), encoding="utf-8"
            )
    if body.has_hex:
        # JS emits hex as ASCII; decode to real bytes so the file is the
        # actual payload (e.g. a DDS image is readable as-is). bytes.fromhex
        # tolerates whitespace but not partial digits — strip and validate.
        hex_str = "".join(body.joined_hex.split())  # remove any whitespace
        try:
            raw = bytes.fromhex(hex_str)
        except ValueError:
            # Salvage: drop trailing odd nibble so we keep as much as we can.
            if len(hex_str) % 2 == 1:
                hex_str = hex_str[:-1]
            raw = bytes.fromhex(hex_str)
        (family_dir / f"{stem}.{side}.bin").write_bytes(raw)


def write_bundles(
    requests: list[Request],
    session_dir: Path,
    only_endpoint: Optional[str] = None,
    one_per_endpoint: bool = False,
) -> tuple[int, dict]:
    """Returns (count_written, summary_for_index)."""
    session_dir.mkdir(parents=True, exist_ok=True)
    seen_endpoints: set[tuple[str, str, str]] = set()
    written = 0
    catalog: list[dict] = []

    for r in requests:  # already sorted + seq-numbered
        family = slugify_host(r.host)
        if only_endpoint and family != only_endpoint:
            continue
        endpoint_key = (r.verb, r.host, r.path)
        if one_per_endpoint and endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)

        family_dir = session_dir / family
        family_dir.mkdir(parents=True, exist_ok=True)

        slug = r.endpoint_slug()
        stem = f"{r.seq:05d}_{r.verb}_{slug[:80]}"

        (family_dir / f"{stem}.meta.json").write_text(
            json.dumps(_build_meta(r), indent=2), encoding="utf-8"
        )
        _write_body_files(family_dir, stem, "req",  r.request_body)
        _write_body_files(family_dir, stem, "resp", r.response_body)

        catalog.append({
            "seq":   r.seq,
            "verb":  r.verb,
            "host":  r.host,
            "path":  r.path,
            "family": family,
            "stem":  stem,
            "status": r.response_status_line,
            "request_wire_bytes":  r.request_body.wire_bytes,
            "response_wire_bytes": r.response_body.wire_bytes,
        })
        written += 1

    summary = {
        "request_count_written": written,
        "request_count_total":   len(requests),
        "first_seq": requests[0].seq  if requests else 0,
        "last_seq":  requests[-1].seq if requests else 0,
        "first_started_ms": requests[0].started_ms  if requests else 0,
        "last_started_ms":  requests[-1].started_ms if requests else 0,
        "one_per_endpoint": one_per_endpoint,
        "endpoint_filter":  only_endpoint,
        "catalog": catalog,
    }
    return written, summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _default_session_name() -> str:
    # dd_mm_yyyy_HH_MM (24h). Anchored to extraction time, not capture
    # time, since the user may rerun extraction multiple times on the
    # same log with different filters. Pass `--session` to override.
    return datetime.datetime.now().strftime("%d_%m_%Y_%H_%M")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("log", help="path to nw_https_tap.py JSONL log")
    p.add_argument("--out", default="captures",
                   help="root output directory (default: captures)")
    p.add_argument("--session", default=None,
                   help="session subdir under --out. "
                        "Default: dd_mm_yyyy_HH_MM of now.")
    p.add_argument("--summary", action="store_true",
                   help="print a summary of hosts+paths; don't write files")
    p.add_argument("--endpoint",
                   help="filter to a single endpoint family "
                        "(tokenservice, channel_config, gateway_cf, ...)")
    p.add_argument("--one-per-endpoint", action="store_true",
                   help="keep only the FIRST request per (verb, host, path). "
                        "The seq number recorded preserves the original "
                        "first-occurrence position in the full capture.")
    args = p.parse_args()

    log_path = Path(args.log)
    if not log_path.is_file():
        print(f"log not found: {log_path}", file=sys.stderr)
        return 2

    reqs = parse(log_path)

    if args.summary:
        summarize(reqs)
        return 0

    session_name = args.session or _default_session_name()
    session_dir  = Path(args.out).resolve() / session_name

    n, summary = write_bundles(
        reqs, session_dir,
        only_endpoint=args.endpoint,
        one_per_endpoint=args.one_per_endpoint,
    )

    summary["session"]  = session_name
    summary["source_log"] = str(log_path.resolve())
    (session_dir / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    print(f"wrote {n} request bundles to {session_dir}")
    print(f"  summary index: {session_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
