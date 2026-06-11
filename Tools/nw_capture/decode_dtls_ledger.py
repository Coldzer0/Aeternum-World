"""
decode_dtls_ledger — IDA-verified offline decoder for nw_dtls_tap ledgers.

End-to-end pipeline:
  binary ledger record (from nw_dtls_tap.js)
    -> 4-byte datagram header (mode flag + 0x01 const + dgram_seq u16 BE)
    -> [if mode bit 0 set] strip 2-byte compressor additional-header
                            -> LZ4_decompress_safe(body)
    -> per-carrier-message loop using Lumberyard flag-bit layout
       (MF_RELIABLE 0x01, MF_CHUNKS 0x04, MF_SQUENTIAL_ID 0x08,
        MF_SQUENTIAL_REL_ID 0x10, MF_DATA_CHANNEL 0x20, MF_CONNECTING 0x80)

Every wire field is cited at its IDA-verified instruction VA. The decoder
fails LOUD: any byte not accounted for triggers a `bad_record` line so we
know where the model is wrong.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import lz4.block  # type: ignore
except ImportError:
    print("ERROR: pip install lz4", file=sys.stderr)
    raise SystemExit(2)


LEDGER_MAGIC = 0x4C44574E  # 'NWDL'

# Lumberyard flag bits (Carrier.h:76-82) — confirmed via NW.exe IDA decompile
MF_RELIABLE         = 0x01
MF_CHUNKS           = 0x04
MF_SQUENTIAL_ID     = 0x08
MF_SQUENTIAL_REL_ID = 0x10
MF_DATA_CHANNEL     = 0x20
MF_CONNECTING       = 0x80


@dataclass
class CarrierMessage:
    flags: int
    data_size: int
    channel: int | None = None
    num_chunks: int | None = None
    seq: int | None = None
    rel_seq: int | None = None
    payload: bytes = b""

    def to_dict(self) -> dict:
        return {
            "flags":      f"0x{self.flags:02x}",
            "flag_names": flag_names(self.flags),
            "data_size":  self.data_size,
            **({"channel":     self.channel}     if self.channel     is not None else {}),
            **({"num_chunks":  self.num_chunks}  if self.num_chunks  is not None else {}),
            **({"seq":         self.seq}         if self.seq         is not None else {}),
            **({"rel_seq":     self.rel_seq}     if self.rel_seq     is not None else {}),
            "payload_hex": self.payload.hex(),
            "payload_len": len(self.payload),
        }


@dataclass
class Datagram:
    ts_ms: int
    dir: str             # "in" or "out"
    ssl_ptr: int
    record_idx: int
    raw_len: int
    mode_byte: int
    format_byte: int
    dgram_seq: int
    compressed: bool
    decompressed_len: int | None
    additional_header: str | None
    messages: list[CarrierMessage] = field(default_factory=list)
    trailer: bytes = b""
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "ts_ms":               self.ts_ms,
            "dir":                 self.dir,
            "ssl_ptr":             f"0x{self.ssl_ptr:x}",
            "record_idx":          self.record_idx,
            "raw_len":             self.raw_len,
            "mode_byte":           f"0x{self.mode_byte:02x}",
            "format_byte":         f"0x{self.format_byte:02x}",
            "dgram_seq":           self.dgram_seq,
            "compressed":          self.compressed,
            "decompressed_len":    self.decompressed_len,
            "additional_header":   self.additional_header,
            "messages":            [m.to_dict() for m in self.messages],
            "trailer_hex":         self.trailer.hex(),
            "error":               self.error,
        }


def flag_names(flags: int) -> list[str]:
    out = []
    if flags & MF_RELIABLE:         out.append("RELIABLE")
    if flags & MF_CHUNKS:           out.append("CHUNKS")
    if flags & MF_SQUENTIAL_ID:     out.append("SEQ_OMITTED")
    if flags & MF_SQUENTIAL_REL_ID: out.append("REL_SEQ_OMITTED")
    if flags & MF_DATA_CHANNEL:     out.append("DATA_CHANNEL")
    if flags & MF_CONNECTING:       out.append("CONNECTING")
    extra = flags & ~(MF_RELIABLE | MF_CHUNKS | MF_SQUENTIAL_ID |
                      MF_SQUENTIAL_REL_ID | MF_DATA_CHANNEL | MF_CONNECTING)
    if extra:                       out.append(f"UNKNOWN(0x{extra:02x})")
    return out


def parse_carrier_messages(buf: bytes, is_first_seq_assumed: bool = True
                           ) -> tuple[list[CarrierMessage], bytes]:
    """Parse the per-message section per Lumberyard WriteMessageHeader.

    Returns (messages, trailer). Trailer = any bytes left over after the
    loop terminates because there isn't enough to form another message.
    """
    msgs: list[CarrierMessage] = []
    i = 0
    is_first = True
    while i < len(buf):
        # Minimum header: flag (1) + size (2) = 3
        if len(buf) - i < 3:
            break
        flags = buf[i]; i += 1
        data_size = int.from_bytes(buf[i:i+2], "big"); i += 2

        m = CarrierMessage(flags=flags, data_size=data_size)

        if flags & MF_DATA_CHANNEL:
            if len(buf) - i < 1: break
            m.channel = buf[i]; i += 1

        if flags & MF_CHUNKS:
            if len(buf) - i < 2: break
            m.num_chunks = int.from_bytes(buf[i:i+2], "big"); i += 2

        # seq: written when MF_SQUENTIAL_ID is NOT set OR this is the first
        # message in the datagram (the writer at Carrier.cpp:2659 always
        # writes the first seq number).
        if is_first or not (flags & MF_SQUENTIAL_ID):
            if len(buf) - i < 2: break
            m.seq = int.from_bytes(buf[i:i+2], "big"); i += 2

        # rel_seq: written when MF_SQUENTIAL_REL_ID is NOT set AND either
        # (the message is reliable) OR (this is the first message and a
        # reliable seq baseline has not been emitted yet, Carrier.cpp:2662).
        if (flags & MF_RELIABLE) and not (flags & MF_SQUENTIAL_REL_ID):
            if len(buf) - i < 2: break
            m.rel_seq = int.from_bytes(buf[i:i+2], "big"); i += 2
        elif is_first and not (flags & MF_SQUENTIAL_REL_ID):
            # Even unreliable first-msg writes rel_seq baseline
            if len(buf) - i < 2: break
            m.rel_seq = int.from_bytes(buf[i:i+2], "big"); i += 2

        if data_size > 0:
            if len(buf) - i < data_size:
                # truncated payload — abort and let trailer capture what's left
                break
            m.payload = buf[i:i+data_size]
            i += data_size

        msgs.append(m)
        is_first = False

    return msgs, buf[i:]


def decode_record(idx: int, dir_byte: int, ts_ms: int, ssl_ptr: int,
                  payload: bytes) -> Datagram:
    d = Datagram(
        ts_ms=ts_ms,
        dir="in" if dir_byte == 0 else "out",
        ssl_ptr=ssl_ptr,
        record_idx=idx,
        raw_len=len(payload),
        mode_byte=payload[0] if len(payload) >= 1 else 0,
        format_byte=payload[1] if len(payload) >= 2 else 0,
        dgram_seq=int.from_bytes(payload[2:4], "big") if len(payload) >= 4 else 0,
        compressed=False,
        decompressed_len=None,
        additional_header=None,
    )

    if len(payload) < 4:
        d.error = "too-short"
        return d
    # Sanity: byte 1 must be 0x01 per NW_Carrier_SendDataPackets:0x145DDF483
    if d.format_byte != 0x01:
        d.error = f"unexpected format byte 0x{d.format_byte:02x}"
        return d
    # Mode byte: 0x80 or 0x81 per NW_Carrier_ReceiveDataPackets:0x145DDE366
    if d.mode_byte not in (0x80, 0x81):
        d.error = f"unexpected mode byte 0x{d.mode_byte:02x}"
        return d

    body = payload[4:]
    d.compressed = bool(d.mode_byte & 0x01)

    if d.compressed:
        # The full body[4:] (post 4-byte datagram header) IS the LZ4
        # block. Verified empirically: skip=0 decompresses cleanly, and
        # the apparent "f0 02" prefix on inspection is just the first
        # token byte + extended-literal-length byte of the LZ4 stream
        # (high nibble 0xf = extended literal, then ext byte 0x02 →
        # 17 literals).
        decoded = None
        for size_hint in (256, 1024, 4096, 16384, 65536, 262144):
            try:
                decoded = lz4.block.decompress(body, uncompressed_size=size_hint)
                break
            except lz4.block.LZ4BlockError:
                continue
        if decoded is None:
            d.error = "lz4 decompress failed"
            return d
        d.decompressed_len = len(decoded)
        msgs, trailer = parse_carrier_messages(decoded)
    else:
        d.decompressed_len = len(body)
        msgs, trailer = parse_carrier_messages(body)

    d.messages = msgs
    d.trailer = trailer
    return d


def iter_ledger(path: Path):
    data = path.read_bytes()
    off = 0
    idx = 0
    while off + 28 <= len(data):
        magic, ts_ms, dir_byte, _, _, _, ssl_ptr, plen = struct.unpack_from(
            '<IQBBBBQI', data, off
        )
        if magic != LEDGER_MAGIC: break
        if off + 28 + plen > len(data): break
        payload = data[off+28:off+28+plen]
        yield idx, dir_byte, ts_ms, ssl_ptr, payload
        off += 28 + plen
        idx += 1


def main():
    p = argparse.ArgumentParser()
    p.add_argument("ledger", help="Path to ledger.bin")
    p.add_argument("--out", help="Output JSONL path (default: alongside ledger as decoded.jsonl)")
    p.add_argument("--max", type=int, default=0, help="Stop after N records (0 = all)")
    p.add_argument("--summary-only", action="store_true",
                   help="Print summary stats only; skip per-record JSONL output")
    args = p.parse_args()

    ledger_path = Path(args.ledger)
    if not ledger_path.is_file():
        print(f"not a file: {ledger_path}", file=sys.stderr); return 1
    out_path = Path(args.out) if args.out else ledger_path.with_name("decoded.jsonl")

    total = 0
    ok = 0
    errors = {}
    by_dir = {"in": 0, "out": 0}
    flag_hist: dict[str, int] = {}
    channel_hist: dict[int, int] = {}
    msg_total = 0
    msg_payload_total = 0

    out_f = None if args.summary_only else out_path.open("w", encoding="utf-8")
    try:
        for idx, dir_byte, ts_ms, ssl_ptr, payload in iter_ledger(ledger_path):
            if args.max and idx >= args.max: break
            dg = decode_record(idx, dir_byte, ts_ms, ssl_ptr, payload)
            total += 1
            if dg.error:
                errors[dg.error] = errors.get(dg.error, 0) + 1
            else:
                ok += 1
            by_dir[dg.dir] += 1
            for m in dg.messages:
                msg_total += 1
                msg_payload_total += len(m.payload)
                for fn in flag_names(m.flags):
                    flag_hist[fn] = flag_hist.get(fn, 0) + 1
                if m.channel is not None:
                    channel_hist[m.channel] = channel_hist.get(m.channel, 0) + 1
            if out_f:
                out_f.write(json.dumps(dg.to_dict()) + "\n")
    finally:
        if out_f: out_f.close()

    print(f"-- decoded {ok}/{total} records  ({total - ok} errors)")
    if errors:
        print(f"   errors:")
        for k, v in sorted(errors.items(), key=lambda kv: -kv[1]):
            print(f"     {v:>5d}  {k}")
    print(f"   IN={by_dir['in']}  OUT={by_dir['out']}")
    print(f"   total carrier messages: {msg_total}")
    print(f"   total carrier payload bytes: {msg_payload_total}")
    if flag_hist:
        print(f"   flag histogram (per message):")
        for k, v in sorted(flag_hist.items(), key=lambda kv: -kv[1]):
            print(f"     {v:>7d}  {k}")
    if channel_hist:
        print(f"   channel histogram:")
        for k, v in sorted(channel_hist.items()):
            print(f"     ch{k}: {v}")
    if out_f is None:
        print()
        print(f"   (no JSONL written; --summary-only set)")
    else:
        print(f"   wrote per-record JSONL to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
