// _dtls_ledger.js -- always-on DTLS plaintext + keylog capture.
//
// This module self-installs SSL_read / SSL_write / nss_keylog_int hooks
// at script-load time so every Frida session against NewWorld.exe gets
// a ledger.bin + keylog.txt for free. _runner.py auto-prepends this
// file after _common.js, so probe scripts no longer need to wire DTLS
// hooks themselves.
//
// Guard:
//   NW._dtls_ledger_armed is set to true after first install, so a
//   second include (e.g. nw_dtls_tap.js running in legacy mode) is a
//   no-op rather than a double-hook.
//
// Wire/ledger format identical to the original nw_dtls_tap.js:
//
//   Binary ledger record format (little-endian):
//     u32 magic        = 0x4C44574E  ('NWDL')
//     u64 ts_ms        -- Date.now() at the hook site
//     u8  dir          -- 0 = read (incoming), 1 = write (outgoing)
//     u8  reserved[3]
//     u64 ssl_ptr      -- SSL* (correlates records to the same session)
//     u32 payload_len
//     u8  payload[payload_len]
//
// Each send({type:'dtls_ledger'}, ArrayBuffer) is a concatenation of one
// or more records. The Python side appends the buffer verbatim to
// captures/<session>/dtls/ledger.bin.

(function () {
    if (typeof NW === 'undefined') {
        throw new Error('_dtls_ledger.js loaded before _common.js');
    }
    if (NW._dtls_ledger_armed) return;
    NW._dtls_ledger_armed = true;

    const VAS = {
        SSL_read:    '0x1478F17E0',
        SSL_write:   '0x1478F1E20',
        nss_keylog:  '0x1478F23A0',
    };

    const REC_MAGIC       = 0x4C44574E;
    const REC_HEADER      = 28;
    const FLUSH_MS        = 25;
    const FLUSH_THRESHOLD = 32 * 1024;
    const STAGING_INITIAL = 0x40000; // 256 KiB initial

    let stagingBuf  = new ArrayBuffer(STAGING_INITIAL);
    let stagingView = new DataView(stagingBuf);
    let stagingPos  = 0;
    let stats       = { records: 0, bytes: 0, flushes: 0, keylog: 0 };

    function ensureCapacity(extra) {
        if (stagingPos + extra <= stagingBuf.byteLength) return;
        let newSize = stagingBuf.byteLength;
        while (stagingPos + extra > newSize) newSize *= 2;
        const newBuf = new ArrayBuffer(newSize);
        new Uint8Array(newBuf).set(new Uint8Array(stagingBuf, 0, stagingPos));
        stagingBuf  = newBuf;
        stagingView = new DataView(stagingBuf);
    }

    function appendRecord(dir, sslPtr, bytes) {
        const len = bytes.byteLength;
        ensureCapacity(REC_HEADER + len);
        stagingView.setUint32(stagingPos + 0, REC_MAGIC, true);
        stagingView.setBigUint64(stagingPos + 4, BigInt(Date.now()), true);
        // setUint32 at +12 writes [dir, 0, 0, 0] little-endian -- atomic
        // dir + zero-pad. Don't switch to setUint8(+12, dir): the buffer
        // is recycled across batches and positions 13..15 of a non-zeroth
        // record can sit inside a prior batch's payload (e.g. a 1..6-byte
        // keepalive packet), so a stale reserved[3] would leak previous-
        // payload bytes into the decoded header.
        stagingView.setUint32(stagingPos + 12, dir, true);
        stagingView.setBigUint64(stagingPos + 16,
            BigInt(sslPtr.toString()), true);
        stagingView.setUint32(stagingPos + 24, len, true);
        new Uint8Array(stagingBuf, stagingPos + REC_HEADER, len)
            .set(new Uint8Array(bytes));
        stagingPos += REC_HEADER + len;
        stats.records += 1;
        stats.bytes   += REC_HEADER + len;
        if (stagingPos >= FLUSH_THRESHOLD) flushNow();
    }

    function flushNow() {
        if (stagingPos === 0) return;
        const out = stagingBuf.slice(0, stagingPos);
        send({ type: 'dtls_ledger' }, out);
        stagingPos = 0;
        stats.flushes += 1;
    }

    function bytesToHex(bytes) {
        const arr = new Uint8Array(bytes);
        let s = '';
        for (let i = 0; i < arr.length; i++) {
            s += arr[i].toString(16).padStart(2, '0');
        }
        return s;
    }

    function hookSslRead(addr) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.ssl = args[0];
                this.buf = args[1];
            },
            onLeave: function (retval) {
                const n = retval.toInt32();
                if (n <= 0) return;
                try {
                    const bytes = this.buf.readByteArray(n);
                    appendRecord(0, this.ssl, bytes);
                } catch (e) {
                    nwSend('error', { stage: 'SSL_read', msg: String(e) });
                }
            },
        });
    }

    function hookSslWrite(addr) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                const n = args[2].toInt32();
                if (n <= 0) return;
                try {
                    const bytes = args[1].readByteArray(n);
                    appendRecord(1, args[0], bytes);
                } catch (e) {
                    nwSend('error', { stage: 'SSL_write', msg: String(e) });
                }
            },
        });
    }

    function hookKeylog(addr) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    const label  = args[0].readUtf8String();
                    const crLen  = args[3].toInt32();
                    const secLen = args[5].toInt32();
                    if (crLen <= 0 || secLen <= 0) return;
                    const cr  = args[2].readByteArray(crLen);
                    const sec = args[4].readByteArray(secLen);
                    nwSend('dtls_keylog', {
                        label:   label,
                        cr_hex:  bytesToHex(cr),
                        sec_hex: bytesToHex(sec),
                    });
                    stats.keylog += 1;
                } catch (e) {
                    nwSend('error', { stage: 'nss_keylog', msg: String(e) });
                }
            },
        });
    }

    // Arm immediately at script load (suspended process; module already
    // mapped). nwInit() is idempotent so it's safe to call here even if
    // the user script calls it again later.
    nwInit();
    const aRead   = nwRva(VAS.SSL_read);
    const aWrite  = nwRva(VAS.SSL_write);
    const aKeylog = nwRva(VAS.nss_keylog);
    nwSend('dtls_hook_installed', {
        ssl_read:           aRead.toString(),
        ssl_write:          aWrite.toString(),
        nss_keylog:         aKeylog.toString(),
        first16_ssl_read:   nwHexdump(aRead, 16),
        first16_ssl_write:  nwHexdump(aWrite, 16),
        first16_nss_keylog: nwHexdump(aKeylog, 16),
    });
    hookSslRead(aRead);
    hookSslWrite(aWrite);
    hookKeylog(aKeylog);
    setInterval(flushNow, FLUSH_MS);

    // Expose flush + stats globally so runners can read them at teardown
    // without rpc.exports clash. (rpc.exports is owned by the user script.)
    NW._dtls_ledger_flush = flushNow;
    NW._dtls_ledger_stats = function () { return stats; };

    nwSend('dtls_ready', {
        flush_ms:        FLUSH_MS,
        flush_threshold: FLUSH_THRESHOLD,
        armed_at:        'script_load_top_level',
    });
})();
