// nw_https_tap.js
//
// Tap NewWorld.exe's WinHTTP traffic for the auth bootstrap phase.
//
// Why WinHTTP (not OpenSSL)? Per analysis.md, NewWorld uses two transport
// stacks: WinHTTP + SChannel for the HTTPS auth bootstrap (channel config,
// tokenservice, credentials/omni, login_queue, getlogininfo, …) and
// statically-linked OpenSSL for the DTLS gameplay path. winhttp.dll is a
// system DLL with stable exports, so hooks are dynamic via the loaded
// module instance — no signature hunting required.
//
// What we capture per request:
//   • host:port             (WinHttpConnect)
//   • verb + path           (WinHttpOpenRequest)
//   • request headers+body  (WinHttpSendRequest + WinHttpWriteData)
//   • response headers      (WinHttpQueryHeaders / RAW_HEADERS_CRLF)
//   • response body chunks  (WinHttpReadData {sync|async}, WinHttpReadDataEx)
//
// Diagnostics (DEBUG_VERBOSE):
//   • winhttp_read_data       — unconditional log of every ReadData call
//   • winhttp_read_data_ex    — same for ReadDataEx (Win 10+)
//   • winhttp_status_event    — every status callback event (any kind)
//   This is on by default while we hunt down the seq=1 channel_config
//   response-body miss. Flip DEBUG_VERBOSE off once that's understood.
//
// Primary target: POST tokenservice.amazongames.com/games/new-world/tokens
// to unblock the OmniSDK 203 wall (parser at IDA 0x1479C9F00 ==
// OmniSDK_AgsFedAccTokenServGateway_CreateToken_ParseResponse).

const DEBUG_VERBOSE = true;

// WINHTTP_CALLBACK_STATUS_* (winhttp.h). The dwInternetStatus value
// passed to a WINHTTP_STATUS_CALLBACK identifies the event kind.
//
// FIXED 2026-05-19: earlier values were wrong — READ_COMPLETE through
// SENDREQUEST_COMPLETE were each shifted right by one bit, so the async
// response-body capture path silently missed every READ_COMPLETE event
// (we compared against 0x00040000 which is actually DATA_AVAILABLE).
// Verified against the live NW.exe trace: status=0x80000 carries
// info_len equal to the response body size, matching the canonical
// 0x00080000 value of READ_COMPLETE.
const WINHTTP_CALLBACK_STATUS_RESOLVING_NAME        = 0x00000001;
const WINHTTP_CALLBACK_STATUS_NAME_RESOLVED         = 0x00000002;
const WINHTTP_CALLBACK_STATUS_CONNECTING_TO_SERVER  = 0x00000004;
const WINHTTP_CALLBACK_STATUS_CONNECTED_TO_SERVER   = 0x00000008;
const WINHTTP_CALLBACK_STATUS_SENDING_REQUEST       = 0x00000010;
const WINHTTP_CALLBACK_STATUS_REQUEST_SENT          = 0x00000020;
const WINHTTP_CALLBACK_STATUS_RECEIVING_RESPONSE    = 0x00000040;
const WINHTTP_CALLBACK_STATUS_RESPONSE_RECEIVED     = 0x00000080;
const WINHTTP_CALLBACK_STATUS_CLOSING_CONNECTION    = 0x00000100;
const WINHTTP_CALLBACK_STATUS_CONNECTION_CLOSED     = 0x00000200;
const WINHTTP_CALLBACK_STATUS_HANDLE_CREATED        = 0x00000800;
const WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING        = 0x00001000;
const WINHTTP_CALLBACK_STATUS_DETECTING_PROXY       = 0x00001000; // same value
const WINHTTP_CALLBACK_STATUS_REDIRECT              = 0x00004000;
const WINHTTP_CALLBACK_STATUS_INTERMEDIATE_RESPONSE = 0x00008000;
const WINHTTP_CALLBACK_STATUS_SECURE_FAILURE        = 0x00010000;
const WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE     = 0x00020000;
const WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE        = 0x00040000;
const WINHTTP_CALLBACK_STATUS_READ_COMPLETE         = 0x00080000;
const WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE        = 0x00100000;
const WINHTTP_CALLBACK_STATUS_REQUEST_ERROR         = 0x00200000;
const WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE  = 0x00400000;

// WinHTTP query attribute mask. dwInfoLevel passed to WinHttpQueryHeaders
// can be ORed with WINHTTP_QUERY_FLAG_* bits in the high half. The actual
// attribute lives in the low byte; defined attribute IDs go up to ~78
// (WINHTTP_QUERY_LAST). Use a 16-bit mask to be safe against future
// additions — the old `& 0x3F` was tight against 78 and would have
// false-matched 22 against attribute 86 (none exists today, but cheap to
// fix).
const WINHTTP_QUERY_ATTR_MASK        = 0x0000FFFF;
const WINHTTP_QUERY_RAW_HEADERS_CRLF = 22;

// Body cap per chunk — auth responses are O(KB); huge transfers (DDS
// images, etc.) come in chunks WinHTTP itself sizes (commonly ≤8 KB
// per ReadData), so this caps each capture event, not the whole body.
const BODY_CAP_BYTES = 256 * 1024;

const connectMap = new Map(); // hConnect -> { host, port }
const requestMap = new Map(); // hRequest -> per-request state

let MOD_WINHTTP      = null;  // resolved when winhttp.dll loads
let winhttpInstalled = false; // guard against double-install

// Anchor for NativeCallback wrappers so the JS GC doesn't free them
// while WinHTTP holds a function pointer. Grows once per
// WinHttpSetStatusCallback call; small (each wrapper is a few hundred
// bytes), and we never know when WinHTTP is done with a callback so we
// can't free them safely. Acceptable for capture sessions of any
// realistic length.
const cbWrappers = [];
const wrapperSet = new Set();  // wrapperPtr.toString() — for double-wrap detection

// Re-entry guard: WinHttpReadDataEx internally calls WinHttpReadData,
// so naive hooking double-captures every chunk (once at the outer Ex
// frame, once at the inner ReadData frame). We track per-thread which
// frame the current thread is in so the inner ReadData hook can skip.
const tidsInReadDataEx = new Set(); // Process.getCurrentThreadId() ints

// Secondary dedup: NW invokes Read and ReadDataEx sequentially in the
// same ms with identical data for content-CDN binary downloads, so we
// get two emits per chunk. The dup signal is specific: DIFFERENT via
// tag + same fingerprint + within 10ms. Matching via tag with matching
// fingerprint is NOT a dup — it's a chunk-aligned run of identical
// bytes (e.g. zero padding in a DDS file) crossing a chunk boundary.
const DEDUP_WINDOW_MS = 10;
function emitChunkDedup(ent, chunkPayload, chunk) {
    const via = chunkPayload.via || '';
    const fp = (chunk.text && chunk.text.length >= 16)
                  ? chunk.text.substring(0, 16)
              : (chunk.hex && chunk.hex.length >= 32)
                  ? chunk.hex.substring(0, 32)
              : (chunk.text || chunk.hex || '');
    const now = Date.now();
    if (fp && via && via !== ent._lastChunkVia
            && fp === ent._lastChunkFp
            && (now - (ent._lastChunkTs || 0)) < DEDUP_WINDOW_MS) {
        return false; // paired duplicate
    }
    ent._lastChunkVia = via;
    ent._lastChunkFp  = fp;
    ent._lastChunkTs  = now;
    ent.respBody.push(chunk);
    nwSend('http_response_body_chunk', chunkPayload);
    return true;
}


// ─── helpers ──────────────────────────────────────────────────────────────

function winhttp(name) {
    if (MOD_WINHTTP === null) return null;
    // mod.findExportByName returns null on miss; mod.getExportByName throws.
    // Some WinHTTP exports are only on newer Windows builds (ReadDataEx,
    // WebSocket*), so we tolerate misses with a trace event.
    const a = MOD_WINHTTP.findExportByName(name);
    if (a === null) {
        nwSend('trace', { msg: 'winhttp export missing: ' + name });
    }
    return a;
}

function readWideStr(p, lenChars) {
    if (p === null || p.isNull()) return '';
    if (lenChars === -1 || lenChars === 0xFFFFFFFF || lenChars === undefined) {
        return p.readUtf16String();
    }
    if (lenChars <= 0) return '';
    return p.readUtf16String(lenChars);
}

// Read a contiguous byte buffer of size n bytes. Try UTF-8 first (the
// JSON / text path) and fall back to a binary-safe hex dump. Both paths
// share BODY_CAP_BYTES so binary responses (DDS images, encrypted blobs)
// aren't artificially shorter than text ones. Returns {kind, text, hex,
// total, captured} — `total` is what WinHTTP reported, `captured` is what
// we actually serialized (== total unless we hit BODY_CAP_BYTES).
function readBodyChunk(p, n) {
    if (n <= 0 || p.isNull()) return { kind: 'empty', text: '', hex: '' };
    const limit = Math.min(n, BODY_CAP_BYTES);
    try {
        const txt = p.readUtf8String(limit);
        if (txt !== null) {
            return { kind: 'utf8', text: txt, hex: '', total: n, captured: limit };
        }
    } catch (_) {}
    const bytes = new Uint8Array(p.readByteArray(limit));
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return { kind: 'hex', text: '', hex: hex, total: n, captured: bytes.length };
}


// ─── individual hooks ────────────────────────────────────────────────────

function hookWinHttpConnect() {
    const a = winhttp('WinHttpConnect');
    if (a === null) return;
    Interceptor.attach(a, {
        onEnter: function (args) {
            this._host = args[1].isNull() ? '' : args[1].readUtf16String();
            // INTERNET_PORT is USHORT (16 bit); upper bits of the register
            // are not meaningful — mask to be explicit.
            this._port = args[2].toInt32() & 0xFFFF;
        },
        onLeave: function (retval) {
            if (!retval.isNull()) {
                connectMap.set(retval.toString(), {
                    host: this._host, port: this._port,
                });
            }
        },
    });
}

function hookWinHttpOpenRequest() {
    const a = winhttp('WinHttpOpenRequest');
    if (a === null) return;
    Interceptor.attach(a, {
        onEnter: function (args) {
            this._hConnect = args[0].toString();
            this._verb = args[1].isNull() ? 'GET' : args[1].readUtf16String();
            this._path = args[2].isNull() ? '/'   : args[2].readUtf16String();
        },
        onLeave: function (retval) {
            if (retval.isNull()) return;
            const parent = connectMap.get(this._hConnect) || { host: '?', port: 0 };
            requestMap.set(retval.toString(), {
                host: parent.host, port: parent.port,
                verb: this._verb, path: this._path,
                reqBody: [], respBody: [], respHeaders: '',
            });
        },
    });
}

function hookWinHttpSendRequest() {
    const a = winhttp('WinHttpSendRequest');
    if (a === null) return;
    Interceptor.attach(a, {
        onEnter: function (args) {
            const h = args[0].toString();
            const ent = requestMap.get(h);
            if (!ent) return;
            const headersLen = args[2].toInt32();
            const headers = args[1].isNull() ? ''
                : readWideStr(args[1], headersLen === -1 ? -1 : headersLen);
            const bodyLen  = args[4].toInt32() | 0;
            const totalLen = args[5].toInt32() | 0;
            if (bodyLen > 0 && !args[3].isNull()) {
                ent.reqBody.push(readBodyChunk(args[3], bodyLen));
            }
            nwSend('http_request', {
                h, host: ent.host, port: ent.port,
                verb: ent.verb, path: ent.path,
                headers: headers,
                initialBodyLen: bodyLen, totalContentLen: totalLen,
            });
        },
    });
}

function hookWinHttpWriteData() {
    const a = winhttp('WinHttpWriteData');
    if (a === null) return;
    Interceptor.attach(a, {
        onEnter: function (args) {
            const h = args[0].toString();
            const ent = requestMap.get(h);
            if (!ent) return;
            const n = args[2].toInt32() | 0;
            const chunk = readBodyChunk(args[1], n);
            ent.reqBody.push(chunk);
            nwSend('http_request_body_chunk', {
                h, host: ent.host, path: ent.path, len: n, ...chunk,
            });
        },
    });
}

function hookWinHttpReceiveResponse() {
    // Emit the joined request body once the request is fully sent.
    // For pure-GETs (no reqBody) we skip — there's nothing to flush.
    const a = winhttp('WinHttpReceiveResponse');
    if (a === null) return;
    Interceptor.attach(a, {
        onEnter: function (args) {
            const h = args[0].toString();
            const ent = requestMap.get(h);
            if (!ent || ent.reqBody.length === 0) return;
            // Mixed-kind chunks are theoretically possible (text then hex)
            // but never happen in practice for our auth POSTs. If they do
            // appear, the joined string would interleave UTF-8 text with
            // hex characters — flag that in the event so the extractor can
            // decide to fall back to per-chunk reassembly.
            const kinds = new Set(ent.reqBody.map(c => c.kind));
            const mixed = kinds.size > 1;
            const joined = ent.reqBody.map(c => c.text || c.hex || '').join('');
            nwSend('http_request_body', {
                h, host: ent.host, path: ent.path,
                kind: mixed ? 'mixed' : ent.reqBody[0].kind,
                body: joined,
                totalBytes: ent.reqBody.reduce((s, c) => s + (c.total || 0), 0),
            });
        },
    });
}

function hookWinHttpQueryHeaders() {
    const a = winhttp('WinHttpQueryHeaders');
    if (a === null) return;
    Interceptor.attach(a, {
        onEnter: function (args) {
            this._h     = args[0].toString();
            this._level = args[1].toInt32();
            this._buf   = args[3];
            this._lenP  = args[4];
        },
        onLeave: function (retval) {
            if (retval.toInt32() === 0) return;                              // call failed
            if ((this._level & WINHTTP_QUERY_ATTR_MASK) !== WINHTTP_QUERY_RAW_HEADERS_CRLF) return;
            if (this._buf.isNull() || this._lenP.isNull()) return;
            const bytesNeeded = this._lenP.readU32();
            if (bytesNeeded === 0) return;
            const headers = readWideStr(this._buf, bytesNeeded / 2);         // bytes → wchars
            const ent = requestMap.get(this._h);
            if (ent) ent.respHeaders = headers;
            nwSend('http_response_headers', {
                h: this._h,
                host: ent ? ent.host : '?',
                path: ent ? ent.path : '?',
                headers: headers,
            });
        },
    });
}

// WinHttpReadData: BOOL WinHttpReadData(hReq, buf, dwToRead, lpdwRead)
//   SYNC  (lpdwRead != NULL): bytes filled on return; BOOL non-zero == success
//   ASYNC (lpdwRead == NULL): callback path via status callback (READ_COMPLETE)
function hookWinHttpReadData() {
    const a = winhttp('WinHttpReadData');
    if (a === null) return;
    Interceptor.attach(a, {
        onEnter: function (args) {
            this.h         = args[0].toString();
            this.buf       = args[1];
            this.requested = args[2].toInt32() | 0;
            this.lenOutPtr = args[3];
            // If we're inside a WinHttpReadDataEx call on this same
            // thread, the Ex hook owns the capture. Skip here.
            this.skipDueToEx = tidsInReadDataEx.has(Process.getCurrentThreadId());
            if (DEBUG_VERBOSE && !this.skipDueToEx) {
                nwSend('winhttp_read_data', {
                    h: this.h,
                    bytes_requested: this.requested,
                    async: this.lenOutPtr.isNull(),
                    has_request_entry: requestMap.has(this.h),
                });
            }
        },
        onLeave: function (retval) {
            if (this.skipDueToEx) return;                // outer Ex frame handles emit
            if (retval.toInt32() === 0) return;          // BOOL failure
            if (this.lenOutPtr.isNull()) return;         // async: bytes via callback
            const n = this.lenOutPtr.readU32();
            if (n === 0) return;                         // EOF
            const ent = requestMap.get(this.h);
            if (!ent) return;
            const chunk = readBodyChunk(this.buf, n);
            emitChunkDedup(ent, {
                h: this.h, host: ent.host, path: ent.path,
                len: n, ...chunk, via: 'sync_read',
            }, chunk);
        },
    });
}

// WinHttpReadDataEx (Win 10 1903+):
//   DWORD WinHttpReadDataEx(hReq, buf, dwToRead, lpdwRead,
//                           ULONGLONG ullFlags, DWORD cbProp, LPVOID pvProp)
// Return is DWORD: 0 = ERROR_SUCCESS, !=0 = Win32 error code (inverted vs
// WinHttpReadData's BOOL semantics — be careful).
function hookWinHttpReadDataEx() {
    const a = winhttp('WinHttpReadDataEx');
    if (a === null) return;
    Interceptor.attach(a, {
        onEnter: function (args) {
            this.h         = args[0].toString();
            this.buf       = args[1];
            this.requested = args[2].toInt32() | 0;
            this.lenOutPtr = args[3];
            this.tid       = Process.getCurrentThreadId();
            // Mark this thread as in-Ex so the inner ReadData hook skips.
            tidsInReadDataEx.add(this.tid);
            if (DEBUG_VERBOSE) {
                nwSend('winhttp_read_data_ex', {
                    h: this.h,
                    bytes_requested: this.requested,
                    async: this.lenOutPtr.isNull(),
                    has_request_entry: requestMap.has(this.h),
                });
            }
        },
        onLeave: function (retval) {
            tidsInReadDataEx.delete(this.tid);
            // ReadDataEx success == 0 (DWORD error). Capture only on success.
            if (retval.toInt32() !== 0) return;
            if (this.lenOutPtr.isNull()) return;
            const n = this.lenOutPtr.readU32();
            if (n === 0) return;
            const ent = requestMap.get(this.h);
            if (!ent) return;
            const chunk = readBodyChunk(this.buf, n);
            emitChunkDedup(ent, {
                h: this.h, host: ent.host, path: ent.path,
                len: n, ...chunk, via: 'sync_read_ex',
            }, chunk);
        },
    });
}

// Hook the app-installed WINHTTP_STATUS_CALLBACK to observe ALL status
// events. The original purpose is to intercept READ_COMPLETE for async
// response-body capture; the DEBUG_VERBOSE log surfaces every status event
// regardless so we can see what WinHTTP actually fires on a per-handle
// basis (helps diagnose handles where we capture headers but no body).
function hookWinHttpSetStatusCallback() {
    const a = winhttp('WinHttpSetStatusCallback');
    if (a === null) return;
    const INVALID_CB = ptr('-1');
    Interceptor.attach(a, {
        onEnter: function (args) {
            const origCb = args[1];
            const cbStr  = origCb.toString();
            const cleared = origCb.isNull() || origCb.equals(INVALID_CB);
            nwSend('winhttp_set_status_callback', {
                h: args[0].toString(),
                cb: cbStr,
                mask: args[2].toInt32() >>> 0,
                cleared: cleared,
            });
            if (cleared) return;
            // Double-wrap guard: if origCb is itself one of our wrappers
            // (NW set the callback then changed it then changed it back),
            // skip — wrapping the wrapper would double-emit every event.
            if (wrapperSet.has(cbStr)) return;

            const fwd = new NativeFunction(origCb, 'void',
                ['pointer', 'pointer', 'uint32', 'pointer', 'uint32'], 'win64');
            const wrapper = new NativeCallback(function (hInternet, ctx, status, info, infoLen) {
                try {
                    const hStr = hInternet.toString();
                    if (DEBUG_VERBOSE) {
                        nwSend('winhttp_status_event', {
                            h: hStr,
                            status: status >>> 0,
                            has_info: !info.isNull(),
                            info_len: infoLen >>> 0,
                            has_request_entry: requestMap.has(hStr),
                        });
                    }
                    if (status === WINHTTP_CALLBACK_STATUS_READ_COMPLETE
                        && !info.isNull() && infoLen > 0) {
                        const ent = requestMap.get(hStr);
                        if (ent) {
                            const chunk = readBodyChunk(info, infoLen);
                            emitChunkDedup(ent, {
                                h: hStr, host: ent.host, path: ent.path,
                                len: infoLen, ...chunk, via: 'callback',
                            }, chunk);
                        }
                    }
                } catch (e) {
                    nwSend('error', {
                        stage: 'cb_status_event',
                        msg: String(e), stack: e.stack,
                    });
                }
                fwd(hInternet, ctx, status, info, infoLen);
            }, 'void', ['pointer', 'pointer', 'uint32', 'pointer', 'uint32'], 'win64');
            cbWrappers.push(wrapper);
            wrapperSet.add(wrapper.toString());
            args[1] = wrapper;
        },
    });
}

function hookWinHttpCloseHandle() {
    const a = winhttp('WinHttpCloseHandle');
    if (a === null) return;
    Interceptor.attach(a, {
        onEnter: function (args) {
            const h = args[0].toString();
            const ent = requestMap.get(h);
            if (ent) {
                nwSend('http_request_closed', {
                    h, host: ent.host, path: ent.path,
                    respChunks: ent.respBody.length,
                });
                requestMap.delete(h);
            } else if (connectMap.has(h)) {
                connectMap.delete(h);
            }
        },
    });
}


// ─── install / load orchestration ─────────────────────────────────────────

// winhttp.dll is NOT statically imported by NewWorld.exe (IDA shows it
// as a string literal at 0x1484D7A08 + GetProcAddress-resolved entry
// points), so we have to wait for LoadLibrary{,Ex}{W,A}/LdrLoadDll
// before our exports resolve. install() is called pre-resume, so by the
// time NW executes its first instruction the load watcher is armed.
function installWinHttpHooks() {
    if (winhttpInstalled) return;
    const m = Process.findModuleByName('winhttp.dll');
    if (m === null) return;
    MOD_WINHTTP = m;
    nwSend('winhttp_loaded', { base: m.base.toString(), size: m.size });
    try {
        // Install SetStatusCallback FIRST so any callback registered
        // during this same install batch (rare but possible if NW races
        // its WinHTTP init across threads) is intercepted from the start.
        hookWinHttpSetStatusCallback();
        hookWinHttpConnect();
        hookWinHttpOpenRequest();
        hookWinHttpSendRequest();
        hookWinHttpWriteData();
        hookWinHttpReceiveResponse();
        hookWinHttpQueryHeaders();
        hookWinHttpReadData();
        hookWinHttpReadDataEx();        // Win 10 1903+; harmless no-op otherwise
        hookWinHttpCloseHandle();
    } catch (e) {
        MOD_WINHTTP = null;
        nwSend('error', {
            stage: 'installWinHttpHooks',
            msg: String(e), stack: e.stack,
        });
        return;
    }
    winhttpInstalled = true;
    nwSend('winhttp_hooks_armed', { hooks: 10 });
}

function watchForWinHttpLoad() {
    const k32 = Process.findModuleByName('kernel32.dll');
    if (k32 !== null) {
        const loaders = ['LoadLibraryW', 'LoadLibraryExW', 'LoadLibraryA', 'LoadLibraryExA'];
        for (const name of loaders) {
            const addr = k32.findExportByName(name);
            if (addr === null) continue;
            Interceptor.attach(addr, {
                onLeave: function () { installWinHttpHooks(); },
            });
        }
    }
    // LdrLoadDll is what the loader uses internally for ALL DLL loads,
    // including delay-imports and dependent loads that don't go through
    // kernel32!LoadLibraryW. Catching it closes the small window where
    // winhttp.dll could load via a path that bypasses kernel32.
    const ntdll = Process.findModuleByName('ntdll.dll');
    if (ntdll !== null) {
        const ldrLoadDll = ntdll.findExportByName('LdrLoadDll');
        if (ldrLoadDll !== null) {
            Interceptor.attach(ldrLoadDll, {
                onLeave: function () { installWinHttpHooks(); },
            });
        }
    }
}

rpc.exports.install = function () {
    nwInit();
    watchForWinHttpLoad();
    installWinHttpHooks();  // in case winhttp.dll is already loaded (attach mode)
    nwSend('install_complete', {
        state: winhttpInstalled ? 'winhttp_already_loaded' : 'deferred_pending_LoadLibrary',
        debug_verbose: DEBUG_VERBOSE,
    });
};
