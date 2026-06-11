// Shared Frida agent helpers for NewWorld.exe instrumentation. Loaded via
// string-concatenation by _runner.py before every script. No real module
// system because Frida's quickjs/v8 runtimes don't import without
// frida-compile, and we keep the toolchain minimal.
//
// All addresses we hold come from the IDA database at image base
// 0x140000000. Runtime ASLR makes the actual base different, so every
// address goes through nwRva() before use.

const NW = {
    BASE_IDA: ptr("0x140000000"),
    MODULE_NAME: "NewWorld.exe",
    module: null,
    slide: null, // ptr(runtimeBase - 0x140000000)
};

// Resolve the loaded NewWorld.exe and compute the ASLR delta. Idempotent.
// Emits a "module_resolved" event so the Python wrapper learns the base
// once and can rebase any IDA address itself.
function nwInit() {
    if (NW.module !== null) return NW.module;
    const m = Process.findModuleByName(NW.MODULE_NAME);
    if (m === null) {
        nwSend("error", { stage: "nwInit", msg: "module not found",
                          name: NW.MODULE_NAME });
        throw new Error("NewWorld.exe not loaded yet");
    }
    NW.module = m;
    NW.slide = m.base.sub(NW.BASE_IDA);
    nwSend("module_resolved", {
        name:  m.name,
        base:  m.base.toString(),
        size:  m.size,
        slide: NW.slide.toString(),
        // The IDA base is fixed; phase-2 will hardcode it to rebase
        // its own constants. Surfacing it explicitly avoids guesswork.
        ida_base: NW.BASE_IDA.toString(),
    });
    return m;
}

// IDA-VA -> runtime pointer. Accepts both numeric (literal) and string
// inputs. Asserts nwInit() ran. The arithmetic is base.add(va - BASE_IDA),
// which works regardless of where Windows loaded the module.
function nwRva(va) {
    if (NW.module === null) {
        throw new Error("nwRva called before nwInit");
    }
    const vap = (typeof va === "number" || typeof va === "string") ? ptr(va) : va;
    return NW.module.base.add(vap.sub(NW.BASE_IDA));
}

// Stable event shape: every send() carries a timestamp + thread id. Phase
// 2 will extend payloads but never break the envelope.
function nwSend(type, payload) {
    const msg = Object.assign({
        ts_ms: Date.now(),
        tid:   Process.getCurrentThreadId(),
        type:  type,
    }, payload || {});
    send(msg);
}

// Light wrapper for trace messages so callers don't reach for send()
// directly. Keeps the schema consistent.
function nwLog(msg) {
    nwSend("trace", { msg: msg });
}

// Deterministic 16-byte hex dump for sanity-checking we're at the right
// address after rebasing. We don't want Frida's variable hexdump() format
// for that; we want a flat space-separated byte string the wrapper can
// regex-match against expected MSVC CRT signatures.
function nwHexdump(addr, n) {
    const bytes = new Uint8Array(addr.readByteArray(n));
    const parts = [];
    for (let i = 0; i < bytes.length; i++) {
        parts.push(bytes[i].toString(16).padStart(2, "0").toUpperCase());
    }
    return parts.join(" ");
}

// Attach Interceptor and auto-detach after the first hit. Used for entry
// hooks where we only care about "did we get here once". Sends both
// hook_installed and hook_fired events so the wrapper knows the lifecycle.
//
// `hook_installed` carries first16_at_install: the 16 bytes at the target
// captured *before* Frida's Interceptor patches them. Without this the
// runtime read would show Frida's own jmp trampoline, masking the real
// prologue bytes. Callers use these for sanity-checking they hooked the
// right function.
function nwAttachOnce(va, name, onEnter) {
    const runtimeAddr = nwRva(va);
    let first16AtInstall = "";
    try {
        first16AtInstall = nwHexdump(runtimeAddr, 16);
    } catch (e) {
        first16AtInstall = "<unreadable: " + e.message + ">";
    }
    nwSend("hook_installed", {
        name: name,
        rva:  ptr(va).sub(NW.BASE_IDA).toString(),
        addr: runtimeAddr.toString(),
        first16_at_install: first16AtInstall,
    });
    let listener = null;
    listener = Interceptor.attach(runtimeAddr, {
        onEnter: function (args) {
            try {
                onEnter.call(this, args);
            } catch (e) {
                nwSend("error", { stage: "onEnter:" + name,
                                  msg: String(e), stack: e.stack });
            }
            if (listener !== null) {
                listener.detach();
                listener = null;
            }
        },
    });
    return listener;
}
