# PS5 WebKit Security Research — PoC Suite

## Overview

Targeted security research against Sony's WebKit port (WebKit-1200) for PlayStation 5.
Focus: memory-safety bugs (OOB, UAF, integer overflow) in PlayStation-specific code
and Sony's custom backend libraries reachable from web content.

**GitHub Pages:** https://ozrviju.github.io/ps5-webkit-poc/

## Tools

### 1. `mse-fuzzer.html` — Media Source Extensions Fuzzer ★ PRIORITY #1
**Target:** `mediaplayer::PSSourceBufferBackend::append()` (Sony's closed-source media demuxer)
**Attack path:** Web page → `SourceBuffer.appendBuffer()` → `SourceBufferPrivatePlayStation::appendInternal()` → Sony backend
**How to use:**
1. Open on PS5 browser via GitHub Pages or local server
2. Click "Fuzz MP4/H.264" (or other codec buttons)
3. Monitor klog for SIGSEGV/SIGBUS/page faults
4. Each iteration sends a mutated MP4/WebM container to the demuxer

**Mutation strategies:**
- Box size corruption (integer overflow in size calculations)
- Truncation at random offsets
- Bit-flip mutation
- Large count fields (array allocation overflow)
- Duplicate/overlap structures
- Zero-fill (null deref / div-by-zero)
- Box type swapping (state machine confusion)
- Dimension overflow (width×height×bpp integer overflow)

### 2. `eme-cdm-fuzzer.html` — EME/CDM Fuzzer ★ PRIORITY #2
**Target:** `mediaplayer::PSCDMSessionBackend` (Sony's closed-source DRM backend)
**Attack path:** Web page → `MediaKeySession.generateRequest()` → `CDMInstanceSessionPlayStation::requestLicense()` → Sony backend
**How to use:**
1. Open on PS5 browser
2. Select fuzzing mode (CENC/KeyIDs/WebM/All)
3. Monitor klog for crashes in the CDM backend
4. Also tries garbage license responses via `session.update()`

**Mutation strategies:**
- PSSH box with overflowed dataSize field
- Negative/zero box sizes
- Truncated PSSH headers
- Nested PSSH boxes
- Large KID count (0xFFFFFFFF) in version 1 PSSH
- Malformed KeyIDs JSON (unclosed, null bytes, huge arrays)
- Garbage WebM init data

### 3. `webgl-fuzzer.html` — WebGL Fuzzer
**Target:** PlayStation GPU driver via GraphicsContextGL / ANGLE
**Attack path:** Web page → WebGL API → GPU driver
**How to use:**
1. Open on PS5 browser
2. Select fuzzing mode (Textures/Shaders/Framebuffers/All)
3. Monitor klog for GPU faults or driver crashes

**Targets:**
- `readPixels` with OOB dimensions (hits `width * height * bytesPerPixel` unchecked multiply in GraphicsContextGL.cpp:523)
- Huge texture dimensions exceeding MAX_TEXTURE_SIZE
- Format mismatches in texImage2D
- Malformed GLSL shaders (infinite loops, huge arrays, deep nesting, null bytes)
- Use-after-free: delete texture while attached to FBO, then draw
- Render-to-self (same texture as FBO attachment and sampler)

### 4. `css-html-fuzzer.html` — HTML/CSS/SVG Parser Fuzzer
**Target:** WebCore HTML parser, CSS style resolver, SVG parser, layout engine
**Attack path:** Direct web content parsing in WebProcess
**How to use:**
1. Open on PS5 browser
2. Select fuzz mode (HTML/CSS/SVG/Mixed)
3. Monitor klog for crashes

### 5. `ax-enum-ub.html` — Accessibility IPC Bug PoC
**Target:** `WebPageProxy::accessibilityNotification()` and related handlers
**Bug:** uint32 from IPC cast to enum without range validation, switch without default → UB

### 6. `multipart-fuzzer.html` + `multipart-server.py` — Multipart Parser Fuzzer
**Target:** `CurlMultipartHandle::findBoundary()` / `parseHeadersIfPossible()`
**Requires:** `python multipart-server.py` running on your PC

## Identified Vulnerabilities

### VULN-001: IPC Enum Range Validation Missing (WebProcess → UIProcess)

**Files:**
- `Source/WebKit/UIProcess/neko/WebPageProxyPlayStation.cpp:125-164`
- `Source/WebKit/UIProcess/neko/WebViewAccessibilityClient.cpp` (toAPI functions)
- `Source/WebKit/Shared/neko/WebAccessibilityObjectData.cpp:83,100`

**Description:**
Five IPC decode/handler sites receive `uint32_t` values from the WebProcess and
cast them directly to enum types without range validation:

```cpp
// WebPageProxyPlayStation.cpp:136 — IPC handler
static_cast<WebCore::AXObjectCache::AXNotification>(notification)

// WebPageProxyPlayStation.cpp:150 — IPC handler
static_cast<WebCore::AXTextChange>(textChange)

// WebPageProxyPlayStation.cpp:164 — IPC handler
static_cast<WebCore::AXObjectCache::AXLoadingEvent>(loadingEvent)

// WebAccessibilityObjectData.cpp:83 — IPC decode
data.m_role = static_cast<AccessibilityRole>(role)

// WebAccessibilityObjectData.cpp:100 — IPC decode
data.m_buttonState = static_cast<AccessibilityButtonState>(buttonState)
```

The `toAPI()` conversion functions in `WebViewAccessibilityClient.cpp` then switch
on these enum values **without a `default:` case**, causing undefined behavior
when the value is out of range.

**Impact:** Undefined behavior in the UIProcess (privileged process) triggered from
the WebProcess (sandboxed). This is a sandbox escape vector — the compiler may
generate a jump table indexed by the enum value, causing arbitrary code paths.

**Severity:** Medium-High (sandbox boundary violation, UB in privileged process)

### VULN-002: Closed-Source Media Demuxer Attack Surface

**Entry point:** `SourceBufferPrivatePlayStation.cpp:64`
```cpp
m_playstation->append(data->data(), data->size());
```

**Description:** Web-attacker-controlled media data is passed directly to Sony's
closed-source `PSSourceBufferBackend::append()`. Media demuxers are historically
rich in memory corruption bugs. The MSE fuzzer targets this surface.

**Severity:** Depends on fuzzing results — potentially Critical if OOB found

### VULN-003: Closed-Source CDM Backend Attack Surface

**Entry points:**
- `CDMInstanceSessionPlayStation.cpp:62-91` — `requestLicense()` passes web-controlled initData
- `CDMInstanceSessionPlayStation.cpp:93-136` — `updateLicense()` passes web-controlled license response

**Description:** EME initData and license responses from JavaScript flow directly to
Sony's closed-source `PSCDMSessionBackend`. CENC PSSH parsing, KeyID extraction,
and license response processing are all closed-source attack surfaces. The EME
fuzzer targets this surface.

**Severity:** Depends on fuzzing results — potentially Critical if memory corruption found

### VULN-004: WebSecurity URL Evaluation Attack Surface

**Entry point:** `CurlTMServiceRequest.cpp:143`
```cpp
WebSecurity::evalResponse(m_responseHeader.data(), m_responseHeader.size(),
    m_responseData.data(), m_responseData.size(), ...);
```

**Description:** HTTP response headers and body from the network are passed to
Sony's closed-source `WebSecurity::evalResponse()`. A malicious server or MITM
can send crafted responses to reach this code path. Not directly web-fuzzable
without a malicious server, but the multipart server can be adapted.

**Severity:** Depends on backend implementation

### VULN-005: PunchHole canvasHandle Forgery (IPC)

**Files:**
- `DrawingAreaProxyCoordinatedGraphics.cpp:120` — stores IPC vector without validation
- `PlayStationWebView.cpp:391` — passes canvasHandle to application layer
- `AcceleratedSurfacePlayStation.cpp:229,234` — canvasHandle used to address GPU surfaces

**Description:** The `canvasHandle` field in PunchHole IPC messages is not validated.
From a compromised WebProcess, forged canvas handles could address arbitrary GPU
surfaces via `canvas::IndirectCanvas::setIndirectCompositingSource()`.

**Severity:** Medium (requires WebProcess compromise first)

### VULN-006: JSC Config Freezing Disabled in Production

**File:** `Source/JavaScriptCore/runtime/VM.cpp:395-398`
```cpp
#if PLATFORM(PLAYSTATION)
    // FIXME: <PLAYSTATION> REMOVE disableFreezingForTesting() call after RNPS no longer needs this behavior
    Config::disableFreezingForTesting();
#endif
```

**Description:** PlayStation WebKit disables JSC's Config freezing — a security
hardening that makes `g_jscConfig` read-only after initialization. This is
explicitly a testing function (`disableFreezingForTesting`) used in production.
With writable config, an attacker who has an arbitrary write primitive can
modify JIT configuration, disable security features (caging, randomization),
or change execution settings. This significantly lowers the exploitation bar
for any initial memory corruption vulnerability.

**Severity:** Medium (security mitigation bypass — not a bug itself, but weakens defense)

### VULN-007: LLInt PC Range Check Disabled

**File:** `Source/JavaScriptCore/llint/LLIntPCRanges.h:46-48`
```cpp
#if PLATFORM(PLAYSTATION)
    UNUSED_PARAM(pc);
    return false;  // Always false — skips CFI check
#else
    // Normal: checks if PC is within LLInt code range
```

**Description:** The `isLLIntPC()` function, used for control flow integrity
verification, always returns `false` on PlayStation. This disables runtime
checks that verify program counters point to valid interpreter code,
making ROP (Return-Oriented Programming) attacks easier.

**Severity:** Low-Medium (security mitigation bypass)

### VULN-008: Reduced StructureID Heap (128MB vs 4GB)

**File:** `Source/JavaScriptCore/runtime/StructureID.h:50-51`
```cpp
#elif PLATFORM(PLAYSTATION)
constexpr uintptr_t structureHeapAddressSize = 128 * MB;
```

**Description:** PlayStation uses a 128MB StructureID heap vs 4GB on desktop.
StructureIDs are JSC's type tags used to prevent type confusion. A smaller
heap means fewer possible StructureID values, making prediction/collision
attacks more feasible in certain exploit scenarios.

**Severity:** Low (hardening reduction)

## Testing Setup

### Requirements
- PS5 with jailbreak (for klog access)
- klog kernel logger configured and running
- Network access to GitHub Pages or local server

### Serving PoCs locally
```bash
cd poc/
python -m http.server 8080
```
Then navigate PS5 browser to `http://YOUR_PC_IP:8080/`

### Reading klog
When a crash occurs, klog will show:
- Faulting address (check if it's near a heap boundary → OOB)
- Signal type (SIGSEGV = bad memory access, SIGBUS = alignment)
- Backtrace with function names
- Register dump

### What to capture for the HackerOne report
1. The exact PoC HTML that triggered the crash
2. Full klog output around the crash timestamp
3. Faulting address and accessed address
4. Whether the crash is in WebProcess (renderer) or UIProcess (browser)
5. Reproducibility rate (X crashes in Y attempts)
6. Root cause analysis using the REPORT-TEMPLATE.md
