# PS5 WebKit Security Research — PoC Suite

## Overview

Targeted security research against Sony's WebKit port (WebKit-1200) for PlayStation 5.
Focus: memory-safety bugs (OOB, UAF, integer overflow) in PlayStation-specific code
and Sony's custom backend libraries reachable from web content.

## Tools

### 1. `mse-fuzzer.html` — Media Source Extensions Fuzzer
**Target:** `mediaplayer::PSSourceBufferBackend::append()` (Sony's closed-source media demuxer)
**Attack path:** Web page → `SourceBuffer.appendBuffer()` → `SourceBufferPrivatePlayStation::appendInternal()` → Sony backend
**How to use:**
1. Host this file on a web server accessible from PS5
2. Open in PS5 browser
3. Click "Fuzz MP4/H.264" (or other codec buttons)
4. Monitor klog for SIGSEGV/SIGBUS/page faults
5. Each iteration sends a mutated MP4/WebM container to the demuxer

**Mutation strategies:**
- Box size corruption (integer overflow in size calculations)
- Truncation at random offsets
- Bit-flip mutation
- Large count fields (array allocation overflow)
- Duplicate/overlap structures
- Zero-fill (null deref / div-by-zero)
- Box type swapping (state machine confusion)
- Dimension overflow (width×height×bpp integer overflow)

### 2. `css-html-fuzzer.html` — HTML/CSS/SVG Parser Fuzzer
**Target:** WebCore HTML parser, CSS style resolver, SVG parser, layout engine
**Attack path:** Direct web content parsing in WebProcess
**How to use:**
1. Host and open on PS5
2. Select fuzz mode (HTML/CSS/SVG/Mixed)
3. Monitor klog for crashes
4. Generates random DOM structures with extreme attribute values, deep nesting, and malformed SVG

### 3. `multipart-fuzzer.html` + `multipart-server.py` — Multipart Parser Fuzzer
**Target:** `CurlMultipartHandle::findBoundary()` / `parseHeadersIfPossible()`
**Attack path:** Network response → multipart/x-mixed-replace parsing (used for MJPEG streams, etc.)
**How to use:**
1. Run `python multipart-server.py` on your PC
2. Edit `SERVER` variable in `multipart-fuzzer.html` to your PC's IP
3. Open the HTML on PS5
4. The server generates malformed multipart responses with various mutations

### 4. `ax-enum-ub.html` — Accessibility IPC Bug PoC
**Target:** `WebPageProxy::accessibilityNotification()` and related handlers
**Bug:** uint32 from IPC cast to enum without range validation, switch without default → UB
**Details:** See the identified vulnerabilities section below

## Identified Vulnerabilities

### VULN-001: IPC Enum Range Validation Missing (WebProcess → UIProcess)

**Files:**
- `Source/WebKit/UIProcess/neko/WebPageProxyPlayStation.cpp:125-164`
- `Source/WebKit/UIProcess/neko/WebViewAccessibilityClient.cpp` (toAPI functions)
- `Source/WebKit/Shared/neko/WebAccessibilityObjectData.cpp:83,100`

**Description:**
Three IPC message handlers in the UIProcess receive `uint32_t` values from the
(sandboxed) WebProcess and cast them directly to enum types without validation:

```cpp
// WebPageProxyPlayStation.cpp:136
static_cast<WebCore::AXObjectCache::AXNotification>(notification)

// WebPageProxyPlayStation.cpp:150
static_cast<WebCore::AXTextChange>(textChange)

// WebPageProxyPlayStation.cpp:164
static_cast<WebCore::AXObjectCache::AXLoadingEvent>(loadingEvent)
```

The `toAPI()` conversion functions then switch on these enum values **without a
`default:` case**, causing undefined behavior when the value is out of range.

Additionally, `WebAccessibilityObjectData::decode()` (line 83) casts raw uint32
to `AccessibilityRole` and `AccessibilityButtonState` without range checks.

**Impact:** A compromised WebProcess can trigger undefined behavior in the
UIProcess by sending out-of-range enum values via IPC. This is a sandbox
escape primitive — the UIProcess runs with higher privileges.

**Severity:** Medium-High (sandbox boundary violation, UB in privileged process)

### VULN-002: Potential OOB in Sony Media Demuxer (Black-box)

**Entry point:** `SourceBufferPrivatePlayStation.cpp:64`
```cpp
m_playstation->append(data->data(), data->size());
```

**Description:** Web-attacker-controlled media data is passed directly to Sony's
closed-source `PSSourceBufferBackend::append()`. Media demuxers are historically
rich in memory corruption bugs. Sony's implementation has not been publicly
fuzzed. The MSE fuzzer tool targets this surface.

## Testing Setup

### Requirements
- PS5 with jailbreak (for klog access)
- klog kernel logger configured and running
- PC on same network to serve PoC files
- Python 3 for the multipart server

### Serving PoCs
```bash
# Simple HTTP server from the poc/ directory
cd poc/
python -m http.server 8080
```
Then navigate PS5 browser to `http://YOUR_PC_IP:8080/mse-fuzzer.html`

### Reading klog
When a crash occurs in the WebProcess or UIProcess, klog will show:
- Faulting address (check if it's near a heap boundary → OOB)
- Signal type (SIGSEGV = bad memory access, SIGBUS = alignment)
- Backtrace with function names
- Register dump

### What to capture for the report
1. The exact PoC HTML that triggered the crash
2. Full klog output around the crash timestamp
3. Faulting address and accessed address
4. Whether the crash is in WebProcess (renderer) or UIProcess (browser)
5. Reproducibility rate (X crashes in Y attempts)
