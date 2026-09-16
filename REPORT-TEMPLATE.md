# HackerOne Report Template — PS5 WebKit

---

## Title
[COMPONENT] Memory corruption in [FUNCTION] via [ATTACK VECTOR]

Example: "WebKit MSE: Heap OOB read in PSSourceBufferBackend::append via malformed MP4 box size"

---

## Summary
A [type of bug: heap OOB read/write, integer overflow, use-after-free, undefined behavior]
exists in [component] when processing [attacker-controlled input]. A remote attacker
can trigger this by serving a specially crafted [web page / media file / multipart response]
to the PS5 browser.

## Affected Component
- **Product:** PlayStation 5 System Software (WebKit Browser)
- **WebKit Version:** WebKit-1200 (Sony port)
- **Source File:** [path:line, if known from source]
- **Binary/Library:** [if crash is in a closed-source library, name it from the backtrace]

## Vulnerability Details

### Root Cause
[Describe the bug mechanically. Example:]
The MP4 box parser reads a 32-bit `size` field from the container header without
checking for integer overflow. When `size` is set to 0xFFFFFFFF, the calculation
`offset + size` wraps to a small value, causing the parser to read beyond the
allocated buffer.

### Attack Path
1. Attacker hosts a web page with the PoC
2. Victim visits the page on PS5 browser
3. JavaScript creates a MediaSource and appends a malformed MP4 segment
4. The Sony media backend (`PSSourceBufferBackend::append`) parses the data
5. [Describe the crash / corruption]

## Impact
- **Process affected:** [WebProcess / UIProcess / GPUProcess / NetworkProcess]
- **Type:** [OOB read → info leak / OOB write → potential RCE / UB → unpredictable]
- **Severity:** [Use CVSS if possible]
- **User interaction:** Visiting a web page (no clicks required)

## Proof of Concept

### PoC File
[Attach the HTML file]

### Steps to Reproduce
1. Host the attached `poc.html` on an HTTP server
2. Open the PS5 browser and navigate to `http://server/poc.html`
3. [Any user interaction needed]
4. Observe crash in klog

### Crash Log (klog output)
```
[paste klog output here showing:]
- Signal: SIGSEGV / SIGBUS
- Faulting address: 0x...
- Process: WebProcess / UIProcess
- Backtrace:
  #0 [function_name + offset]
  #1 [function_name + offset]
  ...
- Register dump (especially the register holding the OOB pointer)
```

### Reproducibility
- Crashes [X] out of [Y] attempts (deterministic / probabilistic)
- Tested on PS5 firmware version [X.XX]

## Remediation Suggestion
[Example:]
- Validate box `size` field: reject if `size > remaining_buffer_length`
- Add integer overflow check: `if (offset > SIZE_MAX - size) return error;`
- Add `default:` branch to switch statements handling IPC enum values
- Validate enum range before cast: `if (notification >= AXNotification::COUNT) return;`

## Additional Information
- This vulnerability was found through source code review of WebKit-1200
  (Sony's open-source WebKit port) combined with black-box fuzzing on PS5 hardware.
- The bug is in PlayStation-specific code / Sony's backend libraries,
  not in upstream WebKit.
- [If applicable:] I have not attempted to develop a full exploit chain;
  this report demonstrates the memory corruption primitive.

---

## Checklist Before Submitting
- [ ] PoC is self-contained (single HTML file, or HTML + server script)
- [ ] PoC triggers crash reliably (>50% rate)
- [ ] klog output captured with full backtrace
- [ ] Faulting address analysis: is it controlled? Is it an OOB offset?
- [ ] Impact assessment: which process, what kind of memory access
- [ ] No speculation about exploitability beyond what's demonstrated
- [ ] Clear remediation suggestion
- [ ] Tested on latest PS5 firmware available to you
