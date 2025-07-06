# Hooking Windows APIs via `.mrdata` — Malware Stealth Technique Explained

*Author: Amit Chaudhary(Security Researcher)
*GitHub: [mrdata-api-hooking-demo](https://github.com/amitchaudharysec/mrdata-api-hooking-demo)*

---

## 🔍 Introduction

Modern malware often avoids traditional API hooking techniques like IAT tampering or inline patching. Instead, it leverages undocumented or obscure areas of system DLLs to stay stealthy. One such area is the `.mrdata` section of `ntdll.dll` — a writable data section that contains internal pointers used by Windows itself.

In this blog, we'll explore:

* What `.mrdata` is and why it's useful
* How malware (like ScyllaHide) uses it to hook APIs
* How to implement a custom `.mrdata` hook in C++
* How to reverse and detect this technique using x32dbg

---

## 🧠 What is `.mrdata`?

`.mrdata` is a writable section in system DLLs like `ntdll.dll`. It typically stores:

* Function pointers for internal Windows logic
* Heap structures and global flags
* Runtime hooks (often undocumented)

Unlike `.text`, `.idata`, or `.rdata`, this section is:

* Writable at runtime
* Not scanned aggressively by AV/EDR
* Not used by normal applications

This makes it a **perfect location for stealthy redirection**.

---

## 💣 How Malware Uses `.mrdata`

Advanced malware uses `.mrdata` to:

* Overwrite internal pointers to redirect control flow
* Hook anti-debug APIs (`IsDebuggerPresent`, `NtQueryInformationProcess`, etc.)
* Store shellcode or encrypted payload handles

Example: ScyllaHide injects hooks into `.mrdata` to bypass anti-debug checks without modifying `.text` or IAT.

---

## 💻 C++ Demo: Hooking `IsDebuggerPresent()` via `.mrdata`

We’ve created a working C++ proof-of-concept that:

* Locates `ntdll.dll`
* Calculates pointer offset inside `.mrdata`
* Redirects the pointer to a custom fake function

### 🔗 [View Full Code on GitHub](https://github.com/amitchaudharysec/mrdata-api-hooking-demo)

#### Key Snippet:

```cpp
*mrdataPtr = (PVOID)&FakeIsDebuggerPresent;
```

### Result:

```bash
[+] .mrdata pointer successfully hooked!
[+] No debugger detected (Fake function was used).
```

---

## 🧪 Reversing with x32dbg

### 1. Set breakpoint on `.mrdata`

* Ctrl+M → Find `.mrdata` under `ntdll.dll`
* Right-click → Breakpoint on Write

### 2. Step into `IsDebuggerPresent()`

* Should jump to custom function address
* You’ll see memory redirection, not traditional `jmp` stub

---

## 📸 Before & After Dump

Using PE-sieve or x32dbg memory tools, dump `.mrdata` region and compare:

* Clean: pointer → real API
* Hooked: pointer → injected stub or fake function

---

## 🧬 Detection with YARA (Example)

```yara
rule MrdataHooking
{
    meta:
        author = "Amit Chaudhary"
        description = "Detects .mrdata pointer redirection in ntdll"
    strings:
        $ntdll = "ntdll.dll"
    condition:
        $ntdll and uint32(0x1F42D0) != 0x77xxxxxx
}
```

Use this as a baseline — exact offsets vary by Windows build.

---

## 🧠 Why This Matters

| Advantage            | Description                   |
| -------------------- | ----------------------------- |
| No `.text` patching  | AV evasion                    |
| No IAT change        | Avoids import table detection |
| No RWX memory needed | Avoids common shellcode flags |
| Hard to detect       | Undocumented & obscure vector |

---

## 📌 Conclusion

Hooking via `.mrdata` is an advanced malware technique that bypasses traditional detection. By understanding and replicating this behavior, researchers can:

* Detect real-world threats more effectively
* Harden defenses against stealth malware
* Build better detection tooling

---

## 🧰 Resources

* [GitHub: mrdata-api-hooking-demo](https://github.com/amitchaudharysec/mrdata-api-hooking-demo)
* [ScyllaHide project (anti-anti-debug)](https://github.com/x64dbg/ScyllaHide)
* [PE-sieve for hook detection](https://github.com/hasherezade/pe-sieve)
* [x32dbg Debugger](https://x64dbg.com/)

---

## ✍️ Author Bio

**Amit Chaudhary** is a malware reverse engineer and security researcher focused on stealth malware techniques, API internals, and threat hunting. Follow his work at:
👉 GitHub: [amitchaudharysec](https://github.com/amitchaudharysec)
👉 Blog: *Coming Soon*
👉 Twitter: *@amitchaudharysec*
