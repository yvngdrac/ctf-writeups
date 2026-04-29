# The Winning Shot — CTF Forensics Writeup

**CTF:** UMCS CTF  
**Category:** Forensics  
**Points:** 110  
**Flag:** `UMCS{k1n3t1c_3n3rgy_r3c0v3r3d_fr0m_c0r3_dump}`

---

## Overview

> "The break shot has been taken, and the balls are scattered across the memory space. We managed to freeze the table mid-game, but the suspect's final move remains hidden in the pocket."

This challenge gave us a zip file (`8_b411_p00l_1s_7un.zip`) and told us a Linux environment is recommended. The hint to `chmod +x winning_shot` already hinted that we'd be dealing with an ELF binary. Let's dig in.

---

## Recon — What's in the zip?

```bash
unzip 8_b411_p00l_1s_7un.zip
file pool winning_shot core.170390
```

```
pool:         JPEG image data, JFIF standard 1.01, ...
winner_shot: ELF 64-bit LSB pie executable, x86-64, ... not stripped
core.170390:  ELF 64-bit LSB core file, x86-64, ... from './winning_shot'
```

Three files:  
- `pool` — a JPEG image (rabbit hole, but fits the theme)  
- `winning_shot` — the main ELF binary  
- `core.170390` — a **core dump** of `winning_shot` mid-execution

The "frozen table mid-game" from the description = the core dump. The process was caught while sleeping in memory. Classic forensics setup.

---

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

---

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

---

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

---

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

---

## Flag

```
UMCS{k1n3t1c_3n3rgy_r3c0v3r3d_fr0m_c0r3_dump}
```

---

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