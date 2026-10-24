# GUI application analysis — Redragon M910-KS control panel

Reverse engineering of Redragon's Windows-only control panel for the
M910-KS Ranger Lite, done to recover the Sino Wealth wire protocol.

Companion to [PROTOCOL.md](PROTOCOL.md). Everything here was obtained by
**static analysis only** — no Windows, no Wine, no USB traffic capture. No
command was ever sent to the mouse during this work.

## Artifact provenance

| | |
|---|---|
| Source | `https://cdn.shopify.com/s/files/1/0655/1289/8735/files/Redragon_M910KS_Setup_v1.0_2876_BY1064_P3104.rar?v=1720771133` |
| SHA-256 (rar) | `28d4e9e3528ab0ae073d6af03503805c693c6f1a35c9c319c08009e77e5ebf78` |
| Format | RAR → `bsdtar` → `setup.exe` → **Inno Setup 5.3.3** → `innoextract` 1.9 |

The filename encodes the target: `2876` = firmware string reported by cmd
`0x01`, `BY1064` = chip variant, `P3104` = PMW 3104 sensor.

### Payload

```
app/OemDrv.exe        2 124 800   the GUI + all protocol logic
app/Lowerdev.dll         57 856   thin HID transport shim (9 exports)
app/MenuEx.dll          242 176   menu skinning
app/InitSetup.dll        56 320   installer-side
app/Cfg.ini               2 588   device database / UI geometry
app/Text/en/text.xml     14 325   UI strings (UTF-16)
app/skins/*                     78 skin bitmaps (4K variants included)
```

**No firmware image ships in this installer.** `Cfg.ini` sets
`ShowFWUpdate=0`, and the text bundle has a `Firmware Update` string, so the
code exists but the UI entry point is disabled for this model.

## Toolchain

No native decompiler provider was configured on the analysis host
(`GHIDRA_INSTALL_DIR` unset, no Hopper, no IDA), so REA's Ghidra/IDA/Hopper
backends were unavailable and `binary_overview` / `analyze_function` /
`search_procedures` could not run.

Analysis used instead:

- `bsdtar` (libarchive) for the RAR — no `unrar` needed
- `innoextract` 1.9, unpacked unprivileged from the Arch package
  (`bsdtar -xf` of `innoextract-1.9-17-x86_64.pkg.tar.zst`)
- `radare2` 6.2.2 for function/vtable/xref recovery, likewise unpacked
  unprivileged from the Arch package plus local `capstone` and `zydis`
- `objdump -d` (binutils) for instruction-level reading
- a small stdlib PE section/offset reader, and a scanner that pairs
  `movb $imm, disp(%esp)` with the following `call` to recover command bytes

**No `sudo`, no system packages installed, no system files modified.**

### Keep scratch in `vendor/`, not `/tmp`

The first pass at this analysis unpacked everything into `/tmp`, and `/tmp` got
wiped between sessions — taking the vendor tree, the disassembly and the
helper scripts with it. The findings survived only because they had already
been written up here.

Put analysis scratch in `vendor/` (gitignored) instead. It is on the same
filesystem as the repo, it is not swept, and `tools/fetch_vendor.sh` already
populates it.

`radare2` recovered the driver class vtable, which is what made the rest
tractable:

```
method.CDrvBY24G.virtual_0     0x00409710
method.CDevBY24G.virtual_0     0x0042f170
method.CDevBY24G.virtual_4     0x0042f160
method.CDevBY24G.virtual_8     0x0040aa10
method.CDevBY24G.virtual_12    0x0040b010
method.CDevBY24G.virtual_16    0x0040bd60   <- Apply_24G
```

### Reproducing this without redoing the archaeology

Three committed helpers regenerate the load-bearing facts from `vendor/`
alone. The scratch versions of these were lost to a `/tmp` wipe once already.

```sh
./tools/fetch_vendor.sh                                    # artifacts

# 1. PE structure, exports, and VA -> file offset mapping.
#    Needed because `objdump -p` will not print Lowerdev.dll's export
#    directory, and every address below depends on the mapping being right.
python3 tools/re_pe.py vendor/gui/app/Lowerdev.dll --exports
python3 tools/re_pe.py vendor/gui/app/OemDrv.exe --where 0x40b680
python3 tools/re_pe.py vendor/gui/app/OemDrv.exe --data 0x40b284:0x20

# 2. Disassemble once. objdump -d linear sweep, ~500k instructions.
objdump -d vendor/gui/app/OemDrv.exe > /tmp/OemDrv.asm

# 3. Recover the command table from the call sites.
python3 tools/re_cmds.py /tmp/OemDrv.asm

# 4. Read one function. objdump loses instruction alignment in data regions
#    near 0x40b000 and never recovers, so restarting at a known function
#    boundary is the only way to read that code.
python3 tools/re_fn.py /tmp/OemDrv.asm 0x40b010 --calls
```

`re_cmds.py` on its own reproduces the whole command table in this document:

```
0x40a325 SendCmd  0x01
0x40a41d SendCmd  0x11 0x21 0x31
0x40a553 GetCmd   0x11 0x21 0x31 0x92
0x40a5cd SendCmd  0x90
0x40a727 GetCmd   0x12 0x22 0x32 0x50 0xa5
0x40a7fb GetCmd   0x30 0x02
```

Note that `0x12`, `0x22`, `0x32` and `0x30` — the four the echo-oracle sweep
could not see — fall straight out of the disassembly.

## Device module: `CDrvBY24G`

Debug strings identify the driver class and the three device interfaces it
opens:

```
CDrvBY24G::ClearHandle
Aly8948_1: nCfgSize=%d, FeatureSize=%d
CDrvBY24G  FindDev: looking for %s
m_hCmd=0x%x, m_hData=0x%x, m_hNotify=0x%x
Psd unmatched: dev=%02x,%02x,%02x,%02x
```

- **BY24G** — the chipset family. Matches `BY1064` in the installer filename.
- **Aly8948** — the internal codename used in size assertions.
- `m_hCmd`, `m_hData`, `m_hNotify` — **three separate handles**, i.e. the
  vendor interface exposes a command channel, a bulk-data channel, and a
  notify channel.
- `PSD` is a 4-byte device signature (`Cfg.ini`: `PSD=32,38,37,36`). The app
  refuses to drive a device whose PSD does not match, and writes the PSD to
  the device during apply.

## Transport

`Lowerdev.dll` is transport only. Its nine exports are thin `__stdcall`
thunks:

```
int SetFeature(HANDLE, BYTE* buf, int len);
int GetFeature(HANDLE, BYTE* buf, int len);
```

`OemDrv.exe` does **not** import it statically — it resolves it at runtime:

```c
hMod = LoadLibraryW(L"Lowerdev.dll");
pOpen  = GetProcAddress(hMod, "OpenHidDevice");
pSet   = GetProcAddress(hMod, "SetFeature");
pGet   = GetProcAddress(hMod, "GetFeature");
pProd  = GetProcAddress(hMod, "GetProductString");
pVer   = GetProcAddress(hMod, "GetVersionNumber");
```

resolved into an object with the function pointers at `+0x08 … +0x1c`.

### `SendCmd` — the command packet

This is the routine at `0x409f80`, and it **independently confirms the
format `tools/sinowealth.py` already uses**:

```c
// in : BYTE cmd[5] = { cmd, a1, a2, a3, a4 }
BYTE out[8];
out[0] = 0x05;                 // HID report ID
out[1] = cmd[0];               // command byte
out[2] = cmd[1]; out[3] = cmd[2]; out[4] = cmd[3]; out[5] = cmd[4];
// out[6], out[7] are not explicitly written here
for (int i = 3; i > 0; i--) {
    if (SetFeature(m_hCmd, out, 8)) break;
    Sleep(200);
}
```

So on the wire: **`SET_FEATURE(report 0x05, [0x05, CMD, a1, a2, a3, a4, 0, 0])`**
— a 5-byte command with 3 retries and a 200 ms settle.

This matches `battery.py`'s `cmd_query` exactly. The 200 ms × 3 retry
behaviour is also the likely reason aggressive polling returns "asleep"
rather than a reading.

## Command table — recovered

Recovered by scanning the driver module for immediate byte writes paired
with calls into `SendCmd` / `GetCmd`.

| Command | Function @ | Address | Direction |
|---|---|---|---|
| `0x01` | general / firmware info | `0x40a2f0` | read |
| `0x11` | get config, profile 1 | `0x40a3c0` | read |
| `0x21` | get config, profile 2 | `0x40a3c0` | read |
| `0x31` | get config, profile 3 | `0x40a3c0` | read |
| `0x12` | **SetMatrix**, profile 1 | `0x40a680` | **write** |
| `0x22` | **SetMatrix**, profile 2 | `0x40a680` | **write** |
| `0x32` | **SetMatrix**, profile 3 | `0x40a680` | **write** |
| `0x30` | **SetMacro** | `0x40a760` | **write** |
| `0x90` | **ReadPower** (battery) | `0x40a590` | read |
| `0x92` | PSD sub-command | `0x40a4d0` | write |

Supporting constants, in the same module:

| Byte | Where | Meaning |
|---|---|---|
| `0x05` | `SendCmd` | HID report ID for commands |
| `0x08` | data path | HID report ID for the bulk config blob |
| `0x50` | `SetMatrix` | at packet offset 0x02 — payload length, see below |
| `0xa5` | `SetMatrix` | at packet offset 0x57 — terminator |

### Why `0x12` and `0x22` looked dead

`PROTOCOL.md` recorded `0x12` as "no reply / empty" and `0x22` as empty.
That is now explained: **they are write commands and do not echo**, so the
command-support oracle could never see them. The same is true of `0x30`.
This confirms the earlier hypothesis that the `0x01..0xFF` sweep was
structurally blind to the write half of the protocol.

`0x31` was recorded as "untested" rather than unsupported — it is in fact
implemented, and is the profile-3 config read.

### `SetMatrix` packet layout

From the stack arithmetic in `0x40a680`:

```c
BYTE pkt[0x206];
memset(pkt + 1, 0, 0x205);
pkt[0] = 0x12 | 0x22 | 0x32;   // by profile
pkt[2] = 0x50;                 // 80
memcpy(pkt + 7, matrix, len);
pkt[0x57] = 0xa5;
```

```
[0x00]  command           0x12 / 0x22 / 0x32
[0x01]  zeroed
[0x02]  0x50  (80)        payload length
[0x03..0x06] zeroed
[0x07..0x56] 80 bytes     key matrix payload
[0x57]  0xa5              terminator
```

The identity `0x07 + 0x50 = 0x57` is what makes byte 2 read as a length
rather than a constant — the `0xa5` lands exactly one past an 80-byte
payload. Flagged as **strong inference**, not observation.

**Not** the origin of the `0xa5` in the 520-byte config blob. An earlier
version of this file proposed the matrix terminator as its origin, on the
strength of `0x97 - 0x50 = 0x47`. That was inference, never observed, and it
is wrong: the blob's only `0xa5` is at offset `0x98`, where the
general-block packer writes a hard-coded constant (#6). The two `0xa5` bytes
are unrelated.

### `SetMacro` packet

```c
BYTE pkt[0x203];
pkt[0] = 0x30;
pkt[1] = 0x02;
pkt[2] = 0x00;
```

Matches libratbag's `CMD_MACRO = 0x30`, previously never sent.

## `Apply_24G` — the vendor write sequence

`Apply_24G` (`0x40bd60`, virtual 16) is the complete device-apply routine.
Its call order is the vendor's own recipe, recovered verbatim:

```
Apply_24G
 ├─ "Writing Mode %x (PID=%04X)------"
 ├─ GetConfig(profile)          0x40a3c0   0x11/0x21/0x31   read-back first
 ├─ "General(Load):-------------"           read current general block
 │    "lastGeneral:-------------"
 ├─ "General(Save):-------------"           write general block
 │    "Warning: value=0"  "Tips: rsn=0"  "Tips: wsn=0"
 ├─ SetProfile / PSD            0x40a4d0   0x11/0x21/0x31 + 0x92
 ├─ SetMacro                     0x40a760   0x30
 │    "Macro number error!!!, nMacroNum=%d, nBulletNum=%d"
 ├─ "-------KeyMode%d-------"
 │    "Matrix[%d][%d] = 0x%08x"
 └─ SetMatrix                   0x40a680   0x12/0x22/0x32
```

Two things worth keeping:

1. **The vendor reads the current config back before writing it.** It does
   not blind-write. Any Linux implementation should do the same.
2. The write is split across four separate commands, not one blob dump —
   general block, PSD, macro, then key matrix.

## Key / button model

The profile file format is explicit:

```
pro.dct  = 15 slots x 5816 bytes = 87240 bytes (0x154c8)
each slot: [0x00] magic = 0xFcaa1235
           [0x04] in-use flag (0 = slot free)
```

`curid.dct` holds the current profile index; macros use `mac.dct` and
`*.mck`.

The per-key record, from the app's own diagnostic string:

```
pFile->Key[%d][%d]: dwFunID=0x%x, dwMacroID=0x%08x,
                   dwParameter=0x%08x, stCombo=0x%08x
```

— four 32-bit fields per key, indexed `[profile][key]`.

`Cfg.ini` stores defaults as `K<key>_<profile>` in the form
`K1_1=0x01,0x11,0x00,0x01`:

```
K1  0x01,0x11  left      K6  0x08,0xA8
K2  0x01,0x13  right     K7  0x08,0xA9
K3  0x01,0x12  middle    K8  0x08,0xAE
K4  0x01,0x14            K9  0x01,0x17
K5  0x01,0x15            K10 0x08,0xAC
```

Byte 3 is the button index (`01 02 03 05 06 07 08 09 04 0A` — note `04`
lands on K9, matching the physical layout). Byte 1 carries the function
code; the `0xA8`/`0xA9`/`0xAC`/`0xAE` group on K6/K7/K8/K10 are the
programmable macro buttons.

The matrix builder at `0x40b010` dispatches on **byte 0** of each record,
in **two stages**. The whole dispatch is six instructions:

```
  40b072:  8a 0e                 mov    (%esi),%cl        ; cl = byte 0 = the FunID
  40b088:  0f b6 d1              movzbl %cl,%edx
  40b08b:  83 c2 f0              add    $0xfffffff0,%edx   ; edx = FunID - 0x10
  40b093:  81 fa ea 00 00 00     cmp    $0xea,%edx
  40b099:  0f 87 b8 00 00 00     ja     0x40b157           ; out of range -> default
  40b09f:  0f b6 92 84 b2 40 00  movzbl 0x40b284(%edx),%edx ; stage 1: FunID -> case
  40b0a6:  ff 24 95 44 b2 40 00  jmp    *0x40b244(,%edx,4)   ; stage 2: case -> handler
```

Stage 1 indexes a **235-byte table** at `0x40b284`; stage 2 indexes a
**16-entry dword** jump table at `0x40b244`. Both counts are real, and they
count different things — that was the contradiction an earlier revision of
this section papered over with "16 reachable entries, not 235".

| | address | extent | holds |
|---|---|---|---|
| stage 1, byte table | `0x40b284` | `235` bytes (`0x40b284`–`0x40b36e`) | case index `0x00`–`0x0f` |
| stage 2, jump table | `0x40b244` | `64` bytes = `16` entries | handler VA |

The bound is self-consistent at both levels, which is the point of splitting
it in two:

- `cmp $0xea` / `ja` is **unsigned**, so `edx` is constrained to `0..0xea` —
  235 values — which is exactly the byte table's length. FunIDs below `0x10`
  wrap on the `add` and also take the `ja`.
- Every value in the byte table is `<= 0x0f`, so it can never index past the
  16-entry jump table. **No second clamp is needed**, and none exists.
- `ja 0x40b157` and `jump[15]` are *the same address*, so an out-of-range
  FunID and the default case converge on one handler rather than needing a
  separate path.

Immediately past the byte table there is **one** byte, an `int3` at
`0x40b36f`; `0x40b370` is already the next function's SEH prolog
(`push $0xffffffff; push $0x56c08b; mov %fs:0x0,%eax`). There are no
trailing table entries of any kind.

> **Corrected twice.** The first version had the encoded column off by one
> and omitted case 0. The second fixed that but then asserted "16 reachable
> entries, not 235" alongside a `cmp $0xea` that makes 235 reachable, and
> claimed ten dead entries past `0xFA` where there is one `int3`.
>
> Reproducing this section takes more than one tool: `re_pe.py --data` dumps
> the two tables' bytes, and `re_fn.py` on a disassembly restarted at each
> handler address gives its behaviour. `re_pe.py` alone yields the tables but
> not the handlers.

| case | FunIDs | size (`bl`) | encoded | meaning |
|---|---|---|---|---|
| 0 | `0x10`, `0xa0`, `0xa1` | 6 | `0x02` | |
| 1 | `0x11`, `0xa2`, `0xa3` | 6 | `0x01` | left click |
| 2 | `0x12`, `0xa4`, `0xa5` | 6 | `0x04` | |
| 3 | `0x5b`, `0x5c` | 6 | `0x08` | |
| 4 | `0xf0` | 1 | `0x01` | |
| 5 | `0xf1` | 1 | `0x02` | |
| 6 | `0xf2` | 1 | `0x04` | |
| 7 | `0xf3` | 1 | `0x08` | |
| 8 | `0xf4` | 1 | `0x10` | |
| 9 | `0xf5` | 4 | byte 1 as-is | |
| 10 | `0xf6` | 4 | byte 1 negated | |
| 11 | `0xf7` | 3 | byte 1 negated | |
| 12 | `0xf8` | 3 | byte 1 as-is | |
| 13 | `0xf9` | 2 | byte 1 negated | |
| 14 | `0xfa` | 2 | byte 1 as-is | |
| 15 | default (213) | 5 | default | keyboard / media / combo |

The case-to-FunID mapping and every `size (bl)` above is read straight out of
the two tables. Two details are worth being precise about:

- **The default case is not the contiguous range `0x13`–`0xef`.** It is 213
  FunIDs in three runs — `0x13`–`0x5a`, `0x5d`–`0x9f`, `0xa6`–`0xef` — because
  `0x5b`, `0x5c` and `0xa0`–`0xa5` are carved out. That is the `221` FunIDs
  of `0x13`–`0xef` minus the `8` special-cased ones.
- **Cases 9–14 differ by more than a label.** All six clear `0x13(%esp)`,
  which sends them down the table-lookup path at `0x40b175` instead of
  writing a literal. Three of them (cases 10, 11, 13) additionally run
  `not %al; inc %al` on byte 1 first, i.e. they negate it before the lookup.
  Case 9 does **not** — an earlier revision of this table labelled it
  "*increments*" and paired it with case 10, which is backwards; cases 9, 12
  and 14 are the same plain variant.

Two shapes fall out of this that were not visible before:

- **`0xf0`–`0xf4` encode a clean bit pattern** (`0x01`, `0x02`, `0x04`,
  `0x08`, `0x10`) at size 1 — five independent single-bit flags. Strong
  candidate for the dedicated hardware buttons.
- **`0xf5`–`0xfa` pair up**: `(0xf5, 0xf6)` both size 4, `(0xf7, 0xf8)` both
  size 3, `(0xf9, 0xfa)` both size 2, and within each pair one handler
  negates byte 1 while the other passes it through unchanged. That is the
  shape of a pair of related settings, e.g. two sides of one function.

Neither interpretation is confirmed. `text.xml` names DPI, RGB, profile
switch and fire key as distinct hardware actions, so five flags fits — but
naming them needs the button mapping from #3, not more disassembly.

The 6-byte encodings and their field meanings remain open — that is #8.

## Feature inventory

From `Cfg.ini` and `text.xml`. `Cfg.ini` is the authoritative vocabulary of
everything the app understands.

**Device** — `Sensor=0x3104`, `VID=0x258A`, `PID=0x002E`, `PID2=0x002F`,
`PSD=32,38,37,36`, `ApplyNow=1`, `ShowFWUpdate=0`, `AutoSw=0`,
`Suwnd=0`, `WuYU=1`, `BtnTips=0`, `PopByte1=0`.

**DPI** — `DM=5` (levels), `DPI=500,1000,2000,3000,4000` (the 5 on-board
levels), `DPISET=250,500,750,…,8000` (24 values, the software DPI ladder),
`DEFLEVEL=1`, plus `DPIH`, `DPIHW`, `DPILK` consumed by the app with
consistency errors (`DPISET Num != DPIHW Num`).

**Polling rate** — `RATE1`–`RATE4`, rendered from the literal strings
`125 Hz`, `250 Hz`, `500 Hz`, `1000 Hz`. Default `DR=0x125` (`DR_2`,
`DR_3` also parsed).

**Lighting** — `LedOpt1`–`LedOpt10` documented in `Cfg.ini` as
`;Speed Light Direct Random ColorNum`. Ten LED effects, matching
`text.xml`: Colorful Streaming, Steady, Breathing, Colorful Tail, Neon,
Colorful Steady, Flicker, Stars twinkle, Wave, LED OFF. `DC` gives six
default colours; `MainRGB`, `LogoRGB`, `DpiRGB` are per-zone colours.

**Buttons** — `K%d_%d`, `KEYH`, `KM` (key mask), `KEYY`, `Mark%d`, `ExKey1`–`ExKey4`,
`CustomkeyCode`, `SnipMenu`. Per key: mouse button, single/double/R-double
click, media, key combination, macro, disable, fire key.

**Advanced** — `tc_adv_str*`: double-click speed, mouse sensitivity,
scrolling speed, scroll one page, improve pointer precision, USB polling
rate, brightness, LED effect, LOGO effect, speed, colour, predefined colour,
RGB value, DPI effect.

**Battery** — `ReadPower: nPower=%d, nUsbConnect=%d` confirms `cmd 0x90`
returns charge **and** a USB-connected flag. `nUsbConnect` is very likely
the charging indicator the tool currently leaves as `None`.

## Live validation

`tools/verify_vendor_cmds.py` sends **only** the commands the RE classifies
as reads — `0x01`, `0x11`, `0x21`, `0x31`, `0x90`. It asserts that none of
the write commands (`0x12`, `0x22`, `0x32`, `0x30`, `0x92`) or `0x75`
appear in its send list.

One transport detail worth recording: a config read must ask for the reply
on **report `0x08`**, not `0x05`. Asking report `0x05` for 520 bytes makes
the device stall the control transfer and the kernel returns `EPIPE`
("Broken pipe"), which looks like a dead device but is not one.

Results on the dongle (`258a:002f`, `hidraw1`, mouse asleep, not charging):

```
0x01  firmware = 2876
0x21  520 bytes, echo confirmed
0x90  link=wireless power=100% usb_connected=0x11
```

**`0x11` and `0x31` stall the control transfer.** Reproducible across three
rounds with 1.2 s spacing, so it is not a timing or ordering artefact.

This does not contradict the disassembly, but it is an important
discrepancy to record: **`PROTOCOL.md`'s command table was derived from the
wired mouse (`258a:002e`)**, while this run is the dongle (`258a:002f`).
Either the two products expose a different slice of the command space, or
the dongle only answers for whichever profile is currently active. The
vendor app maintains three handles and a single active `nProIndex`, which
is consistent with the latter — but it is **not established**.

### The config blob, as read from the dongle

```
0000  08 21 00 00 00 00 00 00 64 13 04 25 00 02 00 04   |.!......d..%....|
0010  00 08 00 0c 00 10 00 00 00 00 00 00 00 00 00 00   |................|
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 ff 00 00   |................|
0030  00 00 ff 00 ff 00 ff 00 ff ff ff 00 00 ff ff ff   |................|
0040  ff ff ff 46 00 01 42 01 40 ff 00 00 42 07 ff 00   |...F..B.@...B...|
0050  00 00 ff 00 00 00 ff ff 00 ff ff ff 00 ff 80 00   |................|
0060  00 ff ff 02 42 40 ff 00 00 00 ff 00 00 00 ff ff   |....B@..........|
0070  00 ff ff ff 00 ff ff 00 00 00 00 00 00 00 00 00   |................|
0080  00 00 00 00 42 ff 00 00 00 ff 00 42 42 02 ff 00   |....B......BB...|
0090  00 00 00 01 02 ff 00 00 a5 00 00 00 00 00 00 00   |................|
```

Offsets `0x000`–`0x09f` shown contiguously; the blob is 520 bytes and the
rest is not yet mapped. Raw copy kept out of git; re-read it any time with
`python3 tools/verify_vendor_cmds.py`, and diff it against
`captures/vendor-0x21-dongle.bin`.

**Offsets 13..22 are the DPI table**, as five 16-bit little-endian values:

| offset | bytes | stored | ×250 = DPI |
|---|---|---|---|
| 13 | `02 00` | 2 | 500 |
| 15 | `04 00` | 4 | 1000 |
| 17 | `08 00` | 8 | 2000 |
| 19 | `0c 00` | 12 | 3000 |
| 21 | `10 00` | 16 | 4000 |

Five levels, matching `DM=5`. The stored values are indices into the
`DPISET` ladder in `Cfg.ini`, which runs `250,500,750,…` in 250 steps — so
index *n* means *n*×250 DPI, giving exactly `DPI=500,1000,2000,3000,4000`
from the same file.

> **Corrected.** This table previously started at offset **12** and read
> `00 02` = **512**, `1024`, `2048`, `3072`, `4096`, on the theory that "the
> device rounds each level up to the next multiple of 512". Both the offset
> and the units were wrong, and the rounding story was a rationalisation of
> the error: 512 is 2×256, not a DPI value. Reading one byte early makes each
> 16-bit value 256× too large. See #6 — the packer writes the low byte first
> from a cursor at offset `0x0d`.

**`0xa5` is at offset `0x98`**, and it is a hard-coded constant — the last
byte of the 146-byte general block, written by `movb $0xa5,0x90(%esi)` at
`0x40ba2f`. It is **not** related to the `SetMatrix` terminator.

> **Corrected.** This section previously placed `0xa5` at `0x97` and argued
> for it from `0x97 - 0x50 = 0x47`, a "constant `0x40` shift" mirroring the
> matrix arithmetic. That inference was wrong, and its stated evidence was
> not real: the hexdump above previously ended with four rows copied from a
> *different* capture, one of which was a byte-for-byte duplicate of the real
> row at `0x0060`. The blob contains exactly one `0xa5`, at `0x98`.

`PROTOCOL.md` carried both errors and has been corrected.

The region from `0x45` to `0x95` is dense with `0xff`, matching keys set
to *Disable* (`tc_key_off`), and carries repeated `0x42` bytes that look
like per-key function tags.

Byte `[8] = 0x64` = 100 is **explained** (#6): it is the first byte of the
general block, written as a hard-coded constant by `movb $0x64,(%esi)` at
`0x40b75d`. It is stable across the `0x11` and `0x21` reads on two different
USB products because it is a constant, not device state — so it is not a
candidate for anything and will never move.

## Still unknown

Stated plainly, because these matter for anyone considering writes.

1. **Flash or RAM?** Not determined. No firmware image ships with this
   installer, and the apply path is in the (undecoded) bulk-data routines.
   Whether `SetMatrix` commits to flash or only to RAM decides whether a
   malformed write is a scare or a brick. **This is the single most important
   open question.**
2. **There is a `Restore` / `Reset` button in the UI**
   (`tc_restore`, `tc_reset`, `tc_msg5` "Are you sure you want to
   restore?"), but its protocol command was **not** traced. Whether a
   defaults-restore exists on the wire is unknown. Do not assume an escape
   hatch until this is confirmed.
3. The field layout of the 520-byte config blob. Partly resolved (#6): the
   general block at `[8..0x99]` is now mapped. The remaining un-decoded span
   is `[0x99..0x207]`.
4. Why the dongle answers `0x21` but stalls `0x11` / `0x31`, while the
   wired mouse answered `0x11`. Needs a wired-vs-dongle comparison.
5. The meaning of the special FunIDs `0x5b`/`0x5c` and the `0xf0`–`0xfa`
   group.

## Risk notes

Analysis was read-only and **nothing was transmitted to the mouse**. For
anyone continuing to the write path:

- `Apply_24G` reads the config back before writing. Copy that behaviour.
- The write is four commands (`general`, `PSD`, `macro`, `matrix`), not one
  blob. A partial apply is possible and is presumably survivable.
- The `0xa5` at matrix offset `0x57` is a terminator, and `0xa5`/`0x5a` are
  the classic sentinel pair. Getting this byte wrong is exactly the failure
  mode to avoid.
- `cmd 0x75` (DFU) does not appear anywhere in this application's command
  set. That is reassuring but not a guarantee: the bootloader entry point
  lives in device firmware, not in the host app.

Not affiliated with or endorsed by Redragon. Reverse engineering of vendor
software supplied by the vendor for hardware the user owns.