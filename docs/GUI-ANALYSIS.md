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
objdump -d vendor/gui/app/OemDrv.exe > vendor/OemDrv.asm

# 3. Recover the command table from the call sites.
python3 tools/re_cmds.py vendor/OemDrv.asm

# 4. Read one function. objdump loses instruction alignment in data regions
#    near 0x40b000 and never recovers, so restarting at a known function
#    boundary is the only way to read that code.
python3 tools/re_fn.py vendor/OemDrv.asm 0x40b010 --calls
```

`re_cmds.py` recovers every call site into `SendCmd`/`GetCmd` and prints the
immediates written into the argument struct just before each one:

```
503866 instructions parsed, 6 call site(s) into SendCmd/GetCmd
look-back window: 60 instruction(s)

call site    fn       command bytes written just before
--------------------------------------------------------------
0x0040a325   SendCmd  0x40a320=0x01
0x0040a41d   SendCmd  0x40a3ed=0x11  0x40a3f9=0x21  0x40a409=0x31
0x0040a553   GetCmd   0x40a4fe=0x00  0x40a510=0x11  0x40a51c=0x21  0x40a528=0x31  0x40a538=0x92
0x0040a5cd   SendCmd  0x40a5c0=0x90
0x0040a727   GetCmd   0x40a6ae=0x00  0x40a6c0=0x12  0x40a6cc=0x22  0x40a6d8=0x32  0x40a6eb=0x50  0x40a6f0=0xa5
0x0040a7fb   GetCmd   0x40a7a5=0x30  0x40a7aa=0x02  0x40a7af=0x00
```

This is **not** a command list on its own. The tool reports every `movb`
immediate in the contiguous run before the call, and only the first one is
the command byte — the rest are packet fields. Of the values above, `0x50`
and `0xa5` are the `SetMatrix` length/terminator pair, `0x02` and `0x00` are
`SetMacro` header bytes, and `0x00` is a length. Reading the command ids off
the first column of each row gives:

```
0x40a325 SendCmd  0x01
0x40a41d SendCmd  0x11 0x21 0x31
0x40a553 GetCmd   0x11 0x21 0x31 0x92
0x40a5cd SendCmd  0x90
0x40a727 GetCmd   0x12 0x22 0x32
0x40a7fb GetCmd   0x30
```

Note that `0x12`, `0x22`, `0x32` and `0x30` — the four the echo-oracle sweep
could not see — fall straight out of the disassembly. All six call sites stop
at a real `int3` boundary rather than the window edge, so nothing is being
attributed across a function boundary.

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

## The general block — `0x40b750` and `0x40b9f0`

These two are the "General(Save)" half of `Apply_24G`. They do not build a
packet from scratch: `GetConfig` has already filled the buffer with the
device's current block, and each packer overwrites only the fields it owns.

```
GetConfig(profile)       0x40a3c0   0x11/0x21/0x31, reads 0x207 bytes
  packer 1               0x40b750   DPI levels, report rate, level colours
  packer 2               0x40b9f0   LED mode table
SetGeneral(profile, buf) 0x40a4d0   0x11/0x21/0x31, writes 0x92 bytes
```

`SetGeneral` copies exactly **`0x92` = 146 bytes** out of the buffer
(`push $0x92` at `0x40a52d`, then the `memcpy` at `0x40a53d`). So the
general block is reply bytes **`[0x08..0x99]`**, and `esi` inside both packers
is the block base, not the reply base. Two writes pin that down against the
captured blob:

| instruction | writes | blob offset | capture |
|---|---|---|---|
| `movb $0x64,(%esi)` at `0x40b75d` | `esi[0x00]` | `[0x08]` | `0x64` |
| `movb $0xa5,0x90(%esi)` at `0x40ba2f` | `esi[0x90]` | `[0x98]` | `0xa5` |

Because the buffer came from `GetConfig`, **any byte neither packer writes
is echoed back unchanged**. This answers the long-standing "what is byte 9"
question: nothing writes `esi[1]`, in either packer. It is whatever the
device returned — `0x13` on the wired and the dongle read alike — not a
field this code understands. It survives a save because the vendor app
round-trips the whole 146-byte block, not because it means anything.

### Packer 1 — `0x40b750` (DPI, report rate, level colours)

The profile record is `0x9e4 + profile * 0x62c` (`0x40b7a4`); per-level
records are 16 bytes apart from `ebp + 0x24`:

| offset | field |
|---|---|
| `+0x00` | X DPI value (an entry from the `DPISET` ladder) |
| `+0x04` | Y DPI value, used only when the dual-axis flag is set |
| `+0x08` | level colour, RGB + pad |
| `+0x0c` | `0` = level in use, non-zero = disabled |

Writes, in order:

| address | target | value |
|---|---|---|
| `0x40b75d` | `esi[0x00]` | `0x64`, constant |
| `0x40b7b0`–`0x40b7de` | — | report-rate comparand against `0x125`/`0x250`/`0x500`/`0x1000` |
| `0x40b7e8` | `esi[0x02]` bits 0–3 | rate code 1–4 |
| `0x40b7ed`–`0x40b7ff` | `esi[0x05..0x24]` | zero: both DPI tables |
| `0x40b820`–`0x40b864` | `esi[0x05+2i]` | X DPI, packed |
| `0x40b843`–`0x40b85c` | `esi[0x15+2i]` | Y DPI, packed, only if dual-axis |
| `0x40b8c1` | `esi[0x03]` | enabled count (low nibble), active position (high nibble) |
| `0x40b8cc`/`0x40b8d2` | `esi[0x02]` bit 7 | dual-axis flag |
| `0x40b8d6`–`0x40b9e5` | `esi[0x25..]` | per-level RGB triples |

Two things here were previously guessed wrong.

**The DPI values are ladder indices, not DPI counts, and the ladder is not a
uniform 250-step scale.** The comparands for report rate are `0x125`,
`0x250`, `0x500`, `0x1000` — the vendor's decimal labels `125/250/500/1000`
typed as hex, which is why they look like nonsense integers. The DPI side
goes through a lookup (`0x40e5e0`) over the `DPISET` ladder in `Cfg.ini`,
`250,500,750,1000,1200,1500,1750,2000,2250,2400,2750,3000,…`, and the wire
value is the **1-based index into that ladder**:

| level | DPI | `DPISET` index | wire |
|---|---|---|---|
| 1 | 500 | 1 | `0x0002` |
| 2 | 1000 | 3 | `0x0004` |
| 3 | 2000 | 7 | `0x0008` |
| 4 | 3000 | 11 | `0x000c` |
| 5 | 4000 | 15 | `0x0010` |

`index + 1` reproduces all five captured values exactly; `DPI / 250` happens
to agree for these five and diverges above 2000, where the ladder switches
to 500 steps. `tools/decode_general_block.py` uses the ladder.

**The two DPI tables are packed, not slotted.** The cursor only advances for
levels whose flag is `0` (`add $0x2,%ebx` at `0x40b864` sits inside the
enabled branch), so five enabled levels occupy ten bytes and the remaining
slots stay zero. That is why `[0x0d..0x1c]` looks like a fixed table on this
device and would not on a mouse with fewer levels enabled.

`esi[0x15..0x24]` — blob `[0x1d..0x2c]` — is the **Y-axis DPI table**. It is
zero here only because bit 7 of `[0x0a]` is clear: this sensor exposes a
single DPI axis. The bytes were previously listed as "zero, unknown"; they
are a second packed table.

Level colours are packed the same way — one RGB triple per *enabled* level,
starting at `esi[0x25]` — so five enabled levels write blob `[0x2d..0x3b]`
and stop. The capture also has triples at `[0x3c..0x44]` (cyan, white,
orange). Those were **not written by this app**: they are echoed from the
device. They match nothing in `Cfg.ini` (whose `DC=` default has five
colours), so the device's factory image carries more level colours than the
vendor tool can express.

`movb $0x0,0x9e(%esi)` at `0x40b78d` is a **dead store**: `esi[0x9e]` is
blob `[0xa6]`, well past the 146-byte body, so it never reaches the device.
It only makes sense if this routine once serialised a longer block.

### Packer 2 — `0x40b9f0` (the LED mode table)

This is `LedOpt1..LedOpt10` from `Cfg.ini`, whose own comment names the five
fields: `;Speed  Light  Direct  Random  ColorNum`. The app parses each
`LedOpt%d` with `sscanf`-style code at `0x4401ec` and stores the five values
as dwords, with an in-use flag at `-0xc`. The packer then serialises them in
a fixed, non-uniform layout:

| blob offset | field |
|---|---|
| `0x45` | active LED mode (`esi[0x3d]`, see below) |
| `0x46` | mode 1 byte: high nibble `Light`, low nibble `Speed` |
| `0x47` | mode 1: `(Random == 3)` |
| `0x48` | mode 2 byte |
| `0x49..0x4b` | mode 2: one colour |
| `0x4c` | mode 3 byte |
| `0x4d` | mode 3: colour count |
| `0x4e..0x62` | mode 3: up to 7 colours |
| `0x63` | mode 4 byte (low nibble only) |
| `0x64` | mode 5 byte |
| `0x65` | mode 6 byte |
| `0x66..0x83` | mode 6: 10 colour slots |
| `0x84` | mode 7 byte |
| `0x85..0x8a` | mode 7: two colours |
| `0x8b` | mode 8 byte |
| `0x8c` | mode 9 byte |
| `0x8d` | mode 10 byte (low nibble only) |
| `0x8e..0x97` | logo LED options + colour — **echoed**, not written here |
| `0x98` | `0xa5` constant |
| `0x99` | echoed `0x00` |

Colours are 3 bytes on the wire and 4 bytes in the app's record, which is
why the copy loop advances the destination by 3 and the source by 4
(`0x40baa0`).

The `LedOpt` identification is not a guess — the per-mode colour counts
match `Cfg.ini` exactly:

| mode | `Cfg.ini` | blob |
|---|---|---|
| 2 | `LedOpt2=0,1,0,0,1` | 1 colour at `[0x49]` |
| 3 | `LedOpt3=1,0,0,0,7` | count `7` at `[0x4d]`, 7 colours |
| 6 | `LedOpt6=0,0,0,0,5` | 5 colours at `[0x66]` (+1 duplicate, below) |
| 7 | `LedOpt7=0,0,0,0,2` | 2 colours at `[0x85]` |

Mode 3's seven colours are a rainbow — red, green, blue, magenta, yellow,
orange, cyan — and the last is followed by mode 4's byte at `[0x63]`.

Three quirks in this packer, all observed rather than inferred:

1. **Mode 6 can gain an extra colour.** If `Cfg.ini`'s `WuYU` option is
   non-zero (it is `1` by default) the packer duplicates the last colour
   (`0x40bc14`–`0x40bc31`), so `LedOpt6` with 5 colours puts 6 triples on
   the wire. That is the only reason `[0x77..0x79]` repeats yellow.
2. **Mode 3 has room for seven colours, not eight.** The count is capped at
   8 (`0x40ba5b`) but the field only runs to `esi[0x5a]`; an eighth triple
   would overwrite modes 4–6. The app's own default is 7, so it never hits
   this.
3. **The last entry is never written.** The loop runs to `ebp == N` and
   skips the body for that entry (`0x40bacc`–`0x40bad2`), where `N` is the
   number of leading `LedOpt` records with the in-use flag set. With all ten
   defined, modes 1–9 are written and mode 10 is left as read. `[0x8d] =
   0x02` is therefore device state, not app output.

`esi[0x3d]` (blob `[0x45]`) is derived, not copied: the stored active index
is incremented and wraps to `0` when it equals `N-1` (`0x40ba1c`–`0x40ba2c`).
On this device it is `1`.

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
| 0 | `0x10`, `0xa0`, `0xa1` | 6 | `0x02` | right button |
| 1 | `0x11`, `0xa2`, `0xa3` | 6 | `0x01` | left button |
| 2 | `0x12`, `0xa4`, `0xa5` | 6 | `0x04` | middle button |
| 3 | `0x5b`, `0x5c` | 6 | `0x08` | forward (mouse bit `0x08`) |
| 4 | `0xf0` | 1 | `0x01` | left button |
| 5 | `0xf1` | 1 | `0x02` | right button |
| 6 | `0xf2` | 1 | `0x04` | middle button |
| 7 | `0xf3` | 1 | `0x08` | forward (mouse bit `0x08`) |
| 8 | `0xf4` | 1 | `0x10` | back (mouse bit `0x10`) |
| 9 | `0xf5` | 4 | byte 1 as-is | scroll, size 4 |
| 10 | `0xf6` | 4 | byte 1 negated | scroll, size 4 |
| 11 | `0xf7` | 3 | byte 1 negated | key action, size 3 |
| 12 | `0xf8` | 3 | byte 1 as-is | key action, size 3 |
| 13 | `0xf9` | 2 | byte 1 negated | delay / step, size 2 |
| 14 | `0xfa` | 2 | byte 1 as-is | delay / step, size 2 |
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

### #8 — FunID → action names, and the 6-byte encoding

The context-menu handler at `0x43b9b8` resolves an assignable button FunID to
the `tc_*` label the UI displays, through the byte table at `0x43bd74` (FunID −
`0x11`, range-checked against `0x9f`) and the jump table at `0x43bcd8`. The
resolved labels are:

| FunID | action (`tc_*`) | handler | UI category |
|---|---|---|---|
| `0x11` | Left button (`tc_click`) | `0x43b9d4` | mouse |
| `0x12` | Middle button (`tc_middle`) | `0x43b9e5` | mouse |
| `0x13` | Right button (`tc_menu`) | `0x43b9f6` | mouse |
| `0x14` | Forward (`tc_forward`) | `0x43ba07` | mouse |
| `0x15` | Back (`tc_back`) | `0x43ba18` | mouse |
| `0x16` | Double Click (`tc_dbclick`) | `0x43ba29` | mouse |
| `0x17` | Three Click (`tc_three`) | `0x43bc4e` | mouse |
| `0x18` | R-Double Click (`tc_rdbclick`) | `0x43ba3a` | mouse |
| `0x21`–`0x28` | Media Player / Play-Pause / Stop / Prev / Next / Vol+ / Vol− / Mute | `0x43ba4b`–`0x43bac2` | media |
| `0x30`–`0x39` | Web-media actions (Favorites, Calculator, Explorer, Search, Home, Email, Web Forward, Web Stop, Web Refresh, Web Favorites) | `0x43bb06`–`0x43bba8` | web |

FunIDs `0x19`–`0x20` and `0x29`–`0x30` resolve to the default handler, i.e.
they are not UI-labelled mouse/media actions and fall through to the generic
keyboard/media/combo path. The hardware family `0xf0`–`0xfa` is named from the
same label strings and the builder: `0xf0`–`0xf4` are the physical buttons
(left/right/middle/forward/back, mouse bits `0x01`/`0x02`/`0x04`/`0x08`/`0x10`)
and `0xf5`–`0xf9` are scroll-up, scroll-down and the key-down/key-up/delay
macro events.

**#8 therefore named the special cases.** `0x11`, `0xa2`, `0xa3` are *left
button* and `0x12`, `0xa4`, `0xa5` are *middle button* in the builder's case
1 and 2; `0x10`, `0xa0`, `0xa1` and `0xf1` are *right button*; `0xf3` is
*forward* and `0xf4` is *back* per the physical-button family. The 6-byte encoding
is the three-byte key-list record the builder emits — first byte
`(size << 4) | nibble`, second byte the parameter (default `0x01`), third byte
the resolved action — with `size` taken from the handler (`6` for the button
cases, `1` for the hardware-button cases, `2`–`4` for the scroll/event cases
that resolve through the lookup at `0x5a2040`).

**#8 is therefore implemented**: every special-cased FunID the builder and
the context menu between them had in common is now named, and the encoding
the builder's handlers write is stated in one place instead of being
re-derived from the two tables each time. The remaining unknowns are not
about naming — they are about what the second and third bytes *mean* and
which default-path FunIDs map to the Keyboard / Media / Combo panes, and
those are write-side questions for #11 rather than mapping questions for
#8.

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

Offsets `0x000`–`0x09f` shown contiguously; the blob is 520 bytes. The
general block the packers own runs from `[0x08]` to `[0x99]`; everything from
`[0x9a]` onward is zero in both captures and belongs to other commands (see
below). Raw copy kept out of git; re-read it any time with
`python3 tools/verify_vendor_cmds.py`, and diff it against
`captures/vendor-0x21-dongle.bin`.

### General block, field by field

Payload offsets are blob offsets minus 8; the packer registers index from 8.
Confidence is marked per row, and every offset here is hex.

| blob | payload | meaning | confidence |
|---|---|---|---|
| `[0x00..0x07]` | — | HID header: report id `0x08`, echoed cmd, 6 zero bytes | confirmed |
| `[0x08]` | `0x00` | `0x64` = 100, hard-coded constant | confirmed static |
| `[0x09]` | `0x01` | **echoed, never written** (`0x13` on both reads) | confirmed static |
| `[0x0a]` | `0x02` bits 0–3 | report rate: 1=125, 2=250, 3=500, 4=1000 Hz | confirmed static |
| `[0x0a]` | `0x02` bit 7 | second (Y) DPI axis present | confirmed static |
| `[0x0b]` | `0x03` low nibble | number of enabled DPI levels | confirmed static |
| `[0x0b]` | `0x03` high nibble | active level, 1-based among enabled levels | confirmed static |
| `[0x0c]` | `0x04` | echoed, never written (`0x00`) | confirmed static |
| `[0x0d..]` | `0x05..` | X DPI table: one u16 per enabled level, `ladder index + 1` | confirmed static |
| `[0x1d..0x2c]` | `0x15..` | Y DPI table: same encoding, only when bit 7 above is set | confirmed static |
| `[0x2d..]` | `0x25..` | one RGB triple per enabled level | confirmed static |
| `[0x45]` | `0x3d` | active LED mode (derived from the stored index) | strong static |
| `[0x46..0x8d]` | `0x3e..` | LED mode table, `LedOpt1..10` | confirmed static |
| `[0x8e..0x97]` | `0x86..` | logo LED options + colour, **echoed, never written** | observed |
| `[0x98]` | `0x90` | `0xa5`, hard-coded constant | confirmed static |
| `[0x99]` | `0x91` | echoed `0x00` | confirmed static |
| `[0x9a..0x207]` | — | not carried by the general-block command | confirmed static |

Both tables are **packed, not slotted**: a disabled level consumes no bytes,
so a level with flag `0` shifts everything after it. Five enabled levels put
`[0x0d..0x1c]` in use and leave the rest of the X table zero, which is exactly
what the capture shows.

**Offsets `0x0d` onward are the X DPI table**, as 16-bit little-endian values:

| offset | bytes | stored | `DPISET` index | DPI |
|---|---|---|---|---|
| `0x0d` | `02 00` | 2 | 1 | 500 |
| `0x0f` | `04 00` | 4 | 3 | 1000 |
| `0x11` | `08 00` | 8 | 7 | 2000 |
| `0x13` | `0c 00` | 12 | 11 | 3000 |
| `0x15` | `10 00` | 16 | 15 | 4000 |

Five levels, matching `DM=5`. The stored value is **one more than the
0-based index into the `DPISET` ladder** in `Cfg.ini`,
`250,500,750,1000,1200,1500,1750,2000,2250,2400,2750,3000,…`. That ladder is
*not* uniform: it runs in 250 steps to 2000, then 500 steps. `index + 1`
reproduces all five captured values; `DPI / 250` agrees only below 2250 and
is the wrong rule in general. `tools/decode_general_block.py` uses the
ladder.

> **Corrected (twice).** This table first started at offset **12** and read
> `00 02` = **512**, `1024`, `2048`, `3072`, `4096`, on the theory that "the
> device rounds each level up to the next multiple of 512". Reading one byte
> early makes each 16-bit value 256× too large. The offset was then fixed but
> the units were still described as *n*×250 DPI, which is wrong above 2000.
> The packer writes the low byte first from a cursor at `0x0d`, and the
> ladder lookup is at `0x40e5e0`.

**`0xa5` is at offset `0x98`**, a hard-coded constant written by
`movb $0xa5,0x90(%esi)` at `0x40ba2f`. It is **not** related to the
`SetMatrix` terminator.

> **Corrected.** This section previously placed `0xa5` at `0x97` and argued
> for it from `0x97 - 0x50 = 0x47`, a "constant `0x40` shift" mirroring the
> matrix arithmetic. That inference was wrong, and its stated evidence was
> not real: the hexdump above previously ended with four rows copied from a
> *different* capture, one of which was a byte-for-byte duplicate of the real
> row at `0x0060`. The blob contains exactly one `0xa5`, at `0x98`.

> **Corrected again.** `0xa5` was then described as the *last* byte of the
> 146-byte general block. It is the **second to last**: the block is
> `payload[0..0x91]`, `0xa5` is at `payload[0x90]`, and `payload[0x91]`
> (blob `[0x99]`) is an echoed `0x00`. So the block ends with the 16-bit
> value `0x00a5`, whose low byte is the constant and whose high byte is
> whatever the device returned.

`PROTOCOL.md` carried the earlier errors and has been corrected.

> **Corrected.** The region `[0x45..0x95]` was previously described as
> "dense with `0xff`, matching keys set to *Disable*", with the repeated
> `0x42` bytes read as "per-key function tags". That was wrong. It holds no
> keys at all: it is the ten-entry LED mode table from `LedOpt1..LedOpt10`,
> where `0x42` is a packed `Light`/`Speed` byte and the `0xff` runs are RGB
> components. The key matrix lives in a different command (`0x12/0x22/0x32`)
> and a different packet.

Byte `[8] = 0x64` = 100 is **explained** (#6): it is the first byte of the
general block, written as a hard-coded constant by `movb $0x64,(%esi)` at
`0x40b75d`. It is stable across the `0x11` and `0x21` reads on two different
USB products because it is a constant, not device state — so it is not a
candidate for anything and will never move.

The decode is executable: `python3 tools/decode_general_block.py BLOB`
prints every field above for a captured 520-byte reply, and
`tests/test_decode_general_block.py` pins the offsets against this exact
capture.

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
3. The field layout of the 520-byte config blob. The **general block is now
   mapped end to end**: `[0x08..0x99]`, 146 bytes, every offset accounted for
   including the two that were misread before (`[0x0a]` is the report rate, not
   an echoed byte; `[0x1d..0x2c]` is the Y-axis DPI table, not "zero, unknown").
   Nothing in `[0x9a..0x207]` is carried by the general-block command, and on
   the dongle that whole span is zero, so it cannot be mapped from a dongle
   capture. It belongs to the other three write commands (PSD, macro, matrix),
   which are still only partly traced.

   Two bytes in the mapped block are **not fields at all**: `[0x09]` and `[0x0c]`
   are echoed from the device because neither packer writes them, and
   `[0x8e..0x97]` (logo LED) is echoed for the same reason. `[0x09]` stays
   `0x13` across products because it is constant device data, not because it
   means anything to the app.

   The button-differential route is **closed** (#3). This model has no
   profile button, and DPI+/DPI−, the light-mode toggle and the report-rate
   switch emit no HID events — they are handled in firmware. Watching both
   input nodes through a prompted session, the only key that ever reached the
   host was `BTN_LEFT`; meanwhile the `0x21` blob did not move a single byte,
   and is byte-identical to the 2026-10-17 capture. The active DPI level,
   lighting mode and report rate are **not** persisted into this blob: the
   DPI table is the configured levels, not the selected one.
4. Why the dongle answers `0x21` but stalls `0x11` / `0x31`, while the
   wired mouse answered `0x11`. Needs a wired-vs-dongle comparison. The
   "cycle the profile with the mouse's own button" test is not possible — this
   model has no profile button; profiles are software-only, so switching them
   needs the gated write path.
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