# Redragon M910-KS "Ranger Lite" -- protocol findings

Target: Redragon Ranger Lite M910-KS wireless gaming mouse
Host: Omarchy (Arch), kernel 7.2.5-3-omarchy, Wayland/Hyprland

## TL;DR

The mouse is **Sino Wealth** (`258a`), not Holtek. Every Redragon Linux
project found online targets Holtek (`04d9`), which is why none of them
match this model. The wireless receiver and the wired mouse are two
different USB products that share a vendor protocol.

**No existing open-source tool reads this mouse's battery.** libratbag has
a `sinowealth` driver with full DPI/RGB/button support but zero battery
code, and no device file for either `002f` or `002e`. Finding the battery
command is genuinely new reverse engineering.

## USB identities

| VID:PID | Product | Interfaces | hidraw |
|---|---|---|---|
| `258a:002f` | SINOWEALTH 2.4G Wireless Receiver | 1.0 mouse, 1.1 vendor | `hidraw0`, `hidraw1` |
| `258a:002e` | SINOWEALTH Wired Gaming Mouse | 1.0 mouse, 1.1 vendor | `hidraw4`, `hidraw5` |

Both have `bcdUSB 0x0110`, 8-byte interrupt endpoints, `bMaxPacketSize0 8`.

### Wired vs wireless

Plugging the mouse in via USB-C makes it enumerate as `258a:002e`, a
*different* product from the `258a:002f` dongle. Both expose the same
vendor interface. The wired path is preferable for protocol work because
there is no radio sleep to fight -- see "Known risk" below.

Note: interface `1-2:1.1` initially reported `waiting_for_supplier` and
did not get a hidraw node; it bound a moment later as `hidraw5`. If you
replug and only see one node, wait a second and re-check.

## Vendor HID interface (usage page 0xFF00)

Interface 1.1 on both products. Report descriptor (213 bytes, identical
on both) declares:

| Report ID | Data size | On-wire | Notes |
|---|---|---|---|
| 1 | 6 | 7 | Boot keyboard (modifiers/keys) |
| 2 | 16 | 17 | Consumer page: media keys |
| 5 | 7 | 8 | **CMD channel** |
| 6 | 7 | 8 | Short variant |
| 7 | 7 | 8 | Short variant |
| 8 | **519** | **520** | **CONFIG blob** |

The 520-byte total is the tell: libratbag defines
`SINOWEALTH_CONFIG_REPORT_SIZE 520` (including the report ID byte) and
`SINOWEALTH_CMD_SIZE 6` (data after the ID). This device's numbers match
exactly, so the config blob layout from libratbag's `driver-sinowealth.c`
should transfer.

### Transport

All vendor traffic uses **HID feature reports** over the control endpoint
(`SET_FEATURE` / `GET_FEATURE`), not interrupt pipes. From libratbag:

```
SET_FEATURE(report_id=5, [0x05, cmd, 0, 0, 0, 0])
sleep ~90ms
GET_FEATURE(report_id=5, 8)   -> reply
```

For config reads the sequence is `SET_FEATURE(id=5, [0x05, cmd])` then
`GET_FEATURE(id=6 or 4, 520)` -- the command goes in on one report ID and
the payload comes back on another.

## Command IDs known so far

**CONFIRMED on this device** by probing `258a:002e` (wired), firmware
`2876`. Note `2876` matches the `2876` in the official driver filename
`Redragon_M910KS_Setup_v1.0_2876_BY1064_P3104.rar`, which independently
confirms we are talking to the real thing.

### The command-support oracle

This is the key trick for enumerating the command space. Send
`SET_FEATURE [0x05, cmd, 0, 0, 0, 0]`, then `GET_FEATURE` on each report
ID and look at byte 1 of the reply:

- **byte 1 echoes the command id** -> the command is supported
- byte 1 is `0x01` instead -> the command is *not* supported and the device
  falls back to the firmware-version reply

**Check every report ID, not just 0x05.** Commands reply on either the CMD
report (`0x05`, short) or the config report (`0x08`, 520 bytes), and both
echo the command id in byte 1. An early version of the sweeper only checked
`0x05` and consequently reported `0x11` and `0x21` as unsupported even
though they work fine -- they answer on `0x08`.

Observed:

| cmd | replies on | verdict |
|---|---|---|
| `0x01` firmware | `0x05` | supported -> `'2876'` |
| `0x02` profile | `0x05` | supported -> profile 0 |
| `0x11` get config | `0x08` | supported -> 520-byte blob |
| `0x21` | `0x08` | supported (returned *button* data here) |
| `0x1a` debounce | `0x05` | NOT supported |
| `0x1b` LOD/snap | `0x05` | NOT supported |
| `0x12` get buttons | -- | no reply / empty |

This matters because **the wired reference mice libratbag was built against
support different commands than this dongle does** -- `0x1a` and `0x1b` are
dead here. The command set must be discovered empirically, not copied.

### Config blob (cmd `0x11`, report id `0x08`, 520 bytes)

First bytes observed: `08 11 00 00 00 00 00 00 64 13 01 15 00 02 00 04 ...`

- `[0]` report id `0x08`, `[1]` echoed command
- `[8]` = `0x64` = 100 -- **sensor field, and a prime battery candidate**
  (libratbag puts the sensor id at byte 8; `0x64` is not a known PMW id, so
  on this device that offset may mean something else)
- `[9]` = `0x13` -> report_rate nibble `3` = 500 Hz, flags nibble `1`
- `[10]` = `0x01` -> dpi_count nibble / active_dpi nibble

Byte 8 being exactly `100` is suggestive but almost certainly the sensor or a
config default -- the mouse is not necessarily at 100%. **This needs a
differential test**: read the blob, change state (charge the mouse, let it
drain, toggle wireless), read again, and diff. The byte that moves is the
battery.

### Commands from libratbag, NOT confirmed here

| Cmd | Purpose | Status on `002e` fw 2876 |
|---|---|---|
| `0x01` | Firmware version | confirmed -> `2876` |
| `0x02` | Get/set active profile | confirmed (get) |
| `0x11`/`0x21`/`0x31` | Get config, profiles 1/2/3 | `0x11`,`0x21` reply; `0x31` untested |
| `0x12`/`0x22`/`0x32` | Get buttons | `0x12` empty; `0x22` empty |
| `0x1a` | Debounce | NOT supported (falls back to 0x01) |
| `0x1b` | Lift-off + angle snapping | NOT supported |
| `0x30` | Write macro | write -- never sent |
| `0x75` | Enter DFU | **never sent** |

## Command table — vendor-verified

Recovered from Redragon's own Windows control panel by static analysis. See
[GUI-ANALYSIS.md](GUI-ANALYSIS.md) for method and evidence. The app talks
to this chipset through a class named `CDrvBY24G`, and its entire command
surface is:

| cmd | meaning | direction | app address |
|---|---|---|---|
| `0x01` | general / firmware info | read | `0x40a2f0` |
| `0x11` | get config, profile 1 | read | `0x40a3c0` |
| `0x21` | get config, profile 2 | read | `0x40a3c0` |
| `0x31` | get config, profile 3 | read | `0x40a3c0` |
| `0x12` | set key matrix, profile 1 | **write** | `0x40a680` |
| `0x22` | set key matrix, profile 2 | **write** | `0x40a680` |
| `0x32` | set key matrix, profile 3 | **write** | `0x40a680` |
| `0x30` | set macro | **write** | `0x40a760` |
| `0x90` | read power (battery + USB-connected) | read | `0x40a590` |
| `0x92` | write PSD (device signature) | **write** | `0x40a4d0` |

**This resolves the sweep's blind spot.** `0x12`, `0x22` and `0x30` were
previously recorded as unsupported or empty. They are implemented — they
are *write* commands, which do not echo, so the byte-1 echo oracle could
never detect them. `0x31` was recorded "untested" rather than unsupported
and is in fact the profile-3 read.

Notably the command set is *smaller* than libratbag's wired reference mice
(no `0x1a` debounce, no `0x1b` LOD/angle-snap). Buttons, DPI, lighting,
polling rate and macros are all reached through `0x11/0x21/0x31` (the 520-
byte config blob) plus `0x12/0x22/0x32` (the key matrix) — there is no
per-setting command at all.

### Transport, independently confirmed

The app's `SendCmd` builds exactly what `tools/sinowealth.py` already sends:

```
SET_FEATURE(report 0x05, [0x05, CMD, a1, a2, a3, a4, 0, 0])
    3 attempts, Sleep(200) between
```

The 5-byte command struct is `{cmd, a1, a2, a3, a4}`. The 200 ms settle and
3 retries are the likely reason that polling faster returns "asleep".

The driver also opens three handles -- `m_hCmd`, `m_hData`, `m_hNotify` --
i.e. separate command, bulk-data and notify interfaces. Our reader only
uses the first.

### `SetMatrix` packet

```
[0x00]  command            0x12 / 0x22 / 0x32
[0x02]  0x50  (80)         payload length
[0x07..0x56] 80 bytes      key matrix payload
[0x57]  0xa5               terminator
```

`0x07 + 0x50 = 0x57` is why byte 2 reads as a length rather than a constant.
This is the most likely origin of the lone `0xa5` at offset `0x97` of the
config blob: the matrix is nested inside the larger blob. Strong inference,
not observed on the wire.

## Command table (empirically confirmed, `258a:002e` fw `2876`)

Full sweep of `0x01`..`0xFF` found exactly these:

| cmd | replies on | body (after report id + cmd echo) | interpretation |
|---|---|---|---|
| `0x01` | `0x05` | `32 38 37 36 00 00` | firmware = `2876` |
| `0x02` | `0x05` | `01 00 00 00 00 00` | active profile, 1-based (`01` = profile 0) |
| `0x11` | `0x08` | 518 bytes | **config blob**, see below |
| `0x21` | `0x08` | 4-byte button records | button map (`11 01`,`11 02`,`11 04`,`41 01`,`50 07`,...) |
| `0x90` | `0x05` | `10 02 00 00 00 00` | **UNKNOWN -- leading battery candidate** |
| `0x75` | -- | -- | DFU; deliberately never sent |

Everything else in `0x01`..`0xFF` falls back to the `0x01` firmware reply,
i.e. is not implemented on this device.

Notably **absent** compared to libratbag's wired reference mice: `0x12`
(get buttons), `0x1a` (debounce), `0x1b` (LOD/angle-snap), `0x22`, `0x31`,
`0x32`. So button/DPI settings are exposed here only through `0x11`/`0x21`.
The command set is genuinely different from the mice libratbag targets --
it had to be discovered, not copied.

### `0x90` -- the current battery lead

An otherwise-unexplained command that replies on the short CMD report with
`10 02 00 00 00 00`. Candidates for the two leading bytes:

- `0x10` = 16 -- could be a battery percentage, a state enum, or a flag
- `0x02` = 2 -- could be a charging flag, channel/slot, or device index

This has to be settled by **observing it change**, not by reading it once:
poll `0x90` while plugging in the USB-C cable, unplugging, and toggling
the power switch. A field that moves with charging state is the battery.
`tools/watch.py` does exactly this.

## BATTERY FOUND: `cmd 0x90` -- read it from the DONGLE

`cmd 0x90` replies on the short CMD report `0x05`. The reply is 8 bytes:

```
offset  0     1     2     3     4  5  6  7
        05    90    11    57    00 00 00 00
              |----- cmd echo
                    |     |------ battery percent (0x57 = 87)
                    |------------ link type: 0x10 wired / 0x11 wireless
```

Observed across devices:

| device | reply[2] | reply[3] | meaning |
|---|---|---|---|
| wired `258a:002e` | `0x10` | `0x02` | link = direct USB |
| dongle `258a:002f` | `0x11` | `0x00` -> `0x57` | link = wireless, **87%** |

**The battery must be read from the dongle (`258a:002f`).** The wired mouse
answers `0x90` too, but without wireless status; it is not where the charge
level lives.

### Sleeping behaviour -- important

When the mouse has been idle, the receiver returns `reply[3] = 0x00`. The
value populates a second or two after the device wakes (movement, cable
insert, button press). A reader must therefore:

- poll on an interval rather than read once,
- treat `reply[3] == 0x00` as **"unknown / asleep"**, not as "0%",
- retry until a non-zero value arrives.

### Status: CONFIRMED

Validated in live use: the bar was observed going **100% -> 99%** during
ordinary use, and a direct read returned `0590116300000000` (`0x63` = 99)
on the wireless link. A field that decrements in normal use is a fuel
gauge, not a coincidental status byte.

A full discharge to `0` is not required, and may never be reachable: mice
commonly reserve the bottom few percent and shut down before reporting a
literal `0`. The real risk is not a wrong number but a **stale** one -- a
dead mouse stops answering, so the receiver has nothing new to report and a
naive reader would sit frozen on its last value. `tools/history.py`
therefore tracks the age of the last good reading and escalates:

| age of last live reading | bar shows | meaning |
|---|---|---|
| < 15 min | `M 99%` | fresh |
| 15 min - 6 h | `M?`, age in tooltip | stale, approximate |
| > 6 h | `M!!` "no signal ... may be flat" | device not reporting |
| never | `M--` | no reading yet |

Thresholds are tunable via `REDRAGON_BATTERY_STALE` and
`REDRAGON_BATTERY_FLAT` (seconds). A merely *sleeping* mouse does not
trigger this -- only the absence of a live reading over time does.

## Config blob (cmd `0x11`, report id `0x08`, 520 bytes)

Bytes `0x00`..`0x9f` carry data; `0xa0`..`0x207` are all zero, so the real
struct is ~160 bytes:

```
0000  08 11 00 00 00 00 00 00 64 13 01 15 00 02 00 04
0010  00 08 00 0c 00 10 00 00 ...
...
0090  00 00 00 01 02 ff 00 00 a5 ...
00a0  00 00 ... (all zero to 0x207)
```

- `[0]` report id `0x08`, `[1]` echoed command `0x11`
- `[8]` = `0x64` = 100 -- libratbag places the *sensor id* here, but no PMW
  id equals `0x64`, so on this device that offset may mean something else.
  Suspected battery candidate, not yet proven; must be shown to move.
- `[9]` = `0x13` -> report_rate nibble `3` = 500 Hz, flags nibble `1`
- `[10]` = `0x01` -> dpi_count / active_dpi nibbles
- `[11]` = `0x15` -> bitmask, plausibly disabled DPI slots
- A lone `a5` appears at offset `0x97` -- see GUI-ANALYSIS.md: this is
  almost certainly the key-matrix terminator (`0xa5` at matrix offset
  `0x57`), nested inside the larger blob.

## What is NOT known

**The battery field** is settled: `cmd 0x90` reply byte 3 on the dongle,
confirmed live. The vendor app reads the same command and parses it as
`ReadPower: nPower=%d, nUsbConnect=%d` -- so reply byte 2 is very likely the
charging / USB-connected flag that `tools/battery.py` currently leaves as
`None`. Worth a diff against charging state to confirm.

Still open:

1. **Flash or RAM.** Not determined, and the most important one: it decides
   whether a malformed write is a harmless scare or a dead mouse. No
   firmware image ships with the installer and the bulk-data routines were
   not fully decoded.
2. **Whether a defaults-restore exists on the wire.** The GUI has a
   `Restore` / `Reset` button (`tc_restore`, `tc_reset`, `tc_msg5`), but the
   command behind it was not traced. Do not assume an escape hatch.
3. **The 520-byte blob field layout**, beyond the nested key-matrix region.
   The general block is assembled by app routines at `0x40b750` / `0x40b9f0`
   that were not decoded. Byte `[8] = 0x64` remains unexplained.
4. Meaning of the special FunIDs `0x5b` / `0x5c` and the `0xf0`-`0xfa`
   group (probably the dedicated DPI / RGB / profile / fire buttons).

## Known risks

1. **Writes can brick these devices.** Multiple Sino Wealth GitHub issues
   document drivers soft-bricking mice by writing a malformed config blob.
   OpenRGB disabled its Sinowealth driver over exactly this. Mitigation:
   stay read-only until the blob format is fully understood, back up the
   config before any write, and never send `0x75`.

2. **Wireless sleep limits readback.** A 2.4 GHz mouse sleeps when idle and
   may only answer the receiver when recently moved. The RE guide notes you
   must poll every ~250-300 ms to wake the link. A battery indicator may
   therefore be "best effort, possibly stale" rather than live. Using USB-C
   wired mode for protocol discovery sidesteps this.

## Environment notes

- No `pip`, `pyusb`, or `hidapi` on this host. `tools/sinowealth.py` uses
  only `ctypes`/`fcntl` from the standard library, so nothing needs
  installing.
- `/dev/hidraw*` is root-only by default; see `docs/SETUP.md`.
- `usbmon` is available as a module but debugfs needs root. `wireshark-cli`
  is in the pacman repo if a raw capture is ever needed.
- Chromium is present, so a WebHID monkeypatch capture of the vendor's web
  control center is viable if one exists for this model.

## Suggested order of work

Steps 1-4 are done. The vendor app has been unpacked and its command table
extracted -- see [GUI-ANALYSIS.md](GUI-ANALYSIS.md). Remaining work, in
order of value:

1. **Decode the bulk-data routines** at `0x40b750` / `0x40b9f0`, which
   build the "general" block that `Apply_24G` writes. This closes most of
   the 520-byte layout and is pure static analysis -- zero hardware risk.
   A real decompiler (`GHIDRA_INSTALL_DIR`) would make this routine work.
2. **Diff `cmd 0x90` reply byte 2 against charging state** to confirm it is
   `nUsbConnect`, then fill in `tools/battery.py`'s `charging` field.
   Read-only, one cable insert.
3. **Trace the GUI's Restore button** to find out whether a defaults-reset
   exists on the wire. Worth knowing before any write, not after.
4. Only then consider writing DPI / lighting from Linux -- see the risk
   notes in GUI-ANALYSIS.md.