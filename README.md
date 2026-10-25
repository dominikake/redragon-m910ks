# Redragon M910-KS Ranger Lite — Linux battery indicator

Reverse-engineered battery indicator for the **Redragon Ranger Lite
M910-KS** wireless gaming mouse.

## The short version

The mouse is **Sino Wealth** (`258a:002f` dongle / `258a:002e` wired), not
Holtek. Every Redragon Linux tool on GitHub targets Holtek `04d9` devices,
which is why none of them support this model. libratbag has a
`sinowealth` driver but **no battery support and no device file** for
either USB ID.

Battery reading (reverse-engineered and **confirmed** in live use):

```
SET_FEATURE(report 0x05, [0x05, 0x90, 0, 0, 0, 0])
GET_FEATURE(report 0x05, 8)
  -> [2] = link type (0x10 wired / 0x11 wireless)
     [3] = battery percent, 0x00 while the mouse sleeps
```

The charge level lives on the **2.4 GHz dongle**, not the wired mouse.
Observed `0x57` = 87%, and the bar was seen going 100% -> 99% in normal use.

Standard library only — no pip, pyusb, or hidapi.

## Staleness (why a dead mouse won't lie)

A flat or out-of-range mouse stops answering, so the receiver has nothing
new to report. Rather than freezing on the last number, the bar escalates
with the age of the last live reading:

| age | shows | meaning |
|---|---|---|
| < 15 min | `M 99%` | fresh |
| 15 min – 6 h | `M?` + age in tooltip | stale, approximate |
| > 6 h | `M!!` "no signal … may be flat" | not reporting |
| never | `M--` | no reading yet |

Tune with `REDRAGON_BATTERY_STALE` / `REDRAGON_BATTERY_FLAT` (seconds).
A *sleeping* mouse never triggers this -- only the passage of time does.

View the discharge curve:

```sh
python3 tools/plot.py            # ASCII chart + verdict
python3 tools/plot.py --csv      # export for a real graph
```

## Quick start

```sh
# 1. Grant access (one-time; see docs/SETUP.md, then log out/in)
sudo usermod -aG input "$USER"
sudo tee /etc/udev/rules.d/99-redragon-m910ks.rules >/dev/null <<'EOF'
KERNEL=="hidraw*", ATTRS{idVendor}=="258a", ATTRS{idProduct}=="002f", MODE="0660", GROUP="input", TAG+="uaccess"
KERNEL=="hidraw*", ATTRS{idVendor}=="258a", ATTRS{idProduct}=="002e", MODE="0660", GROUP="input", TAG+="uaccess"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=hidraw

# 2. Read the battery
python3 tools/battery.py --retries 5

# 3. Confirm it tracks charging state
sudo python3 -B tools/confirm.py --seconds 300 --every 10 --log captures/battery-log.txt
```

## Omarchy bar indicator

Already wired into `~/.config/omarchy/shell.json` as a `type: "command"`
module running `~/.config/omarchy/bar/scripts/omarchy_bar_module.py`
(refreshes every 60s, click re-reads). It shows a mouse glyph plus percent,
greyed when asleep. Restore the previous bar with:
`cp ~/.config/omarchy/shell.json.bak-battery ~/.config/omarchy/shell.json`.

## Background refresh (systemd timer)

`./install.sh` copies the tools to `~/.local/share/redragon-m910ks/` and
enables a user timer that re-reads every 2 minutes:

```sh
./install.sh                 # install + enable timer
./install.sh --no-timer      # files only, no timer
./install.sh --uninstall     # remove timer and units
systemctl --user status redragon-battery.timer
```

Why 2 minutes: the mouse auto-sleeps after ~1 minute idle, so polling
faster mostly returns "asleep" and burns USB traffic. Polling *does not*
wake a sleeping mouse — forcing the link awake to get a faster reading
would drain the very battery being measured. The timer keeps the bar fresh
while you're actively using the mouse, and keeps the USB read off the bar's
critical path.

## UPower bridge (optional)

Publishes an `org.freedesktop.UPower.Device` on the session bus plus a
status file for scripts:

```sh
python3 tools/upower_bridge.py            # serve (Ctrl-C to stop)
cat "$XDG_RUNTIME_DIR/redragon-m910ks-battery.txt"
```

## Layout

| Path | What it is |
|---|---|
| `tools/sinowealth.py` | Minimal HID transport. Standard library only. |
| `tools/safety.py` | **Read-only policy.** Refuses writes; makes `0x75` unreachable. Self-check: `python3 tools/safety.py`. |
| `tools/battery.py` | **Main reader.** Charge % from the dongle via cmd `0x90`. |
| `tools/history.py` | Persistent reading history + staleness tracking. |
| `tools/plot.py` | Render the discharge curve / CSV export from history. |
| `tools/confirm.py` | Timestamped sampling harness. |
| `tools/omarchy_bar_module.py` | Waybar-style JSON for the Omarchy bar. |
| `tools/upower_bridge.py` | D-Bus UPower.Device bridge + status file. |
| `tools/sweep.py` | Command-ID enumeration via the echo oracle. |
| `tools/watch.py` | Poll one command and report changes. |
| `tools/probe.py` | Read-only protocol probes. |
| `tools/sniff.py` | Passive listener for spontaneous reports. |
| `tools/verify_vendor_cmds.py` | Read-only check of the vendor command table. |
| `tools/profile_diff.py` | Map the config blob using the mouse's own buttons. Sends nothing. |
| `tools/re_pe.py` | Minimal PE reader: sections, exports, VA↔offset. Offline. |
| `tools/re_cmds.py` | Recovers the SendCmd/GetCmd call sites and the command byte before each. Offline. |
| `tools/re_fn.py` | Prints one function from an objdump disassembly. Offline. |
| `docs/PROTOCOL.md` | Full findings: wire format, command table, unknowns. |
| `docs/GUI-ANALYSIS.md` | RE of Redragon's Windows control panel: command table, write sequence. |
| `docs/SETUP.md` | udev rule, group setup, troubleshooting. |
| `install.sh` | Installs tools + the systemd user timer. |
| `systemd/` | `redragon-battery.service` / `.timer` units. |

## Design constraints

- **Zero dependencies.** No pip/pyusb/hidapi; `fcntl`/`ctypes` only.
- **Read-only until proven otherwise.** *No tool in this repo sends a config,
  matrix, macro or PSD write.* The full command set is known
  ([`docs/GUI-ANALYSIS.md`](docs/GUI-ANALYSIS.md)) and the write half is
  deliberately unused.
- **Sleep-aware.** The mouse sleeps when idle and returns `0x00`; every
  consumer treats that as *unknown*, never as *0%*.

### Safety policy

Sino Wealth devices have a documented history of soft-bricking from malformed
writes — OpenRGB disabled its driver over exactly this. That history, plus
one device and no spare, is why the write half of the protocol is understood
but untouched.

Two things are worth being precise about:

- **Whether settings live in flash or RAM is not ours to choose.** The device
  commits its own changes to storage the moment you press a button on the
  mouse. That is safe, because the value is one the device considers valid.
  The risk being avoided is *us* crafting 520 bytes and hoping.
- **Recovery has to be reachable without Windows.** A mouse that is
  recoverable in principle, but only by running Redragon's Windows updater,
  is not recoverable for a Linux-only user. Functionally a brick. See #9.

Command `0x75` (DFU) is never sent and has no override path. Writes require
an explicit `allow_write=True` at the call site, so any write shows up in a
diff. Both are enforced in code by `tools/safety.py`, which every send routes
through — not by convention.

```sh
python3 tools/safety.py                             # policy self-check, no hardware
python3 tools/verify_vendor_cmds.py --guard-test    # adversarial, sends nothing
```

Lifting the policy requires establishing a recovery path that does not depend
on Windows (#9) — not merely a successful read.

## Status

- [x] Identify chipset + USB IDs (`258a:002f` / `258a:002e`)
- [x] Decode vendor HID descriptor; match libratbag's Sinowealth wire format
- [x] Dependency-free HID transport
- [x] Confirm transport (firmware `2876` matches official driver filename)
- [x] Command-support oracle (byte 1 echoes the command id)
- [x] Enumerate the command space (`0x01`,`0x02`,`0x11`,`0x21`,`0x90`)
- [x] **Locate battery: cmd `0x90`, byte 3, on the dongle**
- [x] Confirm reading live (observed 100% -> 99% in normal use)
- [x] Omarchy bar indicator + UPower bridge built
- [x] Stale/flat detection so a dead mouse never shows a frozen percent
- [x] Persistent history + discharge-curve plotter
- [x] **Reverse engineer the Windows control panel** — full vendor command
      table, config layout and write sequence (`docs/GUI-ANALYSIS.md`)

Not affiliated with or endorsed by Redragon. Reverse engineering for
personal use on hardware the user owns.