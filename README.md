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
| `docs/PROTOCOL.md` | Full findings: wire format, command table, unknowns. |
| `docs/GUI-ANALYSIS.md` | RE of Redragon's Windows control panel: command table, write sequence. |
| `docs/SETUP.md` | udev rule, group setup, troubleshooting. |
| `install.sh` | Installs tools + the systemd user timer. |
| `systemd/` | `redragon-battery.service` / `.timer` units. |

## Design constraints

- **Zero dependencies.** No pip/pyusb/hidapi; `fcntl`/`ctypes` only.
- **Read-only.** No command writes a config blob. Sino Wealth devices have
  a documented history of soft-bricking from malformed writes (OpenRGB
  disabled its driver over this). Command `0x75` (DFU) is never sent and is
  hard-blocked in the sweep and watcher.
- **Sleep-aware.** The mouse sleeps when idle and returns `0x00`; every
  consumer treats that as *unknown*, never as *0%*.

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