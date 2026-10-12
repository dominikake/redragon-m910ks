# Redragon M910-KS Ranger Lite — Setup

Everything in `tools/` talks to the mouse through `/dev/hidrawN`, which is
owned by root and unreadable by default. One udev rule fixes that.

## Devices covered

| VID:PID | What it is |
|---|---|
| `258a:002f` | Sino Wealth 2.4G wireless receiver (the dongle) |
| `258a:002e` | Sino Wealth wired gaming mouse (USB-C cable mode) |

Both expose the same vendor HID interface; `002f` is the primary target
because that is where the battery level lives.

## Install the rule (permanent, no sudo at runtime)

The bar and bridge run as your normal user, so the node must be readable by
your user. Adding yourself to `input` and giving the node `GROUP="input"`
is the reliable path:

```sh
# 1. Add yourself to the input group
sudo usermod -aG input "$USER"

# 2. Install the rule
sudo tee /etc/udev/rules.d/99-redragon-m910ks.rules >/dev/null <<'EOF'
KERNEL=="hidraw*", ATTRS{idVendor}=="258a", ATTRS{idProduct}=="002f", MODE="0660", GROUP="input", TAG+="uaccess"
KERNEL=="hidraw*", ATTRS{idVendor}=="258a", ATTRS{idProduct}=="002e", MODE="0660", GROUP="input", TAG+="uaccess"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=hidraw
```

## Log out and back in

Group membership only applies to **new** sessions. After re-login:

```sh
id | grep input          # should now list 992(input)
ls -l /dev/hidraw1              # should be root input, rw-rw----
```

Replug the receiver after re-login so udev re-applies the rule to the
freshly created node.

## Verify without sudo

```sh
python3 <repo>/tools/battery.py --retries 5
```

You should see a percentage (or "asleep" if the mouse is idle — move it).

## Interim: run with sudo

Until you re-login you can still run everything with sudo. Add `-B` so
Python does not write a root-owned `__pycache__`:

```sh
sudo python3 -B <repo>/tools/battery.py --retries 5
```

## Troubleshooting

- **Still "permission denied" after re-login:** the group change needs a
  fresh login, and the dongle must be replugged. Check
  `udevadm info -a -n /dev/hidraw1` for the applied rule.
- **Group applied but not to you:** confirm `id` lists `input`.
- **`waiting_for_supplier` on interface 1.1:** the second interface can lag a
  moment after plug-in. Wait a second and re-check `lsusb`; it binds shortly
  after and a second hidraw node appears.
- **Stale root-owned pycache:** if a `sudo` run ever created
  `tools/__pycache__` owned by root, your normal runs may fail to refresh
  the `.pyc`. Remove it:
  `sudo rm -rf <repo>/tools/__pycache__`