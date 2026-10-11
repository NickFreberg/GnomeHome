# Runbook: zero-packet test before the first real scan

**Why:** the plan's go-live gate for the protected-asset list (Protected assets, step 9; risk R-12).
While a full scan runs, you capture every packet your Mac sends to the work laptop. **Zero packets
is a pass.** Do this before the first real scan on the Mac, again on the Pi, and again any time the
laptop's MAC, reserved IP, or the protected list changes.

> Do this together with Claude the first time. Don't start a real scan on your own before this
> test passes.

## What you need first

- [ ] `config/protected_assets.yaml` has the laptop's **real** MACs (Wi-Fi and dock) and its reserved IP
- [ ] `just protected-check` says the list is OK, with no example-values warning
- [ ] `config/gnomehome.toml` has your real LAN in `scan_targets` and the right `interface` (usually `en0`)
- [ ] `just scan-dry` ends with "No problems found"
- [ ] The work laptop is **on and connected** to home Wi-Fi, so a mistake would show up
- [ ] Two Terminal windows, both in `~/gnomehome` (`cd ~/gnomehome`)

## Steps

### 1. Collect three values (window 1)

```
MY_IP=$(ipconfig getifaddr en0); echo "$MY_IP"
ROUTER_IP=$(route -n get default | awk '/gateway/ {print $2}'); echo "$ROUTER_IP"
PROTECTED="$(uv run gnomehome protected-filter)"; echo "$PROTECTED"
```

- `MY_IP` is your Mac's address on the home network.
- `ROUTER_IP` is the router. It serves as the *control*: the scan must reach it, which proves the capture works.
- `PROTECTED` is a tcpdump filter built from your protected list, like
  `host <laptop IP> or ether host <laptop MAC> ...`.

If any of them prints nothing, stop and ask. (No `en0`? Check `interface` in the config.)

### 2. Start the capture (window 1)

```
sudo tcpdump -i en0 -n -w data/zero-packet-test.pcap "src host $MY_IP and (($PROTECTED) or host $ROUTER_IP)"
```

What this does: `tcpdump` records packets. `sudo` is needed because watching the network
interface requires administrator rights, and macOS will ask for your password. The filter keeps only packets
**sent by your Mac** that are addressed to a protected device or to the router. `-w` saves them to a
file instead of printing them. It prints `listening on en0` and then waits. Leave it running.

### 3. Run the full scan (window 2)

```
just scan
```

It asks for your password (nmap needs sudo too) and takes a few minutes. Wait for `Scan N done`.

If the scan prints `STOPPED by the protected-asset guard`, that's the guard doing its job. Still finish
steps 4 and 5, then tell Claude what it printed.

### 4. Stop the capture (window 1)

Press **Control and C**. tcpdump prints how many packets it captured.

### 5. Check the result (window 1)

```
tcpdump -r data/zero-packet-test.pcap -n "$PROTECTED" | wc -l
tcpdump -r data/zero-packet-test.pcap -n "host $ROUTER_IP" | wc -l
```

The first number is packets sent to the protected device. The second is packets sent to the router.

| Protected | Router | Result |
| --- | --- | --- |
| `0` | more than `0` | **PASS.** The scan ran, reached the router, and sent nothing to the laptop |
| `0` | `0` | **Inconclusive.** The capture saw nothing at all (wrong interface or wrong IP). Fix it and repeat |
| more than `0` | any | **FAIL.** Stop. Don't scan again until it's fixed |

On a FAIL, see what was sent with:

```
tcpdump -r data/zero-packet-test.pcap -n -e "$PROTECTED"
```

The usual cause is a laptop that isn't at its reserved IP: an ARP line like
`who-has <ip> tell <your Mac>` for an IP that isn't in the exclude file. Check the router's DHCP
reservation and the laptop's MAC (randomized-MAC setting), update `config/protected_assets.yaml`,
then repeat the whole test.

### 6. Clean up

The capture contains your router's address, so don't share it. It's in `data/`, which git ignores.
tcpdump created it as root, so deleting it needs sudo:

```
sudo rm data/zero-packet-test.pcap
```

Note the date and the PASS in your own records. Don't paste the IPs anywhere public.

## On the Pi (Monday onward)

Same test, run on the Pi itself: use `eth0` instead of `en0`, and get the Pi's IP with
`hostname -I`. In step 3, run the scan the way the timer will:
`sudo systemctl start gnomehome-scan.service`. Run the test before enabling any scan timer
(`deploy/pi/README.md`, step 7).
