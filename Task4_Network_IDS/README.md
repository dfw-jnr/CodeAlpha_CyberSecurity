# Task 4 - Network Intrusion Detection with Suricata

This lab project configures Suricata as a passive network IDS. It includes local alert rules, a synthetic PCAP generator for repeatable offline review, and a Python watcher that turns EVE JSON alerts into a small human-review queue.

The rules only use the `alert` action. The watcher does not block traffic, change firewall settings, or send data to a third party. Use the live-capture instructions only on a device/network you own or are authorized to monitor.

## What is included

- `local.rules` - four local signatures for HTTP probes of `/.env` and `/wp-admin`, a reserved training DNS name, and a thresholded TCP SYN scan pattern.
- `generate_lab_pcap.py` - creates a small synthetic capture containing an HTTP request for `/.env`; it sends no traffic over a network.
- `watch_alerts.py` - follows Suricata `eve.json`, prints alert summaries, and appends recommended triage steps to a JSON Lines queue.
- `response_playbook.md` - explains how to triage and respond to an alert.

## Requirements

Recommended lab: a recent Ubuntu Linux virtual machine with Python 3, Suricata, and (for optional terminal filtering) `jq`.

Install Suricata using the official instructions for your Ubuntu release. A current Ubuntu installation can use the Suricata stable PPA:

```bash
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata jq
```

The exact package version depends on the OS repository. Confirm the installed version with `suricata --build-info`.

## Offline lab run

From the repository root, run these commands inside the Ubuntu VM:

```bash
mkdir -p Task4_Network_IDS/logs
python3 Task4_Network_IDS/generate_lab_pcap.py --output Task4_Network_IDS/lab_test.pcap
sudo suricata -T -c /etc/suricata/suricata.yaml -S "$PWD/Task4_Network_IDS/local.rules"
sudo suricata -c /etc/suricata/suricata.yaml -r Task4_Network_IDS/lab_test.pcap -S "$PWD/Task4_Network_IDS/local.rules" -l "$PWD/Task4_Network_IDS/logs"
python3 Task4_Network_IDS/watch_alerts.py --eve Task4_Network_IDS/logs/eve.json --queue Task4_Network_IDS/logs/triage_queue.jsonl --from-start
```

The synthetic capture should produce a local alert for the HTTP `/.env` request. Suricata reads the PCAP in offline mode; the generator itself creates a file and does not send packets. `-S` loads the supplied local signatures exclusively for this focused lab run. It does not load a commercial or community ruleset.

## Continuous passive monitoring

1. Identify the interface in the VM with `ip -br link`.
2. Create the log directory: `mkdir -p Task4_Network_IDS/logs`.
3. Start Suricata on the authorized interface, replacing `ens33` with the actual interface name:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i ens33 -S "$PWD/Task4_Network_IDS/local.rules" -l "$PWD/Task4_Network_IDS/logs"
```

4. In a second terminal, follow alerts and write triage records:

```bash
python3 Task4_Network_IDS/watch_alerts.py --eve Task4_Network_IDS/logs/eve.json --queue Task4_Network_IDS/logs/triage_queue.jsonl
```

Press `Ctrl+C` to stop the watcher and Suricata. Live capture permissions depend on the OS and installation. For visibility into traffic between other devices, the sensor must receive a copy of that traffic (for example, through a configured mirror/SPAN port or network TAP); attaching a VM to an ordinary virtual switch usually shows only traffic delivered to that VM.

## Read alerts directly

```bash
jq 'select(.event_type == "alert") | {timestamp, src_ip, src_port, dest_ip, dest_port, proto, alert}' Task4_Network_IDS/logs/eve.json
```

## Scope and limitations

These local signatures demonstrate rule configuration; they are not a complete threat-detection ruleset. An IDS alert is a lead for investigation, not proof of malicious activity. HTTP rules can only inspect visible HTTP application data, not encrypted HTTPS paths. The DNS rule uses the reserved `.invalid` namespace and is for a lab signal only. The synthetic PCAP demonstrates offline parsing, while continuous monitoring requires a supported sensor interface and appropriate network visibility.

## References

- Suricata, [Quickstart guide](https://docs.suricata.io/en/latest/quickstart.html)
- Suricata, [Rule format](https://docs.suricata.io/en/latest/rules/intro.html)
- Suricata, [HTTP rule keywords](https://docs.suricata.io/en/latest/rules/http-keywords.html)
- Suricata, [EVE JSON output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
- Suricata, [Command line options](https://docs.suricata.io/en/latest/manpages/suricata.html)
