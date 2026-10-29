"""Follow Suricata EVE JSON alerts and write human-review triage records."""
import argparse
import json
import time
from pathlib import Path


def recommendation(severity):
    if severity == 1:
        return "Review promptly; validate the flow and affected asset; follow the incident process."
    if severity == 2:
        return "Review the alert and related events; confirm whether the activity is expected."
    return "Record and review with surrounding context; tune the rule if it creates false positives."


def summarize(event):
    alert = event.get("alert") or {}
    try:
        severity = int(alert.get("severity", 3))
    except (TypeError, ValueError):
        severity = 3
    return {
        "timestamp": event.get("timestamp"),
        "flow_id": event.get("flow_id"),
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature", "Unlabeled Suricata alert"),
        "severity": severity,
        "source": f"{event.get('src_ip', '?')}:{event.get('src_port', '?')}",
        "destination": f"{event.get('dest_ip', '?')}:{event.get('dest_port', '?')}",
        "protocol": event.get("proto", "unknown"),
        "recommended_action": recommendation(severity),
        "automated_action": "none - analyst review required",
    }


def follow_alerts(eve_path, queue_path, from_start=False, poll_seconds=0.5):
    """Follow one EVE JSON file; no firewall or network changes are made."""
    eve_path = Path(eve_path)
    queue_path = Path(queue_path)
    if not eve_path.is_file():
        raise FileNotFoundError(f"EVE log not found: {eve_path}")
    queue_path.parent.mkdir(parents=True, exist_ok=True)

    with eve_path.open("r", encoding="utf-8") as eve_log, queue_path.open("a", encoding="utf-8") as queue:
        if not from_start:
            eve_log.seek(0, 2)
        print(f"Watching {eve_path}. Press Ctrl+C to stop.")
        while True:
            line = eve_log.readline()
            if not line:
                time.sleep(poll_seconds)
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print("Skipped one incomplete or invalid EVE JSON line.")
                continue
            if event.get("event_type") != "alert":
                continue
            record = summarize(event)
            queue.write(json.dumps(record, ensure_ascii=True) + "\n")
            queue.flush()
            print(f"[{record['timestamp']}] {record['signature']} | {record['source']} -> {record['destination']}")
            print(f"  Suggested response: {record['recommended_action']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eve", type=Path, required=True, help="path to Suricata eve.json")
    parser.add_argument("--queue", type=Path, default=Path("triage_queue.jsonl"), help="append-only human-review queue")
    parser.add_argument("--from-start", action="store_true", help="process existing records before following new ones")
    args = parser.parse_args()
    try:
        follow_alerts(args.eve, args.queue, from_start=args.from_start)
    except KeyboardInterrupt:
        print("\nStopped alert watcher.")


if __name__ == "__main__":
    main()
