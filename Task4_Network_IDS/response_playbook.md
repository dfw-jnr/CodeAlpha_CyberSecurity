# Alert response playbook

This playbook is for the passive CodeAlpha Suricata lab. An alert identifies a rule match; it does not by itself confirm an intrusion.

## Triage steps

1. Read the signature, time, source and destination, protocol, and severity in the alert or `triage_queue.jsonl` record.
2. Check the relevant EVE events for the same flow ID and surrounding traffic. Confirm that the sensor observed the correct asset and that the event is not a lab exercise or approved scan.
3. Record the affected host, user/business impact, evidence location, and analyst decision in the organisation's incident process. Preserve original logs and avoid copying packet payloads unless needed and authorized.
4. For an alert that appears real, notify the responsible security or IT contact and follow the organisation's incident response plan. Contain an affected system only through an approved process.
5. After the event, tune the rule if it generated a false positive, document the change, and verify that the alert is still produced for the intended lab case.

## Response behavior in this project

`watch_alerts.py` continuously reads Suricata EVE JSON, prints alert summaries, and appends a recommended triage record to a local JSON Lines file. It performs no automated network containment. This avoids blocking legitimate traffic based on one unverified signature match and keeps the analyst in control.

For a real deployment, route alerts into an approved ticketing/SIEM workflow, protect logs from unauthorized access, define escalation ownership and response times, and obtain approval before adding any automated firewall or endpoint action.
