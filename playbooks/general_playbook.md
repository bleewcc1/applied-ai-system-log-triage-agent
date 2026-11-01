# General / Unrecognized Log — Incident Response Playbook

Fallback response steps for a log that doesn't match the Snort or Netdata
signal keywords (log_type "unknown") but is still readable, valid text.
Used so an unrecognized log still gets a specific, retrieved response
instead of a generic "insufficient data" message.

## Severity: CRITICAL

1. Treat as a potential incident even though the source system couldn't
   be identified automatically - don't dismiss it on format alone.
2. Identify the originating system/application and its owner.
3. Preserve the raw log and any surrounding context before it rotates out.
4. Escalate to the on-call lead for manual classification within 15 minutes.

## Severity: HIGH

1. Identify the originating system/application and check whether it has
   a dedicated playbook that should have matched instead.
2. Preserve the log for manual review.
3. Notify the relevant service owner within one hour.

## Severity: MEDIUM

1. Log the event for trend analysis and manual review during business hours.
2. Check whether this log source should be added to the agent's known
   signal keywords so future occurrences classify automatically.

## Severity: LOW / UNKNOWN

1. Log for trend analysis; no immediate action required.
2. No further action unless additional related events appear.

## General Notes

- This playbook exists because an unrecognized log is not the same as a
  corrupted one: the content is readable, it just didn't match a known
  log family. Retrieval still happens here - nothing is fabricated.
