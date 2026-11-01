# Netdata Resource Anomaly — Incident Response Playbook

Standard response steps for resource/performance anomaly alarms raised by
Netdata (or similar monitoring). Steps are grouped by severity so the
triage agent can retrieve only the section matching the alarm it is
handling.

## Severity: CRITICAL

1. Check the affected host's current CPU, memory, disk I/O, and load
   average immediately.
2. Determine whether the resource exhaustion is caused by a runaway
   process, a traffic spike, or a stuck job, and identify the top
   consumer.
3. Scale out (add capacity) or fail over to a standby instance if the
   service is customer-facing and degraded.
4. Restart the offending process/service only after capturing diagnostic
   data (stack dump, logs) if a restart is required to restore service.
5. Notify the on-call engineer within 15 minutes if the host is
   production-critical.

## Severity: HIGH

1. Review the resource trend over the last hour to confirm whether the
   condition is worsening or stabilizing.
2. Correlate the spike with recent deployments, cron jobs, or batch
   processes.
3. Prepare a scale-up or restart plan but hold off executing unless the
   trend continues to worsen.
4. Notify the service owner.

## Severity: MEDIUM

1. Add the host/metric to a short-term watch list.
2. Check whether the threshold itself needs tuning (recurring false
   positives at this level).
3. Log the anomaly for the weekly capacity-planning review.

## Severity: LOW / UNKNOWN

1. Log the alarm for trend analysis; no immediate action required.
2. Re-check if the condition clears on its own within the next
   monitoring interval.

## General Notes

- Never restart a production service without checking for in-flight
  transactions or jobs.
- All scaling and restart actions must be logged with timestamp,
  engineer, and justification.
