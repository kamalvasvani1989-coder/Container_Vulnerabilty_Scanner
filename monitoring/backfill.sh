#!/usr/bin/env bash
# Sprint 4: load the scan history into Prometheus, so the dashboard shows
# trends from before the monitoring stack was started.
#
# Run with the stack up (Prometheus needs some live data first):
#   bash monitoring/backfill.sh
#
# What it does:
#   1. exporter.py --backfill replays every scan in the GitHub and Jenkins
#      artifacts (same counting code as the live exporter) and writes the
#      history, ending just before live data began, to the exporter volume.
#   2. Stops Prometheus (its storage must not change during the import).
#   3. promtool imports the history into Prometheus' storage.
#   4. Starts Prometheus again and deletes the temporary history file.
# Safe to run again: identical samples are merged, nothing is counted twice.
# The live exporter and its state file are not touched.

set -euo pipefail
cd "$(dirname "$0")"

compose() { docker compose -f docker-compose.yml "$@"; }

# Named volumes get the compose project name ("vuln-monitoring") as prefix.
EXPORTER_VOLUME=vuln-monitoring_exporter_data
HISTORY=history.om
PROMETHEUS_STOPPED=no

cleanup() {
    if [ "$PROMETHEUS_STOPPED" = yes ]; then
        echo "Starting Prometheus again..."
        compose start prometheus >/dev/null
    fi
    compose run --rm --no-deps exporter rm -f "/data/$HISTORY" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "1/4 Replaying the scan history from GitHub and Jenkins artifacts..."
compose run --rm --no-deps exporter python exporter.py --backfill "/data/$HISTORY"

echo "2/4 Stopping Prometheus..."
compose stop prometheus
PROMETHEUS_STOPPED=yes

echo "3/4 Importing the history into Prometheus storage..."
compose run --rm --no-deps \
    -v "$EXPORTER_VOLUME:/backfill:ro" \
    --entrypoint promtool \
    prometheus tsdb create-blocks-from openmetrics --max-block-duration=24h \
    "/backfill/$HISTORY" /prometheus

echo "4/4 Starting Prometheus and removing the temporary file..."
compose start prometheus
PROMETHEUS_STOPPED=no

echo "Done. Refresh the Grafana dashboard (Last 30 days) to see the history."
