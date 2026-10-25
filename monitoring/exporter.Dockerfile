# Image for exporter.py (Sprint 4). Built by monitoring/docker-compose.yml
# with the repo root as build context, so it can copy the src/ scripts that
# exporter.py imports (digest.py -> notify.py -> scanner.py).
FROM python:3.13-alpine

# pyyaml is the only third-party package on exporter.py's import path.
RUN pip install --no-cache-dir pyyaml==6.0.3

WORKDIR /app
COPY src/exporter.py src/digest.py src/notify.py src/scanner.py ./

# Run as a normal user. /data holds the state file (a Docker volume);
# creating it here gives the new volume this user's ownership.
RUN adduser -D -H exporter && mkdir /data && chown exporter /data
USER exporter

EXPOSE 9105
CMD ["python", "exporter.py", "--listen", "0.0.0.0:9105", "--state-file", "/data/exporter-state.json"]
