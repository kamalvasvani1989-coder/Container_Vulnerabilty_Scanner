# Local Jenkins for the vulnerability scanner (Sprint 2: Jenkins integration).
# LOCAL LAB USE ONLY. See docker-compose.yml for why.
#
# Adds what the pipeline needs on top of the official Jenkins LTS image:
#   - Python 3 + venv   : runs scanner.py, report.py, notify.py
#   - Pango libraries   : WeasyPrint needs them to draw the PDF report
#   - Docker CLI        : builds the image under test (the daemon is
#                         Docker Desktop on the host, via the mounted socket)
#   - Trivy             : pinned to the same version as GitHub Actions
FROM jenkins/jenkins:lts-jdk21

USER root

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip \
      libpango-1.0-0 libpangoft2-1.0-0 \
      ca-certificates curl gnupg \
 && rm -rf /var/lib/apt/lists/*

# Docker CLI only, from Docker's official repository.
RUN install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
 && chmod a+r /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin \
 && rm -rf /var/lib/apt/lists/*

# Same pinned Trivy version as .github/workflows/scan.yml. Bump both together.
ARG TRIVY_VERSION=0.76.0
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"

USER jenkins
