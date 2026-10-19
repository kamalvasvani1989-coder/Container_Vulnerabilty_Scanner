# Image under test — the "application" this pipeline protects.
# Kept on a current, minimal base so it passes the policy gate.
# To demo the gate firing, change FROM to python:3.9-slim on a
# throwaway branch and open a PR — the scan check will block it.
FROM python:3.13-alpine

WORKDIR /app

# A trivial "app" so the image has some content of its own.
COPY app.py .

CMD ["python", "app.py"]
