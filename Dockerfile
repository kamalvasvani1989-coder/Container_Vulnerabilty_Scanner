# Image under test — deliberately based on an older release
# so the scanner finds real vulnerabilities and the gate fires.
FROM python:3.9-slim

WORKDIR /app

# A trivial "app" so the image has some content of its own.
COPY app.py .

CMD ["python", "app.py"]