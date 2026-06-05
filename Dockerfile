FROM python:3.11-slim-bookworm

LABEL maintainer="Toc Consulting <tarek@tocconsulting.fr>"
LABEL description="AWS Lambda security scanner with multi-framework compliance mapping"
LABEL version="1.0.1"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY lambda_security_scanner/ ./lambda_security_scanner/

RUN pip install --no-cache-dir . \
    && mkdir -p /app/output

ENV LAMBDA_SCANNER_OUTPUT_DIR=/app/output

# Run as root so the documented credential mount (-v ~/.aws:/root/.aws:ro)
# and env-var credentials both work. A non-root user cannot read a host
# ~/.aws/credentials file (uid mismatch and 0600 permissions), which
# silently broke --profile based runs.

ENTRYPOINT ["lambda-security-scanner"]
CMD ["--help"]
