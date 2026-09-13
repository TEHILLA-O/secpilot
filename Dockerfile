FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap curl openssl dnsutils whois \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY policies ./policies
COPY toolpacks ./toolpacks
COPY docs ./docs

RUN pip install --no-cache-dir .

# Container stays unprivileged. Scope and config bind-mount at runtime.
USER nobody
ENTRYPOINT ["secpilot"]
CMD ["--help"]
