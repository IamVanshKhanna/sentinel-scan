FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY sentinel_scan ./sentinel_scan
RUN pip install --no-cache-dir .

WORKDIR /scan
ENTRYPOINT ["sentinel-scan"]
CMD ["."]
