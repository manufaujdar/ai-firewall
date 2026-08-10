FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
RUN pip install --no-cache-dir .
RUN useradd --create-home firewall && mkdir -p /app/data && chown -R firewall:firewall /app/data
USER firewall
EXPOSE 8080
CMD ["uvicorn", "ai_firewall.main:app", "--host", "0.0.0.0", "--port", "8080"]

