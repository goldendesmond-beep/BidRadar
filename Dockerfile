FROM python:3.12-slim
WORKDIR /app
COPY app ./app
COPY public ./public
COPY vendor/bidpilot/LICENSE ./vendor/bidpilot/LICENSE
COPY THIRD_PARTY_NOTICES.md ./
COPY data/seed.json data/sources.json ./data/
ENV ZERO_COST_ONLY=true BIDPILOT_HOST=0.0.0.0 BIDPILOT_PORT=8080 BIDPILOT_DB=/var/lib/bidpilot/bidpilot.sqlite3
RUN useradd --uid 10001 --create-home bidpilot && mkdir -p /var/lib/bidpilot && chown -R bidpilot:bidpilot /var/lib/bidpilot /app
USER bidpilot
VOLUME ["/var/lib/bidpilot"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/summary',timeout=4)"
CMD ["python", "-m", "app.server"]
