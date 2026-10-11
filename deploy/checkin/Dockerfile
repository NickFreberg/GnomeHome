# The weekly AI check-in job (FR-18) for Azure Container Apps.
# Build from the repository root:
#   docker build -f deploy/checkin/Dockerfile -t gnomehome-checkin .
# The agent uses the Python standard library only, so the image holds no
# third-party packages, no secrets, and no data. It signs in with the job's
# managed identity at run time.
FROM python:3.12-slim

RUN useradd --system --uid 10001 --no-create-home checkin
WORKDIR /app
COPY python/gnomehome /app/gnomehome
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER checkin
ENTRYPOINT ["python", "-I", "-m", "gnomehome.agent.run"]
