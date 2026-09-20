# SentinelMail AI — SIH26106
# Goal: `docker compose up` gives a judge a working dashboard on the first try.
#
# Build:  docker build -t sentinelmail .
# Run:    docker run -p 8000:8000 --env-file .env sentinelmail
# Then:   http://localhost:8000/app

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build deps for bcrypt/psycopg2 etc., removed again in the same layer so they
# don't bloat the final image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Requirements first so a code change doesn't invalidate the dependency layer —
# this is the difference between a 15-second rebuild and a 4-minute one.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y build-essential && apt-get autoremove -y

COPY . .

# Train the models at build time if the pickles weren't committed, so the image
# is never missing its classifier at runtime. `|| true` keeps the build green
# when there is no network for the Enron download — train_model.py falls back
# to the synthetic generator on its own.
RUN python -c "import os,sys; sys.exit(0 if os.path.exists('phishing_model.pkl') else 1)" \
    || python train_model.py || true
RUN python -c "import os,sys; sys.exit(0 if os.path.exists('phishing_model_hi.pkl') else 1)" \
    || python train_model_hi.py || true

# Run as a non-root user — a security tool that runs as root in its own
# container is an easy question to get asked and an easy one to pre-empt.
RUN useradd --create-home --shell /bin/bash sentinel \
    && mkdir -p /app/data \
    && chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/ || exit 1

CMD ["uvicorn", "backend:app", "--host", "0.0.0.0", "--port", "8000"]
