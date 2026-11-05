FROM python:3.12-alpine

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apk upgrade --no-cache && \
    addgroup -S app && adduser -S -G app app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app app.py .
USER app
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "30", "app:app"]
