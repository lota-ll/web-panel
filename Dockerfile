# EcoCharge Web Portal - Dockerfile
# For CTF/Educational purposes only

FROM python:3.11-slim

LABEL maintainer="CTF Lab"
LABEL description="Intentionally vulnerable web portal for EVSE CTF"

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    flask==3.0.0 \
    flask-sqlalchemy==3.1.1 \
    pyjwt==2.8.0 \
    requests==2.31.0 \
    gunicorn==21.2.0

# Copy application
COPY app.py .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Expose port
EXPOSE 80

# Environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=development
ENV CITRINE_API=http://192.168.20.20:8080
ENV CITRINE_GRAPHQL=http://192.168.20.20:8090/v1/graphql

# Run application
# Using Flask dev server for CTF (debug mode enabled for vulnerabilities)
CMD ["python", "app.py"]

# For production-like setup (still vulnerable):
# CMD ["gunicorn", "--bind", "0.0.0.0:80", "--workers", "2", "app:app"]
