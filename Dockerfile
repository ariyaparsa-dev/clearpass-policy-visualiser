FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV VISUALISER_DATA_DIR=/data

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install \
    --no-cache-dir \
    -r requirements.txt

COPY . .

RUN groupadd \
        --gid 10001 \
        visualiser \
    && useradd \
        --uid 10001 \
        --gid visualiser \
        --no-create-home \
        --shell /usr/sbin/nologin \
        visualiser \
    && mkdir -p /data \
    && chown visualiser:visualiser /data

USER visualiser

EXPOSE 5000

CMD ["python", "server.py"]