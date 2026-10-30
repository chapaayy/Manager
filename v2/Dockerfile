FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY v2/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && groupadd -r xppn && useradd -r -g xppn -u 10001 xppn && mkdir -p /data && chown xppn:xppn /data
COPY --chown=10001:10001 v2 /app/v2
# Installer clones with umask 077; preserve least privilege while making code readable by the non-root runtime.
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn","v2.app:app","--host","0.0.0.0","--port","8000","--workers","1"]
