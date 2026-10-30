FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY manager/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt && groupadd -g 12001 app && useradd -u 12001 -g app -M app
COPY manager /app/manager
COPY agent /app/agent
COPY bootstrap /app/bootstrap
COPY legacy /app/legacy
RUN mkdir -p /data && chown app:app /data
USER app
EXPOSE 8000
CMD ["uvicorn", "manager.app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
