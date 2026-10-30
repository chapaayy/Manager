FROM python:3.12-alpine
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN addgroup -g 15001 xppn && adduser -D -u 10001 -G xppn agent
COPY agent.py /app/agent.py
USER 10001:15001
ENTRYPOINT ["python","/app/agent.py"]
