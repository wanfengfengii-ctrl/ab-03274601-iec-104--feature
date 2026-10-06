# IEC 60870-5-104 会话取证核验服务
# 零第三方依赖：仅用 Python 3 标准库，便于离线构建。

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    HOST=0.0.0.0

WORKDIR /srv

# 复制服务代码、测试与一次性核验脚本，使同一镜像可承担 verify 任务。
COPY app/ ./app/
COPY tests/ ./tests/
COPY verify/ ./verify/

EXPOSE 8080

# 容器内置健康检查，供 compose / 编排器使用。
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD ["python", "/srv/app/healthcheck.py"]

CMD ["python", "app/main.py"]
