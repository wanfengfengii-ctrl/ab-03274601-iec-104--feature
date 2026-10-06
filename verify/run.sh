#!/usr/bin/env bash
# 一次性核验：单元测试 -> 等待 API 健康 -> 合法/非法会话冒烟。
# 在 compose 的 verify 容器中执行时 API_URL=http://api:8080；
# 在没有 Docker 的开发机上执行时，会自动在本地随机端口启动 API 实例。
set -euo pipefail

cd "$(dirname "$0")/.."

API_URL="${API_URL:-http://api:8080}"

echo "==> [1/3] 代码单元测试"
python3 -m unittest discover -s tests -v

probe() {
    python3 - "$1" <<'PY'
import sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1] + "/health", timeout=1) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
}

LOCAL_PID=""
cleanup() {
    if [ -n "$LOCAL_PID" ]; then
        kill "$LOCAL_PID" 2>/dev/null || true
        wait "$LOCAL_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

if ! probe "$API_URL"; then
    echo "==> $API_URL 不可达，改为本地启动 API 实例进行冒烟"
    FREE_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
    PORT="$FREE_PORT" HOST=127.0.0.1 python3 app/main.py >/tmp/verify-api.log 2>&1 &
    LOCAL_PID=$!
    API_URL="http://127.0.0.1:$FREE_PORT"
fi

echo "==> [2/3] 等待 API 健康检查通过 ($API_URL)"
for _ in $(seq 1 30); do
    if probe "$API_URL"; then
        echo "    API 已就绪"
        break
    fi
    sleep 0.5
done
if ! probe "$API_URL"; then
    echo "API 健康检查失败" >&2
    [ -n "$LOCAL_PID" ] && cat /tmp/verify-api.log >&2 || true
    exit 1
fi

echo "==> [3/3] 合法 / 非法会话冒烟"
API_URL="$API_URL" python3 verify/smoke.py

echo "==> 全部核验通过"
