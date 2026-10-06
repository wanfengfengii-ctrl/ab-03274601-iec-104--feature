"""容器健康检查：探测本进程 /health。"""

import os
import sys
import urllib.request

port = os.environ.get("PORT", "8080")
url = f"http://127.0.0.1:{port}/health"
try:
    with urllib.request.urlopen(url, timeout=3) as resp:
        sys.exit(0 if resp.status == 200 else 1)
except Exception:
    sys.exit(1)
