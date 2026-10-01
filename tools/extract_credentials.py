#!/usr/bin/env python3
"""extract_credentials.py — 从已登录机器导出网关所需凭据 (生成 accounts.json 片段)。

在运行过 `devin auth login` 的机器上执行:
  python extract_credentials.py
输出可直接粘贴进 accounts.json 的账号条目 (api_key/api_server_url; fp_hex 可选)。
"""
import json
import os
import re
import sys

CANDIDATES = []
if os.environ.get("APPDATA"):
    CANDIDATES.append(os.path.join(os.environ["APPDATA"], "devin", "credentials.toml"))
home = os.path.expanduser("~")
xdg = os.environ.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share")
CANDIDATES += [
    os.path.join(xdg, "devin", "credentials.toml"),
    os.path.join(home, ".config", "devin", "credentials.toml"),
    os.path.join(home, ".devin", "credentials.toml"),
]

toml_path = next((p for p in CANDIDATES if os.path.exists(p)), None)
if not toml_path:
    print("未找到 credentials.toml, 请先 devin auth login")
    sys.exit(1)
txt = open(toml_path, encoding="utf-8").read()
key = re.search(r'windsurf_api_key\s*=\s*"([^"]+)"', txt).group(1)
url = re.search(r'api_server_url\s*=\s*"([^"]+)"', txt).group(1)

entry = {"name": os.environ.get("ACC_NAME", "acc1"),
         "api_key": key,
         "api_server_url": url}
if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
    entry["fp_hex"] = open(sys.argv[1], "rb").read().hex()   # ci31.bin, 可选
print(json.dumps(entry, indent=1, ensure_ascii=False))
print("\n(粘贴进 accounts.json 的 accounts 数组; api_key 即账号凭据, 注意保密)")
