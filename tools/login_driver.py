#!/usr/bin/env python3
"""login_driver.py — 自动化 `devin auth login --force-manual-token-flow`。

流程: 打印登录 URL → 你在浏览器完成登录(可用任意自动化) → 页面拿到 CLI code 写入
code.txt → 本脚本回填给 CLI → 凭据落盘 credentials.toml。

用法:
  python login_driver.py [devin路径]
  # 另开终端: echo <code> > code.txt

注意: CLI 的 TUI 在 Windows 上不走管道 stdin, 因此用 winpty 包一层 (Git for Windows 自带)。
Linux 下 TUI 通常可直接读管道, 可把 WINPTY=False。
"""
import os
import re
import subprocess
import sys
import threading
import time

DEVIN = sys.argv[1] if len(sys.argv) > 1 else (
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "bundle", "bin", "devin.exe"))
HERE = os.path.dirname(os.path.abspath(__file__))
CODE_F = os.path.join(HERE, "code.txt")
LOG_F = os.path.join(HERE, "login.log")
USE_WINPTY = os.environ.get("WINPTY", "1") == "1"

cmd = ([ "winpty", "-Xallow-non-tty"] if USE_WINPTY else []) + \
      [DEVIN, "auth", "login", "--force-manual-token-flow"]
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT)
log = open(LOG_F, "ab")
holder = {"url": None}


def reader():
    buf = b""
    while True:
        ch = p.stdout.read(1)
        if not ch:
            break
        log.write(ch)
        log.flush()
        buf += ch
        if len(buf) > 4096 or ch == b"\n":
            t = buf.decode("utf-8", "replace")
            # winpty 会按 80 列折行并夹 ANSI, 先剥再匹配
            clean = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", t).replace("\r", "").replace("\n", "")
            m = re.search(r"https://app\.devin\.ai/auth/cli/continue\?[A-Za-z0-9%&=._-]+", clean)
            if m and not holder["url"]:
                holder["url"] = m.group(0)
            buf = b""


threading.Thread(target=reader, daemon=True).start()
deadline = time.time() + 60
while not holder["url"] and time.time() < deadline:
    time.sleep(0.3)
if not holder["url"]:
    print("未取到登录 URL, 查看", LOG_F)
    sys.exit(1)
print("登录 URL:\n", holder["url"], sep="")

sent = False
deadline = time.time() + 600
while time.time() < deadline and p.poll() is None:
    if not sent and os.path.exists(CODE_F):
        code = open(CODE_F).read().strip()
        if code:
            for ch in code:
                p.stdin.write(ch.encode())
                p.stdin.flush()
                time.sleep(0.05)
            p.stdin.write(b"\r")
            p.stdin.flush()
            sent = True
            print("code 已回填", flush=True)
            os.remove(CODE_F)
    time.sleep(0.5)
try:
    p.wait(timeout=30)
except subprocess.TimeoutExpired:
    p.kill()
log.close()
print("done, exit=", p.returncode)
print("验证: devin auth status")
