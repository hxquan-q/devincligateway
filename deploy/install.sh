#!/usr/bin/env bash
# devin-gateway VPS 安装脚本 (Ubuntu/Debian)
# 用法: 把 deploy/ 目录整个 scp 到 VPS 后, 在其内执行 bash install.sh
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/devin-gateway

echo "[1/4] 复制程序文件 -> $DEST"
sudo mkdir -p "$DEST"
sudo cp "$DIR"/deep_client.py "$DIR"/deep_gateway.py "$DIR"/ci31.bin "$DEST"/
[ -f "$DIR"/credentials.toml ] && sudo cp "$DIR"/credentials.toml "$DEST"/

echo "[2/4] Python venv + 依赖"
python3 -m venv "$DEST"/.venv 2>/dev/null || sudo apt-get install -y python3-venv
"$DEST"/.venv/bin/pip install -q fastapi uvicorn

echo "[3/4] 凭据 -> ~/.devin/"
mkdir -p "$HOME"/.devin
SRC_TOML="${DEVIN_TOML:-$DEST/credentials.toml}"
[ -f "$SRC_TOML" ] && cp "$SRC_TOML" "$HOME"/.devin/credentials.toml \
  && echo "  credentials.toml -> ~/.devin/"
cp "$DEST"/ci31.bin "$HOME"/.devin/ci31.bin

echo "[4/4] systemd 服务"
sudo cp "$DIR"/devin-gateway.service /etc/systemd/system/
# 在 service 文件里注入 GATEWAY_API_KEY (交互输入, 留空则保持占位符)
read -r -p "设置 GATEWAY_API_KEY (对外鉴权, 回车跳过): " KEY
if [ -n "${KEY}" ]; then
  sudo sed -i "s/change-me-long-random/$KEY/" /etc/systemd/system/devin-gateway.service
fi
sudo systemctl daemon-reload
sudo systemctl enable --now devin-gateway
sleep 2
systemctl --no-pager -l status devin-gateway | head -8
echo
echo "完成。本机自检: curl http://127.0.0.1:8788/healthz"
