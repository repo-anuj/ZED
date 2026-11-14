#!/usr/bin/env bash
# ZED Deployment Assistant
# Provides 4 deployment paths: Systemd (Local Daemon), Docker, LAN Exposure, Cloud Tunnel

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "======================================================================"
echo "  🚀 ZED DEPLOYMENT ASSISTANT"
echo "  Zero-day Endpoint Detection & Response System"
echo "======================================================================"
echo "Choose your deployment target:"
echo "  [1] Systemd Background Service (Runs on boot as Linux Mint daemon)"
echo "  [2] Docker Container (Isolated deploy with Docker Compose)"
echo "  [3] Expose on Local Network / Wi-Fi (Access from phones/laptops on LAN)"
echo "  [4] Free Cloud / Remote Public URL (Cloudflare Tunnel for Teacher)"
echo "  [5] Cloud Platform Guide (Render / Railway / Cloud VM)"
echo "  [0] Exit"
echo "----------------------------------------------------------------------"
read -p "Select option [0-5]: " choice

case $choice in
  1)
    echo ""
    echo "[*] Setting up ZED as a persistent systemd service..."
    echo "[*] Command to install:"
    echo "    sudo cp $DIR/zed.service /etc/systemd/system/zed.service"
    echo "    sudo systemctl daemon-reload"
    echo "    sudo systemctl enable --now zed.service"
    echo ""
    read -p "Do you want to run these commands now? (requires sudo) [y/N]: " run_sudo
    if [[ "$run_sudo" =~ ^[Yy]$ ]]; then
      sudo cp "$DIR/zed.service" /etc/systemd/system/zed.service
      sudo systemctl daemon-reload
      sudo systemctl enable --now zed.service
      echo "[+] ZED is now active and running in background!"
      echo "[+] Check status with: sudo systemctl status zed.service"
      echo "[+] View live logs with: sudo journalctl -u zed.service -f"
    fi
    ;;
  2)
    echo ""
    echo "[*] Building and starting Docker container..."
    if command -v docker &> /dev/null; then
      docker compose up -d --build
      echo "[+] ZED is now running in Docker!"
      echo "[+] Access Web Interface at: http://localhost:8000"
      echo "[+] Access Victim Demo Portal at: http://localhost:8000/demo"
      echo "[+] View container logs: docker compose logs -f"
    else
      echo "[-] Docker is not installed. Install with: sudo apt install docker.io docker-compose-v2"
    fi
    ;;
  3)
    echo ""
    echo "[*] Detecting Local Network IP for LAN deployment..."
    MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    echo "------------------------------------------------------------------"
    echo "  Your machine's LAN IP: $MY_IP"
    echo "  Access ZED Terminal:   http://$MY_IP:8000"
    echo "  Access Victim Demo:    http://$MY_IP:8000/demo"
    echo "------------------------------------------------------------------"
    echo "Any phone, tablet, or laptop connected to your Wi-Fi can now open"
    echo "those URLs in their browser while ZED is running!"
    ;;
  4)
    echo ""
    echo "[*] Instant Free Public HTTPS URL (Cloudflare Tunnel):"
    echo "To show your teacher or classmates remotely without opening router ports,"
    echo "run this single command in a terminal:"
    echo ""
    echo "    npx -y cloudflared tunnel --url http://127.0.0.1:8000"
    echo ""
    echo "Cloudflare will generate a free temporary https://xxxx.trycloudflare.com link"
    echo "that anyone in the world can open on their phone or laptop!"
    ;;
  5)
    echo ""
    echo "[*] Free Cloud Platform Deployment (Render / Railway):"
    echo "1. Push this repository to GitHub:"
    echo "   git init && git add . && git commit -m 'Initial ZED commit'"
    echo "   git remote add origin https://github.com/<your-username>/ZED.git"
    echo "   git push -u origin main"
    echo ""
    echo "2. Open https://render.com -> New Web Service -> Connect GitHub repo."
    echo "   • Build Command: pip install -r requirements.txt"
    echo "   • Start Command: python run_server.py"
    echo "   • Port: 8000"
    echo "Render will give you a public URL (e.g. https://zed-edr.onrender.com)!"
    ;;
  *)
    echo "Exiting."
    ;;
esac
