#!/bin/bash
# SubClaw Installer
# Run with: curl -fsSL https://raw.githubusercontent.com/zuhaibullahbaig/subclaw/main/install.sh | bash

set -e

echo -e "\033[36m
╔══════════════════════════════════════════════╗
║          Installing SubClaw v1.2             ║
║     Subdomain Takeover & Recon Hunter        ║
╚══════════════════════════════════════════════╝
\033[0m"

# Install Ruby if missing
if ! command -v ruby >/dev/null 2>&1; then
  echo "Ruby not found. Installing Ruby..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y ruby-full
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm ruby
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y ruby
  else
    echo "Could not detect package manager. Please install Ruby manually."
    exit 1
  fi
else
  echo "Ruby already installed ✓"
fi

# Download the script
echo "Downloading SubClaw..."
curl -fsSL https://raw.githubusercontent.com/zuhaibullahbaig/subclaw/main/subclaw.rb -o /tmp/subclaw.rb

chmod +x /tmp/subclaw.rb
sudo mv /tmp/subclaw.rb /usr/local/bin/subclaw

# Make doctor check available immediately
echo "Installing dependencies check..."
subclaw doctor

echo -e "\n\033[32m✅ SubClaw installed successfully!\033[0m"
echo "Run it with: subclaw your_subdomains.txt"
echo "Or:          subclaw doctor"
echo "Full help:   subclaw --help"
echo -e "\nHappy hunting! 🔥"