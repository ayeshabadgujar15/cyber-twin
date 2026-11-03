#!/bin/sh
set -eu
sudo apt update
sudo apt full-upgrade -y
sudo apt install -y plaso python3-venv
plaso-log2timeline --version
