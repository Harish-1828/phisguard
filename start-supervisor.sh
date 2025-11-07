#!/bin/bash
set -e

echo "Installing dependencies..."
pip install -r requirements.txt supervisor
npm install

echo "Starting services with Supervisor..."
supervisord -c supervisord.conf
