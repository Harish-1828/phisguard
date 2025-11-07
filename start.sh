#!/bin/bash
# Install Python dependencies
pip install -r requirements.txt

# Install Node dependencies
npm install

# Start both servers (Flask on 7000, Node on $PORT)
gunicorn app:app --bind 0.0.0.0:7000 --daemon
node server.js
