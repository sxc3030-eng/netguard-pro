#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
pip install -q -r requirements.txt
echo "Code Analysis Viewer → http://localhost:5050"
python app.py
