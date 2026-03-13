#!/bin/bash

cd /home/workspace/Star-Office-UI/backend

export STAR_BACKEND_PORT=18885

nohup python app.py > star-office.log 2>&1 &

echo "Star Office UI started on port 18885"
echo "PID: $(pgrep -f 'python app.py')"
