#!/bin/bash

echo "Starting SkANDA Prime SOC..."

# start backend
npm run dev &

# start capture bridge + watcher
node capture/capture.js &

echo "System Ready."
