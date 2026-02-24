#!/bin/bash

echo "Starting SkANDA Prime SOC..."

# start backend
npm run dev &

# start zeek watcher
node capture/zeekWatcher.js &

echo "System Ready."