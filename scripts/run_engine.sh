#!/bin/bash

echo "Starting SOC Engine..."
cd /mnt/c/soc-lab/engine || exit
python3 soc_engine.py

echo ""
echo "Engine stopped. Shell remains open."
exec bash
