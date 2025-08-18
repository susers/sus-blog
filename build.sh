#!/bin/bash

echo "=== Prebuild ==="
python scripts/gen_members_table.py

echo "=== Build === "

panblog

echo "=== Minify ==="

minify -r output/ --match "*.css" "*.js" "*.html" -o output
