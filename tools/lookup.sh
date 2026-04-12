#!/bin/bash

# Check if a filename was provided as an argument
if [ -z "$1" ]; then
    echo "Usage: ./lookup.sh <filename.txt>"
    exit 1
fi

# Check if the file actually exists
if [ ! -f "$1" ]; then
    echo "Error: File '$1' not found."
    exit 1
fi

# Run the lookup loop
echo "Starting lookup for subdomains in: $1"
echo "------------------------------------"

for sub in $(cat "$1"); do
    host "$sub" | grep "has address"
done
