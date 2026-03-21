#!/bin/bash

INPUT_FILE=$1
OUTPUT_FILE="stealth_waf_results.txt"

# Array of realistic User-Agents to rotate
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
)

if [ -z "$INPUT_FILE" ]; then
    echo "❌ Usage: $0 <ip_list.txt>"
    exit 1
fi

echo "🕶️ Starting Stealth Scan. Results will be slow but steady..."
echo "--------------------------------------------------------"

while read -r ip; do
    # Pick a random User-Agent
    UA=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}
    
    echo -n "[*] Inspecting $ip... "

    # 1. Very basic TCP check (less noisy than a full SYN scan)
    if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$ip/443" 2>/dev/null; then
        
        # 2. Run wafw00f with a custom UA and follow redirects
        # We use a subshell to keep things quiet
        res=$(wafw00f "$ip" -a -H "User-Agent: $UA" 2>/dev/null | grep -i 'is behind' | sed 's/^[[:space:]]*//')

        if [ ! -z "$res" ]; then
            echo -e "\e[32m[MATCH]\e[0m $res"
            echo "$ip: $res" >> "$OUTPUT_FILE"
        else
            echo "Clear"
        fi
    else
        echo "Port 443 Closed"
    fi

    # 3. Random Jitter: Sleep between 2 to 5 seconds
    sleep_time=$(( (RANDOM % 4) + 2 ))
    sleep "$sleep_time"

done < "$INPUT_FILE"

echo "--------------------------------------------------------"
echo "✅ Stealth scan complete. Log: $OUTPUT_FILE"
