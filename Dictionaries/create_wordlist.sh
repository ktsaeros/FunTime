#!/bin/bash

# --- CONFIGURATION ---
# Source: EFF Large Wordlist (The gold standard for readable passphrases)
SOURCE_URL="https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt"

# Get the directory where the script is running
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DICT_DIR="$DIR/Dictionaries"
FILE="$DICT_DIR/words.txt"

# Create directory if it doesn't exist
if [ ! -d "$DICT_DIR" ]; then
    mkdir -p "$DICT_DIR"
fi

echo "Downloading EFF Wordlist..."

# 1. Download the list
# 2. 'awk' grabs the second column (the word), ignoring the dice numbers
# 3. 'grep' filters for words between 4 and 6 letters (^[a-z]{4,6}$)
# 4. 'sed' converts the first letter to Uppercase (Title Case)
# 5. Save to words.txt

curl -s $SOURCE_URL | \
awk '{print $2}' | \
grep -E '^[a-z]{4,6}$' | \
perl -pe 's/(\w)/\u$1/' > "$FILE"

# Count the words
COUNT=$(wc -l < "$FILE" | xargs)

echo -e "\033[0;32mSuccess! Created $FILE with $COUNT high-quality words.\033[0m"

