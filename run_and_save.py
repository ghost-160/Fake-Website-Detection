import os
import subprocess

with open('investigation_output_utf8.txt', 'w', encoding='utf-8') as f:
    result = subprocess.run(['python', 'investigate_chatgpt.py'], capture_output=True, text=True)
    f.write(result.stdout)
    if result.stderr:
        f.write('\nErrors:\n' + result.stderr)
