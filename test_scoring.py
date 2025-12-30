
import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'backend'))
from makineogr.ai_modulu import tahmin_et

urls = [
    "https://www.google.com",
    "https://apple.com",
    "http://suspicious-long-url-with-dashes-and-numbers-123456.com",
    "https://safe-looking-but-long-domain-name-example-for-testing.com",
    "https://example.com"
]

print("Testing dynamic scoring...")
for url in urls:
    result = tahmin_et(url)
    print(f"URL: {url}")
    print(f"Result: {result}")
    print("-" * 30)
