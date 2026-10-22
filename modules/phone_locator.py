#!/usr/bin/env python3
import sys
import requests
import json
import os

class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

class config:
    # Set NUMVERIFY_KEY in the environment; never commit provider credentials.
    key = os.environ.get("NUMVERIFY_KEY", "").strip()

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv} <phone_number>")
        sys.exit(1)
        
    number = sys.argv[1].strip()
    if not config.key:
        print("NUMVERIFY_KEY is not configured; set it in the environment.")
        sys.exit(2)
    if not number:
        print("A non-empty phone number is required.")
        sys.exit(2)

    try:
        output = requests.get(
            "https://api.apilayer.net/api/validate",
            params={
                "access_key": config.key,
                "number": number,
                "country_code": "",
                "format": 1,
            },
            timeout=10,
        )
        output.raise_for_status()
        obj = output.json()
        
        country_code = obj.get('country_code', '')
        country_name = obj.get('country_name', '')
        location = obj.get('location', '')
        carrier = obj.get('carrier', '')
        line_type = obj.get('line_type', None)
        
        print(f" - Getting Country [{'OK' if country_code else 'FAILED'}]")
        print(f" - Getting Country Name [{'OK' if country_name else 'FAILED'}]")
        print(f" - Getting Location [{'OK' if location else 'FAILED'}]")
        print(f" - Getting Carrier [{'OK' if carrier else 'FAILED'}]")
        print(f" - Getting Device [{'OK' if line_type else 'FAILED'}]
        
        print(f"\n{color.YELLOW}[+] Information Output{color.END}")
        print("--------------------------------------")
        print(f" - Phone number: {number}")
        print(f" - Country: {country_code}")
        print(f" - Country Name: {country_name}")
        print(f" - Location: {location}")
        print(f" - Carrier: {carrier}")
        print(f" - Device: {line_type}")
        
    except Exception as e:
        # Avoid rendering request URLs or API credentials from provider exceptions.
        print(f"Phone lookup failed: {type(e).__name__}")

if __name__ == "__main__":
    main()