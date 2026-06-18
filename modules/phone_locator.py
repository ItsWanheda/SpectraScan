#!/usr/bin/env python3
import sys
import requests
import json
import time

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
    # Note: You should replace this with your own API key from numverify.com
    key = "83c4959db3119ceb89d4390911a5ce0e" 

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv} <phone_number>")
        sys.exit(1)
        
    number = sys.argv
    api = f"http://apilayer.net/api/validate?access_key={config.key}&number={number}&country_code=&format=1"
    
    try:
        output = requests.get(api)
        content = output.text
        obj = json.loads(content)
        
        country_code = obj.get('country_code', '')
        country_name = obj.get('country_name', '')
        location = obj.get('location', '')
        carrier = obj.get('carrier', '')
        line_type = obj.get('line_type', None)
        
        time.sleep(0.2)
        print(f" - Getting Country [{'OK' if country_code else 'FAILED'}]")
        time.sleep(0.2)
        print(f" - Getting Country Name [{'OK' if country_name else 'FAILED'}]")
        time.sleep(0.2)
        print(f" - Getting Location [{'OK' if location else 'FAILED'}]")
        time.sleep(0.2)
        print(f" - Getting Carrier [{'OK' if carrier else 'FAILED'}]")
        time.sleep(0.2)
        print(f" - Getting Device [{'OK' if line_type else 'FAILED'}]")
        
        print(f"\n{color.YELLOW}[+] Information Output{color.END}")
        print("--------------------------------------")
        print(f" - Phone number: {number}")
        print(f" - Country: {country_code}")
        print(f" - Country Name: {country_name}")
        print(f" - Location: {location}")
        print(f" - Carrier: {carrier}")
        print(f" - Device: {line_type}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()