import requests
import json
import os
import time
from datetime import datetime

# VirusTotal API configuration
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your API key from https://www.virustotal.com/gui/
VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

# Create necessary directories and files
os.makedirs("responses", exist_ok=True)

def check_ip(ip_address):
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    
    try:
        response = requests.get(VT_API_URL.format(ip_address), headers=headers)
        
        if response.status_code == 200:
            # Save the full response to responses directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            response_filename = f"responses/{ip_address}_{timestamp}.json"
            
            with open(response_filename, "w") as f:
                json.dump(response.json(), f, indent=4)
            
            # Check if IP is malicious or suspicious
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            
            if stats["malicious"] > 0 or stats["suspicious"] > 0:
                with open("malicious_ips.txt", "a") as f:
                    f.write(f"{ip_address}\n")
                return "malicious"
            return "clean"
            
        elif response.status_code == 404:
            with open("not_found_ips.txt", "a") as f:
                f.write(f"{ip_address}\n")
            return "not_found"
        else:
            print(f"Error checking {ip_address}: {response.status_code}")
            return "error"
            
    except Exception as e:
        print(f"Exception while checking {ip_address}: {str(e)}")
        return "error"

def main():
    # Clear previous results
    for filename in ["malicious_ips.txt", "not_found_ips.txt"]:
        if os.path.exists(filename):
            os.remove(filename)
    
    try:
        with open("ips.txt", "r") as f:
            ip_addresses = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Error: ips.txt file not found!")
        return
    
    print(f"Found {len(ip_addresses)} IP addresses to check")
    
    for i, ip in enumerate(ip_addresses, 1):
        print(f"Checking IP {i}/{len(ip_addresses)}: {ip}")
        result = check_ip(ip)
        print(f"Result: {result}")
        
        # Sleep to respect rate limiting (4 requests per minute for public API)
        if i < len(ip_addresses):
            time.sleep(15)  # 15 seconds between requests
    
    print("\nScan completed!")
    print("Check malicious_ips.txt for suspicious/malicious IPs")
    print("Check not_found_ips.txt for IPs not found in VT database")
    print("Check responses/ directory for full JSON responses")

if __name__ == "__main__":
    main() 