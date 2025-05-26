#!/usr/bin/env python3
import geoip2.database
import sys
import logging
from datetime import datetime

# Konfigurasi
DB_PATH = "/usr/local/share/GeoIP/GeoLite2-Country.mmdb"
LOG_PATH = "/var/log/geoip_ssh.log"

# Daftar IP yang diizinkan
WHITELIST_IPS = [
    '127.0.0.1',
    '::1', 
    '::ffff:127.0.0.1',
]

# Setup logging
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def check_ip(ip_address):
    # Log attempt
    logging.info(f"Connection attempt from {ip_address}")
    
    # Strip any IPv6 prefix
    if ip_address.startswith('::ffff:'):
        ip_address = ip_address.replace('::ffff:', '')
        logging.debug(f"IPv6 mapped address converted to: {ip_address}")
    
    # Check whitelist immediately
    if ip_address in WHITELIST_IPS:
        logging.info(f"Access ALLOWED for whitelisted IP {ip_address}")
        return True
        
    # Only check GeoIP if not in whitelist
    try:
        with geoip2.database.Reader(DB_PATH) as reader:
            response = reader.country(ip_address)
            country_code = response.country.iso_code
            country_name = response.country.name
            
            if country_code == "ID":
                logging.info(f"Access ALLOWED from {ip_address} ({country_name})")
                return True
            else:
                logging.warning(f"Access DENIED from {ip_address} ({country_name})")
                return False
                
    except geoip2.errors.AddressNotFoundError:
        logging.error(f"IP not found in database: {ip_address}")
        # Double check whitelist
        if ip_address in WHITELIST_IPS:
            logging.info(f"Access ALLOWED for whitelisted IP {ip_address} (not found in DB)")
            return True
        return False
    except Exception as e:
        logging.error(f"Error processing {ip_address}: {str(e)}")
        # Final whitelist check
        if ip_address in WHITELIST_IPS:
            logging.info(f"Access ALLOWED for whitelisted IP {ip_address} (after error)")
            return True
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.error("No IP address provided")
        print("Error: IP address required")
        sys.exit(1)
        
    ip_address = sys.argv[1]
    result = check_ip(ip_address)
    
    if result:
        print("allow")
        sys.exit(0)
    else:
        print("deny")  
        sys.exit(1)
