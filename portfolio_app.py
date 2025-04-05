from flask import Flask, render_template, request, jsonify
import time
import logging
from datetime import datetime
import json
import csv
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('portfolio_log.txt'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)
logging.info("Portfolio application initialized")

# Attack detection configuration
BLOCK_THRESHOLD = 20  # Requests per 10 seconds
BLOCK_DURATION = 300  # 5 minutes in seconds
request_logs = {}
blocked_ips = {}
request_counts = {}

# Initialize analytics files
def init_analytics_files():
    if not os.path.exists('analytics'):
        os.makedirs('analytics')
    
    # Request log CSV
    with open('analytics/requests.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'ip', 'user_agent', 'status', 'request_count'])
    
    # Block log CSV
    with open('analytics/blocks.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'ip', 'reason', 'duration'])

def log_request(ip, user_agent, status, request_count):
    with open('analytics/requests.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            ip,
            user_agent,
            status,
            request_count
        ])

def log_block(ip, reason, duration):
    with open('analytics/blocks.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            ip,
            reason,
            duration
        ])

# Analytics route - placed before before_request to ensure it's always accessible
@app.route('/analytics')
def analytics():
    try:
        # Read recent requests
        with open('analytics/requests.csv', 'r') as f:
            reader = csv.DictReader(f)
            requests = list(reader)
        
        # Read recent blocks
        with open('analytics/blocks.csv', 'r') as f:
            reader = csv.DictReader(f)
            blocks = list(reader)
        
        # Read attack logs
        attack_log = []
        try:
            with open('attack_log.csv', 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    attack_log.append({
                        'timestamp': row['timestamp'],
                        'content': f"Thread: {row['thread_id']} - IP: {row['ip']} - Status: {row['status_code']} - Response Time: {row['response_time']}s"
                    })
        except FileNotFoundError:
            pass
        
        # Combine and sort all events by timestamp
        all_events = []
        
        # Add requests
        for req in requests:
            all_events.append({
                'type': 'request',
                'timestamp': req['timestamp'],
                'ip': req['ip'],
                'status': req['status'],
                'count': req['request_count']
            })
        
        # Add blocks
        for block in blocks:
            all_events.append({
                'type': 'block',
                'timestamp': block['timestamp'],
                'ip': block['ip'],
                'reason': block['reason'],
                'duration': block['duration']
            })
        
        # Sort all events by timestamp
        all_events.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return render_template('analytics.html',
                             total_requests=len(requests),
                             total_blocks=len(blocks),
                             all_events=all_events,
                             attack_log=attack_log)
    except Exception as e:
        logging.error(f"Error in analytics: {str(e)}")
        return "Error loading analytics", 500

@app.before_request
def before_request():
    # Skip analytics page from all checks
    if request.path == '/analytics':
        return
    
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Check if IP is blocked
    if ip in blocked_ips:
        if time.time() - blocked_ips[ip] < BLOCK_DURATION:
            log_block(ip, "Previously blocked", BLOCK_DURATION)
            return render_template('blocked.html', ip=ip), 403
        else:
            del blocked_ips[ip]
    
    # Update request count
    request_counts[ip] = request_counts.get(ip, 0) + 1
    
    # Check rate limits
    if request_counts[ip] > BLOCK_THRESHOLD:
        blocked_ips[ip] = time.time()
        log_block(ip, "Rate limit exceeded", BLOCK_DURATION)
        return render_template('blocked.html', ip=ip), 429
    
    # Log the request
    log_request(ip, user_agent, "Success", request_counts[ip])

@app.route("/project")
def project():
    return render_template('project.html')

@app.route("/")
def portfolio():
    return render_template('portfolio.html')

@app.route("/status")
def status():
    return jsonify({
        "active_connections": len(request_logs),
        "blocked_ips": len(blocked_ips),
        "server_time": datetime.now().isoformat()
    })

if __name__ == "__main__":
    init_analytics_files()
    logging.info("Starting Portfolio server...")
    app.run(host='0.0.0.0', port=5000, debug=True) 