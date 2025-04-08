"""
DDoS Protection System - Main Application
Editor: Nandeesh Kantli
Last Updated: April 2024
Version: 1.0.0

Description:
This module implements a Flask-based web application with DDoS protection features.
It includes rate limiting, real-time monitoring, and analytics capabilities.

Key Features:
- IP-based rate limiting
- Real-time request monitoring
- Analytics dashboard
- WebSocket-based updates
- Attack detection and blocking

Dependencies:
- Flask 2.0.1
- Flask-SocketIO 5.1.1
- Python 3.8+
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import time
import logging
from datetime import datetime
import json
import csv
import os
import random
from collections import defaultdict, deque
import threading
import queue

# Configure logging to both file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('portfolio_log.txt'),
        logging.StreamHandler()
    ]
)

# Initialize Flask application and SocketIO for real-time updates
app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')
logging.info("Portfolio application initialized")

# Global configuration for attack detection
BLOCK_THRESHOLD = 50  # Number of requests before blocking an IP
BLOCK_DURATION = 300  # Block duration in seconds (5 minutes)
request_logs = {}  # Store request logs per IP
blocked_ips = {}  # Track blocked IPs and their block expiration
request_counts = {}  # Count requests per IP
unique_ips = set()  # Track unique IPs
response_times = deque(maxlen=100)  # Store last 100 response times for analysis
error_counts = deque(maxlen=300)  # Store last 5 minutes of error counts
is_detection_active = True  # Global flag to enable/disable detection
analytics_queue = queue.Queue()  # Queue for analytics data
request_timestamps = deque(maxlen=1000)  # Store timestamps of last 1000 requests
ANOMALY_THRESHOLD = 0.7  # Threshold for anomaly detection
MIN_REQUESTS_FOR_ANOMALY = 20  # Minimum requests needed for anomaly detection
RPS_THRESHOLD = 100  # Requests per second threshold for immediate blocking

def init_analytics_files():
    """
    Initialize CSV files for storing analytics data.
    Creates the analytics directory and required CSV files if they don't exist.
    """
    if not os.path.exists('analytics'):
        os.makedirs('analytics')
    
    # Initialize request log CSV with headers
    if not os.path.exists('analytics/requests.csv'):
        with open('analytics/requests.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'ip', 'user_agent', 'status', 'request_count'])
    
    # Initialize block log CSV with headers
    if not os.path.exists('analytics/blocks.csv'):
        with open('analytics/blocks.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'ip', 'reason', 'duration'])

def log_request(ip, user_agent, status, request_count):
    """
    Log a request to the analytics CSV file.
    
    Args:
        ip (str): IP address of the requester
        user_agent (str): User agent string
        status (str): Request status
        request_count (int): Number of requests from this IP
    """
    try:
        with open('analytics/requests.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                ip,
                user_agent,
                status,
                request_count
            ])
    except Exception as e:
        logging.error(f"Error logging request: {str(e)}")

def log_block(ip, reason, duration):
    """
    Log a blocked IP to the analytics CSV file.
    
    Args:
        ip (str): Blocked IP address
        reason (str): Reason for blocking
        duration (int): Block duration in seconds
    """
    try:
        with open('analytics/blocks.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                ip,
                reason,
                duration
            ])
    except Exception as e:
        logging.error(f"Error logging block: {str(e)}")

def calculate_rps():
    """
    Calculate requests per second based on recent timestamps.
    
    Returns:
        float: Current requests per second
    """
    if not request_timestamps:
        return 0
    
    current_time = time.time()
    requests_in_last_second = sum(1 for ts in request_timestamps if current_time - ts <= 1.0)
    return requests_in_last_second

def calculate_anomaly_score():
    """
    Calculate an anomaly score based on current traffic patterns.
    Uses both RPS and historical data to detect anomalies.
    
    Returns:
        float: Anomaly score between 0 and 1
    """
    if len(request_timestamps) < MIN_REQUESTS_FOR_ANOMALY:
        return 0.0
    
    current_time = time.time()
    requests_last_minute = sum(1 for ts in request_timestamps if current_time - ts <= 60.0)
    avg_rps = requests_last_minute / 60.0
    
    current_rps = calculate_rps()
    
    # Immediate anomaly if RPS exceeds threshold
    if current_rps > RPS_THRESHOLD:
        return 1.0
    
    # Calculate relative anomaly score
    if current_rps > avg_rps * 1.5:
        return min(1.0, (current_rps - avg_rps) / (avg_rps * 2))
    return 0.0

def update_analytics():
    """
    Update analytics data and emit to connected clients.
    Calculates various metrics and sends them through WebSocket.
    """
    if not is_detection_active:
        return
    
    try:
        # Calculate key metrics
        rps = calculate_rps()
        unique_ip_count = len(unique_ips)
        avg_response_time = sum(response_times) / max(1, len(response_times)) if response_times else 0
        error_rate = (sum(error_counts) / max(1, len(error_counts))) * 100 if error_counts else 0
        
        # Calculate anomaly status
        anomaly_score = calculate_anomaly_score()
        is_anomaly = anomaly_score > ANOMALY_THRESHOLD or rps > RPS_THRESHOLD
        
        # Get current IP statistics
        current_ip = max(request_counts.items(), key=lambda x: x[1])[0] if request_counts else 'Unknown'
        current_count = request_counts.get(current_ip, 1)
        
        # Prepare analytics data
        data = {
            'rps': round(rps, 2),
            'unique_ips': unique_ip_count,
            'avg_response_time': round(avg_response_time, 2),
            'error_rate': round(error_rate, 2),
            'anomaly_score': anomaly_score,
            'is_anomaly': is_anomaly,
            'ip': current_ip,
            'status': 'success',
            'count': current_count
        }
        
        analytics_queue.put(data)
    except Exception as e:
        logging.error(f"Error updating analytics: {str(e)}")

def background_task():
    """
    Background task that processes analytics data and emits updates to clients.
    Runs continuously in a separate thread.
    """
    while True:
        try:
            data = analytics_queue.get(timeout=1)
            socketio.emit('stats_update', data)
        except queue.Empty:
            pass
        except Exception as e:
            logging.error(f"Error in background task: {str(e)}")

# Start background analytics task
threading.Thread(target=background_task, daemon=True).start()

def periodic_analytics_update():
    """
    Periodically update analytics data.
    Runs in a separate thread and updates every second.
    """
    while True:
        update_analytics()
        time.sleep(1)

# Start periodic analytics updates
threading.Thread(target=periodic_analytics_update, daemon=True).start()

def generate_test_traffic():
    """
    Generate simulated traffic for testing and demonstration.
    Creates both normal and attack traffic patterns.
    """
    while True:
        try:
            # Simulate normal traffic
            ip = f"192.168.1.{random.randint(1, 254)}"
            request_counts[ip] = request_counts.get(ip, 0) + random.randint(1, 5)
            unique_ips.add(ip)
            response_times.append(random.uniform(0.1, 0.5))
            error_counts.append(0)
            
            # Simulate attack traffic (10% chance)
            if random.random() < 0.1:
                attack_ip = f"10.0.0.{random.randint(1, 254)}"
                request_counts[attack_ip] = request_counts.get(attack_ip, 0) + random.randint(50, 100)
                unique_ips.add(attack_ip)
                response_times.append(random.uniform(1.0, 2.0))
                error_counts.append(1)
            
            time.sleep(0.1)
        except Exception as e:
            logging.error(f"Error generating test traffic: {str(e)}")

# Start test traffic generation
threading.Thread(target=generate_test_traffic, daemon=True).start()

@app.route('/analytics')
def analytics():
    """
    Analytics dashboard route.
    Displays recent requests, blocks, and attack logs.
    """
    try:
        # Read and process request logs
        requests = []
        if os.path.exists('analytics/requests.csv'):
            with open('analytics/requests.csv', 'r') as f:
                reader = csv.DictReader(f)
                requests = list(reader)
        
        # Read and process block logs
        blocks = []
        if os.path.exists('analytics/blocks.csv'):
            with open('analytics/blocks.csv', 'r') as f:
                reader = csv.DictReader(f)
                blocks = list(reader)
        
        # Read and process attack logs
        attack_log = []
        try:
            if os.path.exists('attack_log.csv'):
                with open('attack_log.csv', 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        attack_log.append({
                            'timestamp': row['timestamp'],
                            'content': f"Thread: {row['thread_id']} - IP: {row['ip']} - Status: {row['status_code']} - Response Time: {row['response_time']}s"
                        })
        except Exception as e:
            logging.error(f"Error reading attack log: {str(e)}")
        
        # Combine and sort all events
        all_events = []
        
        # Process request events
        for req in requests:
            all_events.append({
                'type': 'request',
                'timestamp': req['timestamp'],
                'ip': req['ip'],
                'status': req['status'],
            })
        
        # Process block events
        for block in blocks:
            all_events.append({
                'type': 'block',
                'timestamp': block['timestamp'],
                'ip': block['ip'],
                'reason': block['reason']
            })
        
        # Sort events by timestamp
        all_events.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return render_template('analytics.html', events=all_events[:100])
    except Exception as e:
        logging.error(f"Error in analytics route: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.before_request
def before_request():
    # Skip analytics page from all checks
    if request.path == '/analytics':
        return
    
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    start_time = time.time()
    
    # Check if IP is blocked
    if ip in blocked_ips:
        if time.time() - blocked_ips[ip] < BLOCK_DURATION:
            log_block(ip, "Previously blocked", BLOCK_DURATION)
            error_counts.append(1)
            return render_template('blocked.html', ip=ip), 403
        else:
            del blocked_ips[ip]
    
    # Update request count and unique IPs
    request_counts[ip] = request_counts.get(ip, 0) + 1
    unique_ips.add(ip)
    request_timestamps.append(time.time())  # Add timestamp for RPS calculation
    
    # Check rate limits
    if request_counts[ip] > BLOCK_THRESHOLD:
        blocked_ips[ip] = time.time()
        log_block(ip, "Rate limit exceeded", BLOCK_DURATION)
        error_counts.append(1)
        return render_template('blocked.html', ip=ip), 429
    
    # Log the request
    log_request(ip, user_agent, "Success", request_counts[ip])
    
    # Record response time
    response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
    response_times.append(response_time)
    error_counts.append(0)
    
    # Update analytics
    update_analytics()

@app.route("/project")
def project():
    # Track request
    ip = request.remote_addr
    request_counts[ip] = request_counts.get(ip, 0) + 1
    unique_ips.add(ip)
    response_times.append(0.1)  # Simulated response time
    error_counts.append(0)
    
    # Update analytics
    update_analytics()
    return render_template('project.html')

@app.route("/")
def portfolio():
    # Track request
    ip = request.remote_addr
    request_counts[ip] = request_counts.get(ip, 0) + 1
    unique_ips.add(ip)
    response_times.append(0.1)  # Simulated response time
    error_counts.append(0)
    
    # Update analytics
    update_analytics()
    return render_template('portfolio.html')

@app.route("/status")
def status():
    # Track request
    ip = request.remote_addr
    request_counts[ip] = request_counts.get(ip, 0) + 1
    unique_ips.add(ip)
    response_times.append(0.1)  # Simulated response time
    error_counts.append(0)
    
    # Calculate current metrics
    rps = calculate_rps()
    unique_ip_count = len(unique_ips)
    avg_response_time = sum(response_times) / max(1, len(response_times)) if response_times else 0
    error_rate = (sum(error_counts) / max(1, len(error_counts))) * 100 if error_counts else 0
    anomaly_score = calculate_anomaly_score()
    is_anomaly = anomaly_score > ANOMALY_THRESHOLD or rps > RPS_THRESHOLD
    
    return jsonify({
        "active_connections": len(request_logs),
        "blocked_ips": len(blocked_ips),
        "server_time": datetime.now().isoformat(),
        "is_detection_active": is_detection_active,
        "rps": round(rps, 2),
        "unique_ips": unique_ip_count,
        "avg_response_time": round(avg_response_time, 2),
        "error_rate": round(error_rate, 2),
        "anomaly_score": anomaly_score,
        "is_anomaly": is_anomaly,
        "ip": ip,
        "status": "success",
        "count": request_counts.get(ip, 1)
    })

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    logging.info('Client connected')
    emit('connection_status', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    logging.info('Client disconnected')

@socketio.on('start_detection')
def handle_start_detection():
    global is_detection_active
    is_detection_active = True
    emit('detection_status', {'status': 'active'})

@socketio.on('stop_detection')
def handle_stop_detection():
    global is_detection_active
    is_detection_active = False
    emit('detection_status', {'status': 'inactive'})

if __name__ == '__main__':
    # Initialize Socket.IO
    socketio.init_app(app, cors_allowed_origins="*")
    
    # Start the server
    logging.info("Starting DDoS Protection Server")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) 