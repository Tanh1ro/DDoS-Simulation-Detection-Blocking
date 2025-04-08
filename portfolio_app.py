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
socketio = SocketIO(app, async_mode='threading')
logging.info("Portfolio application initialized")

# Attack detection configuration
BLOCK_THRESHOLD = 50  # Increased from 20
BLOCK_DURATION = 300  # 5 minutes in seconds
request_logs = {}
blocked_ips = {}
request_counts = {}
unique_ips = set()
response_times = deque(maxlen=100)  # Store last 100 response times
error_counts = deque(maxlen=300)  # Store last 5 minutes of error counts
is_detection_active = True
analytics_queue = queue.Queue()
request_timestamps = deque(maxlen=1000)  # Store timestamps of last 1000 requests
ANOMALY_THRESHOLD = 0.7  # Lowered threshold for faster detection
MIN_REQUESTS_FOR_ANOMALY = 20  # Lowered minimum requests needed
RPS_THRESHOLD = 100  # RPS threshold for immediate anomaly detection

# Initialize analytics files
def init_analytics_files():
    if not os.path.exists('analytics'):
        os.makedirs('analytics')
    
    # Request log CSV
    if not os.path.exists('analytics/requests.csv'):
        with open('analytics/requests.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'ip', 'user_agent', 'status', 'request_count'])
    
    # Block log CSV
    if not os.path.exists('analytics/blocks.csv'):
        with open('analytics/blocks.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'ip', 'reason', 'duration'])

def log_request(ip, user_agent, status, request_count):
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
    """Calculate actual requests per second based on timestamps"""
    if not request_timestamps:
        return 0
    
    # Get requests in the last second
    current_time = time.time()
    requests_in_last_second = sum(1 for ts in request_timestamps if current_time - ts <= 1.0)
    return requests_in_last_second

def calculate_anomaly_score():
    """Calculate an anomaly score based on current traffic patterns"""
    if len(request_timestamps) < MIN_REQUESTS_FOR_ANOMALY:
        return 0.0
    
    # Calculate baseline metrics
    current_time = time.time()
    requests_last_minute = sum(1 for ts in request_timestamps if current_time - ts <= 60.0)
    avg_rps = requests_last_minute / 60.0
    
    # Calculate current RPS
    current_rps = calculate_rps()
    
    # Immediate anomaly detection if RPS exceeds threshold
    if current_rps > RPS_THRESHOLD:
        return 1.0
    
    # Calculate anomaly score (0-1)
    if current_rps > avg_rps * 1.5:  # If current RPS is 1.5x higher than average
        return min(1.0, (current_rps - avg_rps) / (avg_rps * 2))
    return 0.0

def update_analytics():
    """Update and emit analytics data to connected clients"""
    if not is_detection_active:
        return
    
    try:
        # Calculate metrics
        rps = calculate_rps()
        unique_ip_count = len(unique_ips)
        avg_response_time = sum(response_times) / max(1, len(response_times)) if response_times else 0
        error_rate = (sum(error_counts) / max(1, len(error_counts))) * 100 if error_counts else 0
        
        # Calculate anomaly score
        anomaly_score = calculate_anomaly_score()
        is_anomaly = anomaly_score > ANOMALY_THRESHOLD or rps > RPS_THRESHOLD
        
        # Get the most recent IP and its count
        current_ip = max(request_counts.items(), key=lambda x: x[1])[0] if request_counts else 'Unknown'
        current_count = request_counts.get(current_ip, 1)
        
        # Prepare data for emission
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
        
        # Put data in queue for background thread
        analytics_queue.put(data)
    except Exception as e:
        logging.error(f"Error updating analytics: {str(e)}")

def background_task():
    """Background task to periodically update analytics"""
    while True:
        try:
            # Get data from queue
            data = analytics_queue.get(timeout=1)
            # Emit to all connected clients
            socketio.emit('stats_update', data)
        except queue.Empty:
            pass
        except Exception as e:
            logging.error(f"Error in background task: {str(e)}")

# Start background task
threading.Thread(target=background_task, daemon=True).start()

# Start periodic analytics updates
def periodic_analytics_update():
    while True:
        update_analytics()
        time.sleep(1)  # Update every second

# Start periodic analytics updates in a separate thread
threading.Thread(target=periodic_analytics_update, daemon=True).start()

def generate_test_traffic():
    """Generate test traffic data for demonstration"""
    while True:
        try:
            # Simulate normal traffic
            ip = f"192.168.1.{random.randint(1, 254)}"
            request_counts[ip] = request_counts.get(ip, 0) + random.randint(1, 5)
            unique_ips.add(ip)
            response_times.append(random.uniform(0.1, 0.5))
            error_counts.append(0)
            
            # Occasionally simulate an attack
            if random.random() < 0.1:  # 10% chance of attack
                attack_ip = f"10.0.0.{random.randint(1, 254)}"
                request_counts[attack_ip] = request_counts.get(attack_ip, 0) + random.randint(50, 100)
                unique_ips.add(attack_ip)
                response_times.append(random.uniform(1.0, 2.0))
                error_counts.append(1)
            
            time.sleep(0.1)  # Generate data every 100ms
        except Exception as e:
            logging.error(f"Error generating test traffic: {str(e)}")

# Start test traffic generation
threading.Thread(target=generate_test_traffic, daemon=True).start()

# Analytics route - placed before before_request to ensure it's always accessible
@app.route('/analytics')
def analytics():
    try:
        # Read recent requests
        requests = []
        if os.path.exists('analytics/requests.csv'):
            with open('analytics/requests.csv', 'r') as f:
                reader = csv.DictReader(f)
                requests = list(reader)
        
        # Read recent blocks
        blocks = []
        if os.path.exists('analytics/blocks.csv'):
            with open('analytics/blocks.csv', 'r') as f:
                reader = csv.DictReader(f)
                blocks = list(reader)
        
        # Read attack logs
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