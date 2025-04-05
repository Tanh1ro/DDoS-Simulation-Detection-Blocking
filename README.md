# DDoS Protection System

A comprehensive solution for protecting web applications from DDoS attacks, featuring real-time monitoring and analytics.

## Features

- **Intelligent Rate Limiting**: Automatically detects and blocks suspicious IP addresses
- **Real-time Analytics**: Monitor requests, blocks, and attacks in real-time
- **DDoS Simulator**: Test the protection system with simulated attacks
- **Modern Web Interface**: Clean and responsive dashboard for monitoring

## Project Structure

```
DDoS/
├── portfolio_app.py      # Main Flask application
├── ddos_simulator.py     # DDoS attack simulator for testing
├── requirements.txt      # Python dependencies
├── templates/            # HTML templates
│   ├── portfolio.html   # Portfolio page
│   ├── project.html     # Project details page
│   ├── analytics.html   # Analytics dashboard
│   └── blocked.html     # Blocked request page
└── analytics/           # Analytics data
    ├── requests.csv     # Request logs
    └── blocks.csv       # Block logs
```

## Getting Started

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Start the server:
   ```bash
   python portfolio_app.py
   ```

3. Access the application:
   - Portfolio: http://127.0.0.1:5000
   - Project Details: http://127.0.0.1:5000/project
   - Analytics Dashboard: http://127.0.0.1:5000/analytics

4. Test the protection system:
   ```bash
   python ddos_simulator.py
   ```

## Protection Configuration

The system uses the following thresholds:
- Maximum requests per minute: 60
- Block duration: 5 minutes
- IP tracking window: 1 minute

## Technologies Used

- Python
- Flask
- HTML/CSS
- JavaScript
- CSV for data storage

## License

This project is licensed under the MIT License. 