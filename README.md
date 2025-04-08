# DDoS Protection System

A comprehensive solution for protecting web applications from DDoS attacks, featuring real-time monitoring and analytics.

![DDoS Protection System](https://img.shields.io/badge/status-active-success.svg)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Last Updated](https://img.shields.io/badge/last%20updated-April%202024-blue.svg)

## 📝 Project Information

- **Editor**: Nandeesh Kantli
- **Last Updated**: April 2024
- **Version**: 1.0.0
- **Status**: Active Development

## 🚀 Features

- **Intelligent Rate Limiting**: IP-based rate limiting with configurable thresholds
- **Real-time Analytics Dashboard**: Monitor requests, blocks, and attack patterns
- **DDoS Simulator**: Built-in testing tool for simulating attack scenarios
- **Modern Web Interface**: Responsive dashboard with real-time updates
- **WebSocket Support**: Real-time updates using Flask-SocketIO

## 📁 Project Structure

```
DDoS/
├── portfolio_app.py      # Main Flask application with protection logic
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

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/DDoS-Simulation-Detection-Blocking.git
   cd DDoS-Simulation-Detection-Blocking
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Getting Started

1. Start the server:
   ```bash
   python portfolio_app.py
   ```

2. Access the application:
   - Portfolio: http://127.0.0.1:5000
   - Project Details: http://127.0.0.1:5000/project
   - Analytics Dashboard: http://127.0.0.1:5000/analytics

3. Test the protection system:
   ```bash
   python ddos_simulator.py
   ```

## ⚙️ Protection Configuration

The system uses the following default thresholds:
- Maximum requests per minute: 60
- Block duration: 5 minutes
- IP tracking window: 1 minute

These values can be adjusted in the configuration section of `portfolio_app.py`.

## 🔧 Technologies Used

- **Backend**:
  - Python 3.8+
  - Flask 2.0.1
  - Flask-SocketIO 5.1.1

- **Frontend**:
  - HTML5/CSS3
  - JavaScript
  - Socket.IO

## 📊 Analytics Features

- Real-time request monitoring
- Attack pattern analysis
- IP tracking
- Blocked requests visualization
- Performance metrics

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Flask team for the amazing web framework
- All contributors who have helped improve this project

## 📞 Contact

- **Editor**: Nandeesh Kantli
- **Email**: [Your Email]
- **GitHub**: [Your GitHub Profile]

## 📅 Changelog

### Version 1.0.0 (April 2024)
- Initial release
- Basic DDoS protection features
- Real-time monitoring
- Analytics dashboard
- Attack simulation capabilities 