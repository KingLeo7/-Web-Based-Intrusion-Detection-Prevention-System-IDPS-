# Web-Based Intrusion Detection & Prevention System (IDPS)

A comprehensive Flask-based intrusion detection and prevention system that monitors and blocks malicious attacks on web applications.

## Features

- **Secure Login System**: User authentication with password security
- **SQL Injection Detection**: Detects and blocks SQL injection attacks
- **XSS Prevention**: Identifies and blocks cross-site scripting attempts
- **Brute Force Detection**: Monitors login attempts and blocks IPs after threshold exceedance
- **Admin Dashboard**: View blocked IPs, attack logs, and risk levels
- **IP Blocking System**: Automatic blocking of malicious IP addresses

## Project Structure

```
project_0/
├── app.py                 # Main Flask application
├── static/
│   └── style.css         # Application styling
├── templates/
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   └── dashboard.html    # Admin dashboard
├── take2/                # Alternative implementation
└── users.db              # SQLite database
```

## Getting Started

### Prerequisites
- Python 3.8+
- Flask
- SQLite3

### Installation

1. Clone the repository
```bash
git clone https://github.com/yourusername/idps.git
cd idps
```

2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
pip install flask
```

4. Run the application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Security Features

### 1. SQL Injection Prevention
- Detects common SQL injection patterns
- Blocks requests containing suspicious SQL keywords

### 2. XSS Prevention
- Filters HTML/JavaScript tags in user input
- Validates and sanitizes all user submissions

### 3. Brute Force Protection
- Tracks login attempts per IP address
- Blocks IPs after configurable failure threshold
- Time-based release of blocked IPs

### 4. Dashboard Monitoring
- Real-time attack logs
- Blocked IP addresses display
- Risk level classification (Low/Medium/High)

## Usage

1. **Register a new account** on the registration page
2. **Login** with your credentials
3. **Access the dashboard** to view system activity
4. **Monitor blocked IPs** and attack attempts

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite
- **Frontend**: HTML, CSS, JavaScript
- **Security**: Input validation, IP filtering

## Attack Coverage

- SQL Injection (`' OR 1=1`, `SELECT`, etc.)
- Cross-Site Scripting (`<script>`, HTML tags)
- Brute Force Attacks (Multiple failed login attempts)

## Future Enhancements

- Machine learning-based anomaly detection
- Real-time alerting system
- Advanced logging and analytics
- Geographic IP tracking
- Rate limiting

## Contributing

Feel free to fork this project and submit pull requests.

## License

This project is open source and available under the MIT License.

## Contact

For questions or suggestions, please open an issue on GitHub.
