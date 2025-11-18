# IP Operations Control Panel - Advanced Edition

## Overview
Advanced cybersecurity threat intelligence and operations platform for identifying, analyzing, and neutralizing ransomware threats.

## Features

### Core Operations
- **IP ACK** - Acknowledgment operations
- **IP ACL** - Access Control List management
- **IP File Operations** - Force file send and launch
- **IP Trace** - Network path analysis
- **Network Scanning** - Comprehensive port and service scanning
- **Threat Analysis** - Deep threat intelligence gathering

### Advanced Features
- **SQLite Database** - Persistent threat intelligence storage
- **Advanced Logging** - Rotating logs with multiple levels
- **Statistics Dashboard** - Analytics and reporting
- **Real-Time Monitoring** - Live threat monitoring
- **Export/Import** - JSON and CSV data export
- **Configuration Management** - JSON-based settings
- **SYN Flood Defense** - Protection configuration
- **Automated Response** - Threat response automation

### Security Features
- **Complete IP Blocking** - Multi-layer firewall rules
- **Threat Intelligence** - Database-driven threat tracking
- **Alert System** - Real-time threat alerts
- **Comprehensive Logging** - All operations logged

## Installation

1. Install Python 3.8+
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python ip_gui.py
```

## Configuration

Edit `config.json` to customize:
- Default threat IPs
- Logging levels
- Database settings
- Monitoring intervals
- UI preferences

## Database

The application uses SQLite to store:
- Threat IPs and intelligence
- Operation logs
- Network scan results
- Related IPs
- Alerts

## Export/Import

Export threat intelligence data to:
- JSON format
- CSV format

## Advanced Modules

- `config_manager.py` - Configuration management
- `advanced_logger.py` - Enhanced logging system
- `threat_database.py` - SQLite database operations
- `statistics_dashboard.py` - Analytics dashboard
- `export_import.py` - Data export/import
- `real_time_monitor.py` - Real-time monitoring
- `performance_cache.py` - Performance caching
- `automated_response.py` - Automated threat response

## Security Notice

This software is designed for defensive cybersecurity operations and threat intelligence gathering. All operations are logged and documented for legal compliance.

## License

Proprietary - Cybersecurity Operations

