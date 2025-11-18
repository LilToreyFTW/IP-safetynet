# Installation Guide - IP Operations Control Panel

## System Requirements
- Python 3.8 or higher
- Windows 10/11, Linux, or macOS
- Administrator/Root privileges (for firewall operations)
- 2GB RAM minimum
- 500MB disk space

## Installation Steps

### 1. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 2. Optional: Install Tesseract OCR (for image text detection)
- Windows: Download from https://github.com/UB-Mannheim/tesseract/wiki
- Linux: `sudo apt install tesseract-ocr`
- macOS: `brew install tesseract`

### 3. Run the Application
```bash
python ip_gui.py
```

## First Run
- Configuration file (`config.json`) will be created automatically
- Database (`threat_intelligence.db`) will be initialized
- All required directories will be created

## Advanced Features
All advanced features are optional and will work if modules are available.
If modules are missing, the application will run in basic mode.

## Troubleshooting
- If you see "Advanced features not available", ensure all Python files are in the same directory
- For firewall operations, run as Administrator (Windows) or Root (Linux)
- Check logs in the `Logs/` directory for detailed error information

