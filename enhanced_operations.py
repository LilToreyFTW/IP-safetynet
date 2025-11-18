"""
Enhanced Operations with Advanced Features
"""
import socket
import subprocess
import threading
import time
from datetime import datetime
from typing import List, Dict

class EnhancedOperations:
    def __init__(self, logger=None, db=None):
        self.logger = logger
        self.db = db
    
    def advanced_port_scan(self, ip: str, ports: List[int] = None, timeout: float = 1.0) -> Dict:
        """Advanced port scanning with service detection"""
        if ports is None:
            ports = list(range(1, 1025))  # Common ports
        
        results = {
            "ip": ip,
            "scan_start": datetime.now().isoformat(),
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "services": {}
        }
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    results["open_ports"].append(port)
                    # Try to identify service
                    service = self.identify_service(ip, port)
                    if service:
                        results["services"][port] = service
                else:
                    results["closed_ports"].append(port)
                
                sock.close()
            except:
                results["filtered_ports"].append(port)
        
        results["scan_end"] = datetime.now().isoformat()
        return results
    
    def identify_service(self, ip: str, port: int) -> str:
        """Identify service running on port"""
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        
        if port in common_services:
            return common_services[port]
        
        # Try banner grabbing
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if "HTTP" in banner.upper():
                return "HTTP"
            elif "SSH" in banner.upper():
                return "SSH"
            elif "FTP" in banner.upper():
                return "FTP"
        except:
            pass
        
        return "UNKNOWN"
    
    def comprehensive_network_analysis(self, ip: str) -> Dict:
        """Comprehensive network analysis"""
        analysis = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "connectivity": {},
            "dns": {},
            "ports": {},
            "traceroute": {}
        }
        
        # Connectivity test
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, 80))
            sock.close()
            analysis["connectivity"]["port_80"] = "OPEN" if result == 0 else "CLOSED"
        except:
            analysis["connectivity"]["port_80"] = "ERROR"
        
        # DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            analysis["dns"]["hostname"] = hostname
            analysis["dns"]["reverse_dns"] = True
        except:
            analysis["dns"]["reverse_dns"] = False
        
        return analysis

