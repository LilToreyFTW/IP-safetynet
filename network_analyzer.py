"""
Advanced Network Analysis and Packet Capture
"""
import socket
import struct
import threading
from datetime import datetime
from typing import List, Dict, Optional

class NetworkAnalyzer:
    def __init__(self, logger=None):
        self.logger = logger
        self.capturing = False
        self.capture_thread = None
        self.packets = []
        self.max_packets = 1000
    
    def analyze_connection(self, ip: str, port: int) -> Dict:
        """Analyze connection to IP:port"""
        result = {
            "ip": ip,
            "port": port,
            "status": "UNKNOWN",
            "latency": None,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            start_time = datetime.now()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            connection_result = sock.connect_ex((ip, port))
            end_time = datetime.now()
            
            latency = (end_time - start_time).total_seconds() * 1000
            
            if connection_result == 0:
                result["status"] = "OPEN"
                result["latency"] = latency
                
                # Try to get service banner
                try:
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    result["banner"] = banner[:200]
                except:
                    pass
                
                sock.close()
            else:
                result["status"] = "CLOSED/FILTERED"
        except Exception as e:
            result["status"] = "ERROR"
            result["error"] = str(e)
        
        return result
    
    def scan_port_range(self, ip: str, ports: List[int], max_threads: int = 50) -> List[Dict]:
        """Scan multiple ports with threading"""
        results = []
        lock = threading.Lock()
        
        def scan_port(port):
            result = self.analyze_connection(ip, port)
            with lock:
                results.append(result)
        
        threads = []
        for port in ports:
            while len(threads) >= max_threads:
                threads = [t for t in threads if t.is_alive()]
                threading.Event().wait(0.1)
            
            thread = threading.Thread(target=scan_port, args=(port,), daemon=True)
            thread.start()
            threads.append(thread)
        
        # Wait for all threads
        for thread in threads:
            thread.join(timeout=10)
        
        return results
    
    def get_network_info(self, ip: str) -> Dict:
        """Get comprehensive network information"""
        info = {
            "ip": ip,
            "hostname": None,
            "reverse_dns": None,
            "is_reachable": False,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Reverse DNS lookup
            hostname = socket.gethostbyaddr(ip)[0]
            info["hostname"] = hostname
            info["reverse_dns"] = hostname
        except:
            pass
        
        # Ping test
        try:
            import platform
            import subprocess
            if platform.system() == 'Windows':
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, timeout=2)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, timeout=2)
            info["is_reachable"] = result.returncode == 0
        except:
            pass
        
        return info

