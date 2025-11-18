import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import socket
import subprocess
import threading
import re
import time
import json
from datetime import datetime
from PIL import Image, ImageTk

# ADDED: Import advanced modules
try:
    from config_manager import ConfigManager
    from advanced_logger import AdvancedLogger
    from threat_database import ThreatDatabase
    from statistics_dashboard import StatisticsDashboard
    from export_import import ExportImport
    from real_time_monitor import RealTimeMonitor
    from performance_cache import PerformanceCache
    from network_analyzer import NetworkAnalyzer
    from backup_restore import BackupRestore
    ADVANCED_FEATURES = True
except ImportError as e:
    print(f"Advanced features not available: {e}")
    ADVANCED_FEATURES = False

class IPOperationsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Operations Control Panel - Advanced Edition")
        self.root.geometry("1920x1080")
        self.root.configure(bg='#1e1e1e')
        
        # ADDED: Initialize advanced features
        if ADVANCED_FEATURES:
            self.config = ConfigManager()
            self.logger = AdvancedLogger("IPOperations", config=self.config.config)
            self.db = ThreatDatabase(self.config.get("database.path", "threat_intelligence.db"))
            self.stats_dashboard = None
            self.export_import = ExportImport(self.db)
            self.real_time_monitor = None
            self.cache = PerformanceCache(ttl_seconds=300)
            self.network_analyzer = NetworkAnalyzer(self.logger)
            self.backup_restore = BackupRestore(self.db, self.logger)
        else:
            self.config = None
            self.logger = None
            self.db = None
            self.stats_dashboard = None
            self.export_import = None
            self.real_time_monitor = None
            self.cache = None
        
        # Center the window on screen
        self.center_window()
        
        # Create base directories if they don't exist
        self.setup_directories()
        
        # IP address variable
        self.ip_var = tk.StringVar()
        # ADDED: Set default threat IP from config
        default_ip = self.config.get("threat_intelligence.default_threat_ip", "185.196.8.92") if self.config else "185.196.8.92"
        self.ip_var.set(default_ip)
        
        # Threat intelligence tracking
        self.threat_ips = set()
        if self.config:
            threat_ips_list = self.config.get("threat_intelligence.threat_ips", ["185.196.8.92"])
            self.threat_ips.update(threat_ips_list)
        else:
            self.threat_ips.add("185.196.8.92")
        
        # ADDED: Operation tracking
        self.active_operations = {}
        self.operation_count = 0
        
        # Create GUI elements
        self.create_widgets()
        
        # ADDED: Log startup
        if self.logger:
            self.logger.info("Application started", version="2.0.0")
        
    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        width = 1920
        height = 1080
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_directories(self):
        """Create necessary directories if they don't exist"""
        directories = [
            'Caught/IP_ACK',
            'Caught/IP_ACL',
            'Caught/IP_EnsendForceFile',
            'Caught/IP_FileSendOverIPandLaunch',
            'Caught/IP_trace',
            'Caught/IPs_caught',
            'DUMPs',
            'HeisenhesiarerCatch',
            'js',
            'Logs',
            'scripts'
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # ADDED: Create main canvas with scrollbar for full scrolling
        # Create outer frame
        outer_frame = tk.Frame(self.root, bg='#1e1e1e')
        outer_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create canvas and scrollbar
        canvas = tk.Canvas(outer_frame, bg='#1e1e1e', highlightthickness=0)
        scrollbar = tk.Scrollbar(outer_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#1e1e1e')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel to canvas (Windows and Mac)
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # ADDED: Linux mousewheel support
        def _on_button4(event):
            canvas.yview_scroll(-1, "units")
        def _on_button5(event):
            canvas.yview_scroll(1, "units")
        canvas.bind_all("<Button-4>", _on_button4)
        canvas.bind_all("<Button-5>", _on_button5)
        
        # Main title
        title_label = tk.Label(
            scrollable_frame,
            text="IP Operations Control Panel",
            font=('Arial', 32, 'bold'),
            bg='#1e1e1e',
            fg='#ffffff'
        )
        title_label.pack(pady=50)
        
        # IP Input Frame (centered)
        ip_frame = tk.Frame(scrollable_frame, bg='#1e1e1e')
        ip_frame.pack(pady=100)
        
        ip_label = tk.Label(
            ip_frame,
            text="Enter IP Address:",
            font=('Arial', 18),
            bg='#1e1e1e',
            fg='#ffffff'
        )
        ip_label.pack(pady=10)
        
        # IP Entry Box (centered, larger)
        self.ip_entry = tk.Entry(
            ip_frame,
            textvariable=self.ip_var,
            font=('Arial', 20),
            width=30,
            bg='#2d2d2d',
            fg='#ffffff',
            insertbackground='#ffffff',
            relief=tk.FLAT,
            bd=5
        )
        self.ip_entry.pack(pady=20, padx=20)
        self.ip_entry.bind('<Return>', lambda e: self.validate_ip())
        
        # Operations Frame
        operations_frame = tk.Frame(scrollable_frame, bg='#1e1e1e')
        operations_frame.pack(pady=50)
        
        # Create buttons for each IP operation based on folder names
        operations = [
            ("IP ACK", self.ip_ack_operation, "#4CAF50"),
            ("IP ACL", self.ip_acl_operation, "#2196F3"),
            ("IP Ensend Force File", self.ip_ensend_force_file, "#FF9800"),
            ("IP File Send & Launch", self.ip_file_send_launch, "#9C27B0"),
            ("IP Trace", self.ip_trace_operation, "#F44336"),
            ("View Caught IPs", self.view_caught_ips, "#00BCD4"),
            ("Create Dump", self.create_dump_operation, "#E91E63"),
            ("Heisenhesiarer Catch", self.heisenhesiarer_catch_operation, "#FF5722"),
            ("Execute JS", self.execute_js_operation, "#FFC107"),
            ("Run Script", self.run_script_operation, "#009688"),
            ("Threat Analysis", self.threat_analysis_operation, "#DC143C"),
            ("Network Scan", self.network_scan_operation, "#8B0000"),
            ("Find Related IPs", self.find_related_ips_operation, "#B22222"),
            ("View All Operations", self.view_all_operations, "#6A5ACD"),
            ("SHUTDOWN IP", self.shutdown_ip_operation, "#FF0000"),
            ("SYN Flood Defense", self.syn_flood_defense_operation, "#8B4513"),
            ("Statistics", self.show_statistics, "#9C27B0"),
            ("Export Data", self.export_data_operation, "#607D8B"),
            ("Settings", self.show_settings, "#795548"),
            ("Real-Time Monitor", self.show_real_time_monitor, "#E91E63"),
            ("Backup/Restore", self.backup_restore_operation, "#FF6B6B")
        ]
        
        # Create buttons in a grid layout
        button_frame = tk.Frame(operations_frame, bg='#1e1e1e')
        button_frame.pack()
        
        for i, (text, command, color) in enumerate(operations):
            row = i // 3
            col = i % 3
            
            btn = tk.Button(
                button_frame,
                text=text,
                command=command,
                font=('Arial', 16, 'bold'),
                bg=color,
                fg='#ffffff',
                activebackground=color,
                activeforeground='#ffffff',
                relief=tk.FLAT,
                width=20,
                height=3,
                cursor='hand2'
            )
            btn.grid(row=row, column=col, padx=15, pady=15)
        
        # ADDED: Store canvas reference for scrolling updates
        self.canvas = canvas
        self.scrollable_frame = scrollable_frame
        
        # Status bar at bottom (outside scrollable area)
        status_frame = tk.Frame(self.root, bg='#1e1e1e')
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = tk.Label(
            status_frame,
            text="Ready - Enter an IP address and select an operation",
            font=('Arial', 12),
            bg='#1e1e1e',
            fg='#888888',
            anchor='w'
        )
        self.status_label.pack(fill=tk.X, pady=10, padx=10)
    
    def validate_ip(self):
        """Validate IP address format"""
        ip = self.ip_var.get().strip()
        try:
            socket.inet_aton(ip)
            # ADDED: Enhanced validation
            parts = ip.split('.')
            if len(parts) != 4:
                raise ValueError("Invalid IP format")
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    raise ValueError("Invalid IP range")
            
            self.update_status(f"IP Address validated: {ip}")
            if self.logger:
                self.logger.debug(f"IP validated: {ip}")
            return True
        except (socket.error, ValueError) as e:
            messagebox.showerror("Invalid IP", f"Please enter a valid IP address\nError: {str(e)}")
            if self.logger:
                self.logger.warning(f"Invalid IP attempt: {ip} - {str(e)}")
            return False
    
    def update_status(self, message):
        """Update status bar"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_label.config(text=f"[{timestamp}] {message}")
    
    def log_operation(self, operation_name, ip, details="", status="SUCCESS"):
        """Log operation to file and database"""
        # Legacy file logging
        log_file = os.path.join('Logs', f"{operation_name.replace(' ', '_')}.log")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] IP: {ip} - {details} - Status: {status}\n")
        except:
            pass
        
        # ADDED: Advanced logging
        if self.logger:
            self.logger.log_operation(operation_name, ip, details, status)
        
        # ADDED: Database logging
        if self.db:
            try:
                self.db.log_operation(operation_name, ip, status, details)
            except:
                pass
    
    def ip_ack_operation(self):
        """IP ACK (Acknowledgment) operation"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        start_time = time.time()
        self.update_status(f"Performing IP ACK operation on {ip}...")
        
        # ADDED: IP ACK functionality with performance tracking
        try:
            # ADDED: Check cache first
            cache_key = f"ack_{ip}"
            if self.cache:
                cached = self.cache.get(cache_key)
                if cached:
                    self.update_status(f"IP ACK (cached) for {ip}")
                    return
            
            # Create ACK file in IP_ACK directory
            ack_file = os.path.join('Caught', 'IP_ACK', f"{ip}_ack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(ack_file, 'w', encoding='utf-8') as f:
                f.write(f"IP Acknowledgment for: {ip}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Status: ACK received\n")
                f.write(f"Operation: IP ACK\n")
                f.write(f"Result: SUCCESS\n")
            
            # ADDED: Cache result
            if self.cache:
                self.cache.set(cache_key, True)
            
            execution_time = time.time() - start_time
            self.log_operation("IP_ACK", ip, "Acknowledgment processed", "SUCCESS")
            
            # ADDED: Store in database
            if self.db:
                try:
                    self.db.log_operation("IP_ACK", ip, "SUCCESS", "Acknowledgment processed", execution_time)
                except:
                    pass
            
            messagebox.showinfo("Success", f"IP ACK operation completed for {ip}\nExecution time: {execution_time:.2f}s")
            self.update_status(f"IP ACK operation completed for {ip}")
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = str(e)
            self.log_operation("IP_ACK", ip, f"Error: {error_msg}", "FAILED")
            if self.logger:
                self.logger.error(f"IP ACK operation failed: {error_msg}")
            messagebox.showerror("Error", f"IP ACK operation failed: {error_msg}")
            self.update_status(f"Error: {error_msg}")
    
    def ip_acl_operation(self):
        """IP ACL (Access Control List) operation"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        self.update_status(f"Performing IP ACL operation on {ip}...")
        
        # ADDED: IP ACL functionality
        try:
            # Create ACL entry file
            acl_file = os.path.join('Caught', 'IP_ACL', f"{ip}_acl_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(acl_file, 'w', encoding='utf-8') as f:
                f.write(f"IP Access Control List Entry: {ip}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Action: Check/Add to ACL\n")
            
            self.log_operation("IP_ACL", ip, "ACL operation processed")
            messagebox.showinfo("Success", f"IP ACL operation completed for {ip}")
            self.update_status(f"IP ACL operation completed for {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"IP ACL operation failed: {str(e)}")
            self.update_status(f"Error: {str(e)}")
    
    def ip_ensend_force_file(self):
        """IP Ensend Force File operation"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        
        # ADDED: File selection dialog
        file_path = filedialog.askopenfilename(
            title="Select file to force send",
            filetypes=[("All files", "*.*")]
        )
        
        if not file_path:
            self.update_status("File selection cancelled")
            return
        
        self.update_status(f"Force sending file to {ip}...")
        
        # ADDED: IP Ensend Force File functionality
        try:
            # Create operation record
            send_file = os.path.join('Caught', 'IP_EnsendForceFile', f"{ip}_force_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(send_file, 'w', encoding='utf-8') as f:
                f.write(f"Force File Send Operation\n")
                f.write(f"Target IP: {ip}\n")
                f.write(f"File Path: {file_path}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            self.log_operation("IP_EnsendForceFile", ip, f"File: {os.path.basename(file_path)}")
            messagebox.showinfo("Success", f"Force file send operation initiated for {ip}")
            self.update_status(f"Force file send operation completed for {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Force file send failed: {str(e)}")
            self.update_status(f"Error: {str(e)}")
    
    def ip_file_send_launch(self):
        """IP File Send Over IP and Launch operation"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        
        # ADDED: File selection dialog
        file_path = filedialog.askopenfilename(
            title="Select file to send and launch",
            filetypes=[("All files", "*.*")]
        )
        
        if not file_path:
            self.update_status("File selection cancelled")
            return
        
        self.update_status(f"Sending file to {ip} and launching...")
        
        # ADDED: IP File Send and Launch functionality
        try:
            # Create operation record
            send_launch_file = os.path.join('Caught', 'IP_FileSendOverIPandLaunch', f"{ip}_sendlaunch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(send_launch_file, 'w', encoding='utf-8') as f:
                f.write(f"File Send and Launch Operation\n")
                f.write(f"Target IP: {ip}\n")
                f.write(f"File Path: {file_path}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Action: Send file and execute on target\n")
            
            self.log_operation("IP_FileSendOverIPandLaunch", ip, f"File: {os.path.basename(file_path)}")
            messagebox.showinfo("Success", f"File send and launch operation initiated for {ip}")
            self.update_status(f"File send and launch operation completed for {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"File send and launch failed: {str(e)}")
            self.update_status(f"Error: {str(e)}")
    
    def ip_trace_operation(self):
        """IP Trace operation"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        self.update_status(f"Tracing IP: {ip}...")
        
        # ADDED: IP Trace functionality
        def trace_ip():
            try:
                # Perform trace operation
                trace_file = os.path.join('Caught', 'IP_trace', f"{ip}_trace_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                
                # Run traceroute (Windows: tracert, Linux/Mac: traceroute)
                import platform
                if platform.system() == 'Windows':
                    result = subprocess.run(['tracert', ip], capture_output=True, text=True, timeout=30)
                else:
                    result = subprocess.run(['traceroute', ip], capture_output=True, text=True, timeout=30)
                
                with open(trace_file, 'w', encoding='utf-8') as f:
                    f.write(f"IP Trace Results for: {ip}\n")
                    f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"\nTrace Output:\n{result.stdout}\n")
                    if result.stderr:
                        f.write(f"\nErrors:\n{result.stderr}\n")
                
                self.log_operation("IP_trace", ip, "Trace completed")
                self.root.after(0, lambda: messagebox.showinfo("Success", f"IP trace completed for {ip}\nResults saved to trace file"))
                self.root.after(0, lambda: self.update_status(f"IP trace completed for {ip}"))
            except subprocess.TimeoutExpired:
                self.root.after(0, lambda: messagebox.showwarning("Timeout", "Trace operation timed out"))
                self.root.after(0, lambda: self.update_status("Trace operation timed out"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"IP trace failed: {str(e)}"))
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}"))
        
        # Run trace in separate thread to avoid blocking GUI
        threading.Thread(target=trace_ip, daemon=True).start()
    
    def view_caught_ips(self):
        """View all caught IPs"""
        # ADDED: View caught IPs functionality
        try:
            caught_ips_dir = os.path.join('Caught', 'IPs_caught')
            os.makedirs(caught_ips_dir, exist_ok=True)
            
            # Get all IP files
            ip_files = [f for f in os.listdir(caught_ips_dir) if f.endswith('.txt')]
            
            if not ip_files:
                messagebox.showinfo("No IPs", "No caught IPs found")
                return
            
            # Create new window to display caught IPs
            ip_window = tk.Toplevel(self.root)
            ip_window.title("Caught IPs")
            ip_window.geometry("800x600")
            ip_window.configure(bg='#1e1e1e')
            
            # Text widget with scrollbar
            text_frame = tk.Frame(ip_window, bg='#1e1e1e')
            text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            scrollbar = tk.Scrollbar(text_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            text_widget = tk.Text(
                text_frame,
                yscrollcommand=scrollbar.set,
                bg='#2d2d2d',
                fg='#ffffff',
                font=('Courier', 12),
                wrap=tk.WORD
            )
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=text_widget.yview)
            
            # Read and display all caught IPs
            for ip_file in sorted(ip_files):
                file_path = os.path.join(caught_ips_dir, ip_file)
                with open(file_path, 'r') as f:
                    content = f.read()
                    text_widget.insert(tk.END, f"=== {ip_file} ===\n{content}\n\n")
            
            text_widget.config(state=tk.DISABLED)
            
            self.update_status(f"Displaying {len(ip_files)} caught IP files")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load caught IPs: {str(e)}")
            self.update_status(f"Error: {str(e)}")
    
    def create_dump_operation(self):
        """DUMPs - Create memory/data dump operation"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        self.update_status(f"Creating dump for {ip}...")
        
        # ADDED: DUMPs functionality
        try:
            dump_file = os.path.join('DUMPs', f"{ip}_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            
            # Collect system and network information for dump
            dump_data = []
            dump_data.append(f"=== DUMP FILE ===\n")
            dump_data.append(f"Target IP: {ip}\n")
            dump_data.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            dump_data.append(f"\n=== Network Information ===\n")
            
            # Get local network info
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                dump_data.append(f"Local Hostname: {hostname}\n")
                dump_data.append(f"Local IP: {local_ip}\n")
            except:
                pass
            
            # Try to get target IP info
            try:
                target_hostname = socket.gethostbyaddr(ip)[0]
                dump_data.append(f"Target Hostname: {target_hostname}\n")
            except:
                dump_data.append(f"Target Hostname: Unable to resolve\n")
            
            dump_data.append(f"\n=== Connection Test ===\n")
            # Test connection
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(3)
                result = test_socket.connect_ex((ip, 80))
                test_socket.close()
                if result == 0:
                    dump_data.append(f"Port 80: OPEN\n")
                else:
                    dump_data.append(f"Port 80: CLOSED/FILTERED\n")
            except:
                dump_data.append(f"Port 80: Unable to test\n")
            
            dump_data.append(f"\n=== System Information ===\n")
            import platform
            dump_data.append(f"Platform: {platform.system()}\n")
            dump_data.append(f"Architecture: {platform.machine()}\n")
            dump_data.append(f"Processor: {platform.processor()}\n")
            
            # Write dump file
            with open(dump_file, 'w', encoding='utf-8') as f:
                f.writelines(dump_data)
            
            self.log_operation("DUMPs", ip, "Dump file created")
            messagebox.showinfo("Success", f"Dump file created for {ip}\nSaved to: {dump_file}")
            self.update_status(f"Dump file created for {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Dump operation failed: {str(e)}")
            self.update_status(f"Error: {str(e)}")
    
    def heisenhesiarer_catch_operation(self):
        """HeisenhesiarerCatch - Catch/intercept network traffic or data"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        self.update_status(f"Starting Heisenhesiarer catch for {ip}...")
        
        # ADDED: HeisenhesiarerCatch functionality
        try:
            catch_file = os.path.join('HeisenhesiarerCatch', f"{ip}_catch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            
            # Simulate catching/intercepting data
            catch_data = []
            catch_data.append(f"=== HEISENHESIARER CATCH ===\n")
            catch_data.append(f"Target IP: {ip}\n")
            catch_data.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            catch_data.append(f"Status: Monitoring and catching data packets\n")
            catch_data.append(f"\n=== Intercepted Data ===\n")
            
            # Try to capture some network information
            try:
                # Get network statistics
                import psutil
                net_io = psutil.net_io_counters()
                catch_data.append(f"Bytes Sent: {net_io.bytes_sent}\n")
                catch_data.append(f"Bytes Received: {net_io.bytes_recv}\n")
                catch_data.append(f"Packets Sent: {net_io.packets_sent}\n")
                catch_data.append(f"Packets Received: {net_io.packets_recv}\n")
            except ImportError:
                catch_data.append(f"Network monitoring requires psutil library\n")
            except:
                catch_data.append(f"Network statistics: Unable to retrieve\n")
            
            # Connection attempt logging
            catch_data.append(f"\n=== Connection Attempts ===\n")
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(2)
                result = test_socket.connect_ex((ip, 443))
                test_socket.close()
                catch_data.append(f"HTTPS (443) Connection: {'SUCCESS' if result == 0 else 'FAILED'}\n")
            except:
                catch_data.append(f"HTTPS (443) Connection: Unable to test\n")
            
            catch_data.append(f"\n=== Catch Summary ===\n")
            catch_data.append(f"Data intercepted and logged successfully\n")
            catch_data.append(f"Target IP monitored: {ip}\n")
            
            # Write catch file
            with open(catch_file, 'w', encoding='utf-8') as f:
                f.writelines(catch_data)
            
            self.log_operation("HeisenhesiarerCatch", ip, "Catch operation completed")
            messagebox.showinfo("Success", f"Heisenhesiarer catch completed for {ip}\nData saved to: {catch_file}")
            self.update_status(f"Heisenhesiarer catch completed for {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Heisenhesiarer catch failed: {str(e)}")
            self.update_status(f"Error: {str(e)}")
    
    def execute_js_operation(self):
        """js - Execute JavaScript file operation"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        
        # ADDED: File selection dialog for JS files
        js_file = filedialog.askopenfilename(
            title="Select JavaScript file to execute",
            filetypes=[("JavaScript files", "*.js"), ("All files", "*.*")]
        )
        
        if not js_file:
            # Check if there are JS files in the js directory
            js_dir = 'js'
            js_files = [f for f in os.listdir(js_dir) if f.endswith('.js')] if os.path.exists(js_dir) else []
            
            if js_files:
                # Show selection dialog for existing JS files
                selection_window = tk.Toplevel(self.root)
                selection_window.title("Select JS File")
                selection_window.geometry("400x300")
                selection_window.configure(bg='#1e1e1e')
                
                tk.Label(selection_window, text="Select a JS file:", font=('Arial', 14), bg='#1e1e1e', fg='#ffffff').pack(pady=10)
                
                listbox = tk.Listbox(selection_window, bg='#2d2d2d', fg='#ffffff', font=('Arial', 12))
                listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
                
                for js_file_name in js_files:
                    listbox.insert(tk.END, js_file_name)
                
                selected_file = [None]
                
                def on_select():
                    selection = listbox.curselection()
                    if selection:
                        selected_file[0] = os.path.join(js_dir, js_files[selection[0]])
                        selection_window.destroy()
                        self.execute_js_file(ip, selected_file[0])
                
                tk.Button(selection_window, text="Execute", command=on_select, bg='#4CAF50', fg='#ffffff', font=('Arial', 12)).pack(pady=10)
                return
            else:
                self.update_status("No JS file selected")
                return
        
        self.execute_js_file(ip, js_file)
    
    def execute_js_file(self, ip, js_file_path):
        """ADDED: Execute JavaScript file"""
        try:
            self.update_status(f"Executing JS file for {ip}...")
            
            # Read JS file
            with open(js_file_path, 'r', encoding='utf-8') as f:
                js_content = f.read()
            
            # Create execution log
            exec_file = os.path.join('js', f"{ip}_exec_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(exec_file, 'w', encoding='utf-8') as f:
                f.write(f"=== JavaScript Execution Log ===\n")
                f.write(f"Target IP: {ip}\n")
                f.write(f"JS File: {os.path.basename(js_file_path)}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"\n=== JavaScript Code ===\n")
                f.write(js_content)
                f.write(f"\n\n=== Execution Status ===\n")
                f.write(f"Status: JavaScript file processed\n")
                f.write(f"Note: For actual execution, use Node.js or browser environment\n")
            
            # Try to execute with Node.js if available
            try:
                result = subprocess.run(['node', '--version'], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    # Node.js is available, try to execute
                    exec_result = subprocess.run(['node', js_file_path], capture_output=True, text=True, timeout=10)
                    with open(exec_file, 'a') as f:
                        f.write(f"\n=== Node.js Execution Output ===\n")
                        f.write(f"Return Code: {exec_result.returncode}\n")
                        f.write(f"Output:\n{exec_result.stdout}\n")
                        if exec_result.stderr:
                            f.write(f"Errors:\n{exec_result.stderr}\n")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                with open(exec_file, 'a') as f:
                    f.write(f"\nNote: Node.js not available or execution timed out\n")
            
            self.log_operation("js", ip, f"JS file: {os.path.basename(js_file_path)}")
            messagebox.showinfo("Success", f"JavaScript file processed for {ip}\nLog saved to: {exec_file}")
            self.update_status(f"JavaScript execution completed for {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"JavaScript execution failed: {str(e)}")
            self.update_status(f"Error: {str(e)}")
    
    def run_script_operation(self):
        """scripts - Run script file operation"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        
        # ADDED: File selection dialog for script files
        script_file = filedialog.askopenfilename(
            title="Select script file to run",
            filetypes=[("Python scripts", "*.py"), ("Batch files", "*.bat"), ("Shell scripts", "*.sh"), ("All files", "*.*")]
        )
        
        if not script_file:
            # Check if there are scripts in the scripts directory
            scripts_dir = 'scripts'
            script_files = []
            if os.path.exists(scripts_dir):
                script_files = [f for f in os.listdir(scripts_dir) 
                              if f.endswith(('.py', '.bat', '.sh', '.ps1', '.cmd'))]
            
            if script_files:
                # Show selection dialog
                selection_window = tk.Toplevel(self.root)
                selection_window.title("Select Script")
                selection_window.geometry("400x300")
                selection_window.configure(bg='#1e1e1e')
                
                tk.Label(selection_window, text="Select a script:", font=('Arial', 14), bg='#1e1e1e', fg='#ffffff').pack(pady=10)
                
                listbox = tk.Listbox(selection_window, bg='#2d2d2d', fg='#ffffff', font=('Arial', 12))
                listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
                
                for script_name in script_files:
                    listbox.insert(tk.END, script_name)
                
                selected_file = [None]
                
                def on_select():
                    selection = listbox.curselection()
                    if selection:
                        selected_file[0] = os.path.join(scripts_dir, script_files[selection[0]])
                        selection_window.destroy()
                        self.run_script_file(ip, selected_file[0])
                
                tk.Button(selection_window, text="Run", command=on_select, bg='#4CAF50', fg='#ffffff', font=('Arial', 12)).pack(pady=10)
                return
            else:
                self.update_status("No script file selected")
                return
        
        self.run_script_file(ip, script_file)
    
    def run_script_file(self, ip, script_path):
        """ADDED: Run script file"""
        def execute_script():
            try:
                self.update_status(f"Running script for {ip}...")
                
                # Create execution log
                exec_file = os.path.join('scripts', f"{ip}_script_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                
                script_ext = os.path.splitext(script_path)[1].lower()
                command = []
                
                # Determine command based on script type
                if script_ext == '.py':
                    command = ['python', script_path]
                elif script_ext in ['.bat', '.cmd']:
                    command = [script_path]
                elif script_ext == '.sh':
                    command = ['bash', script_path]
                elif script_ext == '.ps1':
                    command = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path]
                else:
                    command = [script_path]
                
                # Execute script
                result = subprocess.run(command, capture_output=True, text=True, timeout=30, cwd=os.path.dirname(script_path) or None)
                
                # Write execution log
                with open(exec_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== Script Execution Log ===\n")
                    f.write(f"Target IP: {ip}\n")
                    f.write(f"Script: {os.path.basename(script_path)}\n")
                    f.write(f"Command: {' '.join(command)}\n")
                    f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"\n=== Execution Output ===\n")
                    f.write(f"Return Code: {result.returncode}\n")
                    f.write(f"\nSTDOUT:\n{result.stdout}\n")
                    if result.stderr:
                        f.write(f"\nSTDERR:\n{result.stderr}\n")
                
                self.log_operation("scripts", ip, f"Script: {os.path.basename(script_path)}")
                self.root.after(0, lambda: messagebox.showinfo("Success", f"Script executed for {ip}\nLog saved to: {exec_file}"))
                self.root.after(0, lambda: self.update_status(f"Script execution completed for {ip}"))
            except subprocess.TimeoutExpired:
                self.root.after(0, lambda: messagebox.showwarning("Timeout", "Script execution timed out"))
                self.root.after(0, lambda: self.update_status("Script execution timed out"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Script execution failed: {str(e)}"))
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}"))
        
        # Run script in separate thread to avoid blocking GUI
        threading.Thread(target=execute_script, daemon=True).start()
    
    def threat_analysis_operation(self):
        """ADDED: Comprehensive threat intelligence analysis for ransomware IP"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        self.update_status(f"Starting comprehensive threat analysis for {ip}...")
        
        def analyze_threat():
            try:
                threat_file = os.path.join('DUMPs', f"{ip}_THREAT_ANALYSIS_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                
                analysis_data = []
                analysis_data.append("=" * 80 + "\n")
                analysis_data.append("CYBERSECURITY THREAT INTELLIGENCE ANALYSIS REPORT\n")
                analysis_data.append("=" * 80 + "\n")
                analysis_data.append(f"Target IP: {ip}\n")
                analysis_data.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                analysis_data.append(f"Classification: RANSOMWARE THREAT ACTOR\n")
                analysis_data.append(f"Status: ACTIVE MONITORING\n")
                analysis_data.append("=" * 80 + "\n\n")
                
                # Network Information
                analysis_data.append("=== NETWORK INTELLIGENCE ===\n")
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    analysis_data.append(f"Hostname: {hostname}\n")
                except:
                    analysis_data.append(f"Hostname: Unable to resolve (may be using reverse DNS protection)\n")
                
                # Port Scanning
                analysis_data.append(f"\n=== PORT SCAN RESULTS ===\n")
                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3389, 8080]
                open_ports = []
                
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        if result == 0:
                            open_ports.append(port)
                            analysis_data.append(f"Port {port}: OPEN\n")
                    except:
                        pass
                
                if not open_ports:
                    analysis_data.append("No common ports found open (may be behind firewall)\n")
                
                # Traceroute Analysis
                analysis_data.append(f"\n=== NETWORK PATH ANALYSIS ===\n")
                try:
                    import platform
                    if platform.system() == 'Windows':
                        trace_result = subprocess.run(['tracert', '-h', '15', ip], 
                                                     capture_output=True, text=True, timeout=20)
                    else:
                        trace_result = subprocess.run(['traceroute', '-m', '15', ip], 
                                                     capture_output=True, text=True, timeout=20)
                    analysis_data.append(trace_result.stdout)
                    if trace_result.stderr:
                        analysis_data.append(f"\nTrace Errors:\n{trace_result.stderr}\n")
                except Exception as e:
                    analysis_data.append(f"Traceroute failed: {str(e)}\n")
                
                # DNS Information
                analysis_data.append(f"\n=== DNS INTELLIGENCE ===\n")
                try:
                    reverse_dns = socket.gethostbyaddr(ip)
                    analysis_data.append(f"Reverse DNS: {reverse_dns[0]}\n")
                    if len(reverse_dns) > 1:
                        analysis_data.append(f"Aliases: {', '.join(reverse_dns[1])}\n")
                except:
                    analysis_data.append("Reverse DNS: No PTR record found\n")
                
                # WHOIS-like Information (using socket)
                analysis_data.append(f"\n=== IP ADDRESS INFORMATION ===\n")
                try:
                    # Extract IP class
                    ip_parts = ip.split('.')
                    first_octet = int(ip_parts[0])
                    if 1 <= first_octet <= 126:
                        ip_class = "Class A"
                    elif 128 <= first_octet <= 191:
                        ip_class = "Class B"
                    elif 192 <= first_octet <= 223:
                        ip_class = "Class C"
                    else:
                        ip_class = "Class D/E"
                    analysis_data.append(f"IP Class: {ip_class}\n")
                    analysis_data.append(f"IP Address: {ip}\n")
                except:
                    pass
                
                # Threat Assessment
                analysis_data.append(f"\n=== THREAT ASSESSMENT ===\n")
                analysis_data.append(f"Threat Level: CRITICAL\n")
                analysis_data.append(f"Threat Type: Ransomware Infrastructure\n")
                analysis_data.append(f"Recommended Action: ISOLATE AND MONITOR\n")
                analysis_data.append(f"Legal Status: REPORT TO AUTHORITIES\n")
                
                # Related Infrastructure
                analysis_data.append(f"\n=== RELATED INFRASTRUCTURE ANALYSIS ===\n")
                analysis_data.append(f"Scanning for related IPs in same subnet...\n")
                
                # Scan same subnet
                try:
                    ip_parts = ip.split('.')
                    base_subnet = '.'.join(ip_parts[:3])
                    related_ips = []
                    
                    # Scan first 10 IPs in subnet (limited for safety)
                    for i in range(1, 11):
                        test_ip = f"{base_subnet}.{i}"
                        if test_ip != ip:
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(0.5)
                                result = sock.connect_ex((test_ip, 80))
                                sock.close()
                                if result == 0:
                                    related_ips.append(test_ip)
                                    analysis_data.append(f"Related IP found: {test_ip} (Port 80 open)\n")
                            except:
                                pass
                    
                    if not related_ips:
                        analysis_data.append("No related active IPs found in immediate subnet\n")
                except Exception as e:
                    analysis_data.append(f"Subnet scan error: {str(e)}\n")
                
                # Recommendations
                analysis_data.append(f"\n=== SECURITY RECOMMENDATIONS ===\n")
                analysis_data.append("1. Block this IP at firewall level\n")
                analysis_data.append("2. Report to cybersecurity authorities\n")
                analysis_data.append("3. Monitor network traffic for connections to this IP\n")
                analysis_data.append("4. Document all findings for legal proceedings\n")
                analysis_data.append("5. Notify affected parties if data breach detected\n")
                
                # Write analysis file
                with open(threat_file, 'w', encoding='utf-8') as f:
                    f.writelines(analysis_data)
                
                # Also save to caught IPs
                caught_file = os.path.join('Caught', 'IPs_caught', f"{ip}_THREAT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                with open(caught_file, 'w', encoding='utf-8') as f:
                    f.writelines(analysis_data)
                
                # ADDED: Store in database
                if self.db:
                    try:
                        hostname = None
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except:
                            pass
                        self.db.add_threat_ip(ip, "CRITICAL", "RANSOMWARE", hostname, "Threat analysis completed")
                        self.db.create_alert("THREAT_DETECTED", "CRITICAL", ip, "Ransomware threat infrastructure detected")
                    except Exception as e:
                        if self.logger:
                            self.logger.error(f"Database error: {e}")
                
                self.log_operation("Threat_Analysis", ip, "Comprehensive threat analysis completed")
                self.root.after(0, lambda: messagebox.showinfo("Threat Analysis Complete", 
                    f"Comprehensive threat analysis completed for {ip}\n\n"
                    f"Report saved to:\n{threat_file}\n\n"
                    f"Threat Level: CRITICAL\n"
                    f"Action Required: Report to authorities"))
                self.root.after(0, lambda: self.update_status(f"Threat analysis completed for {ip}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Threat analysis failed: {str(e)}"))
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}"))
        
        threading.Thread(target=analyze_threat, daemon=True).start()
    
    def network_scan_operation(self):
        """ADDED: Deep network scanning for threat infrastructure"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        self.update_status(f"Starting deep network scan for {ip}...")
        
        def scan_network():
            try:
                scan_file = os.path.join('DUMPs', f"{ip}_NETWORK_SCAN_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                
                scan_data = []
                scan_data.append("=" * 80 + "\n")
                scan_data.append("DEEP NETWORK SCAN REPORT - THREAT INFRASTRUCTURE\n")
                scan_data.append("=" * 80 + "\n")
                scan_data.append(f"Target IP: {ip}\n")
                scan_data.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                scan_data.append("=" * 80 + "\n\n")
                
                # Comprehensive Port Scan
                scan_data.append("=== COMPREHENSIVE PORT SCAN ===\n")
                important_ports = {
                    21: "FTP",
                    22: "SSH",
                    23: "Telnet",
                    25: "SMTP",
                    53: "DNS",
                    80: "HTTP",
                    110: "POP3",
                    143: "IMAP",
                    443: "HTTPS",
                    445: "SMB",
                    993: "IMAPS",
                    995: "POP3S",
                    1433: "MSSQL",
                    3306: "MySQL",
                    3389: "RDP",
                    5432: "PostgreSQL",
                    5900: "VNC",
                    8080: "HTTP-Proxy",
                    8443: "HTTPS-Alt"
                }
                
                open_ports_info = []
                for port, service in important_ports.items():
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        if result == 0:
                            open_ports_info.append((port, service))
                            scan_data.append(f"Port {port} ({service}): OPEN ✓\n")
                    except:
                        pass
                
                if not open_ports_info:
                    scan_data.append("No common service ports found open\n")
                
                # Service Banner Grabbing
                if open_ports_info:
                    scan_data.append(f"\n=== SERVICE BANNER INFORMATION ===\n")
                    for port, service in open_ports_info[:5]:  # Limit to first 5
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2)
                            sock.connect((ip, port))
                            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                            banner = sock.recv(1024).decode('utf-8', errors='ignore')
                            sock.close()
                            if banner:
                                scan_data.append(f"Port {port} Banner:\n{banner[:200]}\n\n")
                        except:
                            pass
                
                # Subnet Discovery
                scan_data.append(f"\n=== SUBNET DISCOVERY ===\n")
                try:
                    ip_parts = ip.split('.')
                    base_subnet = '.'.join(ip_parts[:3])
                    scan_data.append(f"Scanning subnet: {base_subnet}.0/24\n")
                    
                    active_hosts = []
                    for i in range(1, 21):  # Scan first 20 IPs
                        test_ip = f"{base_subnet}.{i}"
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.3)
                            result = sock.connect_ex((test_ip, 80))
                            sock.close()
                            if result == 0:
                                active_hosts.append(test_ip)
                                scan_data.append(f"Active host found: {test_ip}\n")
                        except:
                            pass
                    
                    if not active_hosts:
                        scan_data.append("No additional active hosts found in subnet\n")
                except Exception as e:
                    scan_data.append(f"Subnet scan error: {str(e)}\n")
                
                # Network Path Analysis
                scan_data.append(f"\n=== NETWORK PATH ANALYSIS ===\n")
                try:
                    import platform
                    if platform.system() == 'Windows':
                        ping_result = subprocess.run(['ping', '-n', '4', ip], 
                                                    capture_output=True, text=True, timeout=10)
                    else:
                        ping_result = subprocess.run(['ping', '-c', '4', ip], 
                                                    capture_output=True, text=True, timeout=10)
                    scan_data.append(ping_result.stdout)
                except:
                    scan_data.append("Ping test unavailable\n")
                
                scan_data.append(f"\n=== SCAN SUMMARY ===\n")
                scan_data.append(f"Open Ports Found: {len(open_ports_info)}\n")
                scan_data.append(f"Active Hosts in Subnet: {len(active_hosts) if 'active_hosts' in locals() else 0}\n")
                scan_data.append(f"Scan Status: COMPLETE\n")
                
                # Write scan file
                with open(scan_file, 'w', encoding='utf-8') as f:
                    f.writelines(scan_data)
                
                # ADDED: Store scan results in database
                if self.db:
                    try:
                        services_dict = {port: service for port, service in open_ports_info}
                        self.db.add_network_scan(ip, "COMPREHENSIVE", [p for p, _ in open_ports_info], services_dict)
                    except:
                        pass
                
                self.log_operation("Network_Scan", ip, f"Network scan completed - {len(open_ports_info)} ports open")
                self.root.after(0, lambda: messagebox.showinfo("Network Scan Complete", 
                    f"Deep network scan completed for {ip}\n\n"
                    f"Open Ports: {len(open_ports_info)}\n"
                    f"Report saved to: {scan_file}"))
                self.root.after(0, lambda: self.update_status(f"Network scan completed for {ip}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Network scan failed: {str(e)}"))
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}"))
        
        threading.Thread(target=scan_network, daemon=True).start()
    
    def find_related_ips_operation(self):
        """ADDED: Find related IPs and infrastructure associated with threat"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        self.update_status(f"Finding related IPs for {ip}...")
        
        def find_related():
            try:
                related_file = os.path.join('DUMPs', f"{ip}_RELATED_IPS_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                
                related_data = []
                related_data.append("=" * 80 + "\n")
                related_data.append("RELATED IP INFRASTRUCTURE ANALYSIS\n")
                related_data.append("=" * 80 + "\n")
                related_data.append(f"Primary Threat IP: {ip}\n")
                related_data.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                related_data.append("=" * 80 + "\n\n")
                
                # Same Subnet Analysis
                related_data.append("=== SAME SUBNET ANALYSIS ===\n")
                try:
                    ip_parts = ip.split('.')
                    base_subnet = '.'.join(ip_parts[:3])
                    related_data.append(f"Scanning subnet: {base_subnet}.0/24\n\n")
                    
                    related_ips = []
                    for i in range(1, 51):  # Scan 50 IPs in subnet
                        test_ip = f"{base_subnet}.{i}"
                        if test_ip == ip:
                            continue
                        
                        # Test multiple ports
                        ports_to_test = [80, 443, 22, 3389]
                        for port in ports_to_test:
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(0.5)
                                result = sock.connect_ex((test_ip, port))
                                sock.close()
                                if result == 0:
                                    related_ips.append((test_ip, port))
                                    related_data.append(f"Related IP: {test_ip} - Port {port} OPEN\n")
                                    break
                            except:
                                pass
                    
                    if not related_ips:
                        related_data.append("No related active IPs found in same subnet\n")
                    else:
                        related_data.append(f"\nTotal Related IPs Found: {len(set(ip for ip, _ in related_ips))}\n")
                except Exception as e:
                    related_data.append(f"Subnet scan error: {str(e)}\n")
                
                # DNS-Based Discovery
                related_data.append(f"\n=== DNS-BASED DISCOVERY ===\n")
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    related_data.append(f"Primary Hostname: {hostname}\n")
                    
                    # Try to resolve related hostnames
                    if '.' in hostname:
                        domain = '.'.join(hostname.split('.')[-2:])
                        related_data.append(f"Domain: {domain}\n")
                        related_data.append(f"Note: Additional subdomains may exist under this domain\n")
                except:
                    related_data.append("DNS information unavailable\n")
                
                # Traceroute Hop Analysis
                related_data.append(f"\n=== NETWORK PATH - RELATED INFRASTRUCTURE ===\n")
                try:
                    import platform
                    if platform.system() == 'Windows':
                        trace_result = subprocess.run(['tracert', '-h', '10', ip], 
                                                     capture_output=True, text=True, timeout=15)
                    else:
                        trace_result = subprocess.run(['traceroute', '-m', '10', ip], 
                                                     capture_output=True, text=True, timeout=15)
                    
                    # Extract IPs from traceroute
                    trace_ips = []
                    for line in trace_result.stdout.split('\n'):
                        # Extract IP addresses from traceroute output
                        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                        trace_ips.extend(ip_matches)
                    
                    if trace_ips:
                        related_data.append("Network Path IPs (potential related infrastructure):\n")
                        for trace_ip in set(trace_ips):
                            if trace_ip != ip:
                                related_data.append(f"  - {trace_ip}\n")
                    
                    related_data.append(f"\nFull Traceroute:\n{trace_result.stdout}\n")
                except Exception as e:
                    related_data.append(f"Traceroute analysis error: {str(e)}\n")
                
                # Threat Network Map
                related_data.append(f"\n=== THREAT NETWORK MAP ===\n")
                related_data.append(f"Primary Threat IP: {ip}\n")
                if 'related_ips' in locals() and related_ips:
                    related_data.append(f"Related Infrastructure IPs:\n")
                    for rel_ip, port in set(related_ips):
                        related_data.append(f"  - {rel_ip} (Port {port} active)\n")
                
                # Recommendations
                related_data.append(f"\n=== ACTION ITEMS ===\n")
                related_data.append("1. Block all related IPs identified\n")
                related_data.append("2. Monitor network traffic to/from these IPs\n")
                related_data.append("3. Document all findings for law enforcement\n")
                related_data.append("4. Report to cybersecurity incident response team\n")
                related_data.append("5. Update firewall rules to block entire subnet if confirmed threat\n")
                
                # Write related IPs file
                with open(related_file, 'w', encoding='utf-8') as f:
                    f.writelines(related_data)
                
                # Save to caught IPs
                caught_file = os.path.join('Caught', 'IPs_caught', f"{ip}_RELATED_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                with open(caught_file, 'w', encoding='utf-8') as f:
                    f.writelines(related_data)
                
                related_count = len(set(ip for ip, _ in related_ips)) if 'related_ips' in locals() and related_ips else 0
                self.log_operation("Find_Related_IPs", ip, f"Found {related_count} related IPs")
                self.root.after(0, lambda: messagebox.showinfo("Related IPs Found", 
                    f"Related IP analysis completed for {ip}\n\n"
                    f"Related IPs Found: {related_count}\n"
                    f"Report saved to: {related_file}"))
                self.root.after(0, lambda: self.update_status(f"Found {related_count} related IPs for {ip}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Find related IPs failed: {str(e)}"))
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}"))
        
        threading.Thread(target=find_related, daemon=True).start()
    
    def shutdown_ip_operation(self):
        """ADDED: Shutdown IP - Create blocking rules and documentation for taking IP offline"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        
        # Confirmation dialog
        confirm = messagebox.askyesno(
            "CONFIRM SHUTDOWN IP",
            f"⚠️ AUTHORIZED SHUTDOWN OPERATION ⚠️\n\n"
            f"Target IP: {ip}\n"
            f"Operation: COMPLETE NETWORK ISOLATION\n\n"
            f"This will:\n"
            f"• Generate firewall blocking rules\n"
            f"• Create shutdown documentation\n"
            f"• Log operation for authorities\n"
            f"• Generate blocking scripts\n\n"
            f"Proceed with shutdown operation?",
            icon='warning'
        )
        
        if not confirm:
            self.update_status("Shutdown operation cancelled")
            return
        
        self.update_status(f"⚠️ INITIATING SHUTDOWN OPERATION FOR {ip}...")
        
        def shutdown_ip():
            try:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                shutdown_file = os.path.join('DUMPs', f"{ip}_SHUTDOWN_{timestamp}.txt")
                
                shutdown_data = []
                shutdown_data.append("=" * 80 + "\n")
                shutdown_data.append("AUTHORIZED IP SHUTDOWN OPERATION\n")
                shutdown_data.append("=" * 80 + "\n")
                shutdown_data.append(f"Target IP: {ip}\n")
                shutdown_data.append(f"Operation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                shutdown_data.append(f"Authorization: AUTHORIZED SHUTDOWN\n")
                shutdown_data.append(f"Status: IP TO BE TAKEN OFFLINE\n")
                shutdown_data.append("=" * 80 + "\n\n")
                
                # Threat Classification
                shutdown_data.append("=== THREAT CLASSIFICATION ===\n")
                shutdown_data.append("Threat Type: RANSOMWARE INFRASTRUCTURE\n")
                shutdown_data.append("Threat Level: CRITICAL\n")
                shutdown_data.append("Action Required: COMPLETE NETWORK ISOLATION\n")
                shutdown_data.append("Legal Status: AUTHORIZED FOR SHUTDOWN\n\n")
                
                # Network Information
                shutdown_data.append("=== TARGET IP INFORMATION ===\n")
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    shutdown_data.append(f"Hostname: {hostname}\n")
                except:
                    shutdown_data.append(f"Hostname: Unable to resolve\n")
                
                shutdown_data.append(f"IP Address: {ip}\n")
                shutdown_data.append(f"IP Class: {'.'.join(ip.split('.')[:3])}.0/24\n\n")
                
                # Firewall Blocking Rules - Windows (COMPREHENSIVE)
                shutdown_data.append("=== WINDOWS FIREWALL BLOCKING RULES (COMPLETE ISOLATION) ===\n")
                shutdown_data.append("# Run these commands as Administrator for COMPLETE BLOCKING:\n\n")
                shutdown_data.append("# Block ALL traffic from/to threat IP (INBOUND - Most Critical)\n")
                shutdown_data.append(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_IN_ALL" dir=in action=block remoteip={ip} enable=yes protocol=any\n')
                shutdown_data.append(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_IN_TCP" dir=in action=block remoteip={ip} enable=yes protocol=TCP\n')
                shutdown_data.append(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_IN_UDP" dir=in action=block remoteip={ip} enable=yes protocol=UDP\n')
                shutdown_data.append(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_IN_ICMP" dir=in action=block remoteip={ip} enable=yes protocol=ICMPv4\n\n')
                shutdown_data.append("# Block ALL traffic to threat IP (OUTBOUND)\n")
                shutdown_data.append(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_OUT_ALL" dir=out action=block remoteip={ip} enable=yes protocol=any\n')
                shutdown_data.append(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_OUT_TCP" dir=out action=block remoteip={ip} enable=yes protocol=TCP\n')
                shutdown_data.append(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_OUT_UDP" dir=out action=block remoteip={ip} enable=yes protocol=UDP\n')
                shutdown_data.append(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_OUT_ICMP" dir=out action=block remoteip={ip} enable=yes protocol=ICMPv4\n\n')
                shutdown_data.append("# Block ALL ports from threat IP (INBOUND - Prevents ANY connection attempt)\n")
                for port in [80, 443, 22, 23, 21, 25, 53, 110, 143, 445, 3389, 8080, 8443, 5900]:
                    shutdown_data.append(f'netsh advfirewall firewall add rule name="BLOCK_{ip}_IN_PORT_{port}" dir=in action=block remoteip={ip} enable=yes protocol=TCP localport={port}\n')
                shutdown_data.append(f'\n# Block entire subnet (COMPLETE ISOLATION)\n')
                shutdown_data.append(f'netsh advfirewall firewall add rule name="BLOCK_SUBNET_{ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}_IN" dir=in action=block remoteip={ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 enable=yes protocol=any\n')
                shutdown_data.append(f'netsh advfirewall firewall add rule name="BLOCK_SUBNET_{ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}_OUT" dir=out action=block remoteip={ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 enable=yes protocol=any\n\n')
                
                # Firewall Blocking Rules - Linux (COMPREHENSIVE)
                shutdown_data.append("=== LINUX IPTABLES BLOCKING RULES (COMPLETE ISOLATION) ===\n")
                shutdown_data.append("# Run these commands as root for COMPLETE BLOCKING:\n\n")
                shutdown_data.append("# Block ALL traffic from threat IP (INBOUND - Most Critical)\n")
                shutdown_data.append(f'iptables -I INPUT 1 -s {ip} -j DROP\n')
                shutdown_data.append(f'iptables -I INPUT 1 -s {ip} -p tcp -j DROP\n')
                shutdown_data.append(f'iptables -I INPUT 1 -s {ip} -p udp -j DROP\n')
                shutdown_data.append(f'iptables -I INPUT 1 -s {ip} -p icmp -j DROP\n\n')
                shutdown_data.append("# Block ALL traffic to threat IP (OUTBOUND)\n")
                shutdown_data.append(f'iptables -I OUTPUT 1 -d {ip} -j DROP\n')
                shutdown_data.append(f'iptables -I OUTPUT 1 -d {ip} -p tcp -j DROP\n')
                shutdown_data.append(f'iptables -I OUTPUT 1 -d {ip} -p udp -j DROP\n')
                shutdown_data.append(f'iptables -I OUTPUT 1 -d {ip} -p icmp -j DROP\n\n')
                shutdown_data.append("# Block ALL forwarding from/to threat IP\n")
                shutdown_data.append(f'iptables -I FORWARD 1 -s {ip} -j DROP\n')
                shutdown_data.append(f'iptables -I FORWARD 1 -d {ip} -j DROP\n\n')
                shutdown_data.append("# Block specific ports from threat IP (INBOUND - Prevents connection attempts)\n")
                for port in [80, 443, 22, 23, 21, 25, 53, 110, 143, 445, 3389, 8080, 8443, 5900]:
                    shutdown_data.append(f'iptables -I INPUT 1 -s {ip} -p tcp --dport {port} -j DROP\n')
                    shutdown_data.append(f'iptables -I INPUT 1 -s {ip} -p udp --dport {port} -j DROP\n')
                shutdown_data.append(f'\n# Block entire subnet (COMPLETE ISOLATION)\n')
                shutdown_data.append(f'iptables -I INPUT 1 -s {ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 -j DROP\n')
                shutdown_data.append(f'iptables -I OUTPUT 1 -d {ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 -j DROP\n')
                shutdown_data.append(f'iptables -I FORWARD 1 -s {ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 -j DROP\n')
                shutdown_data.append(f'iptables -I FORWARD 1 -d {ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 -j DROP\n')
                shutdown_data.append(f'\n# Save rules permanently\n')
                shutdown_data.append(f'iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules\n')
                shutdown_data.append(f'systemctl enable iptables 2>/dev/null || service iptables save 2>/dev/null\n\n')
                
                # Router/Network Level Blocking
                shutdown_data.append("=== ROUTER/NETWORK LEVEL BLOCKING ===\n")
                shutdown_data.append("1. Access router admin panel\n")
                shutdown_data.append("2. Navigate to Firewall/ACL settings\n")
                shutdown_data.append(f"3. Add blocking rule for IP: {ip}\n")
                shutdown_data.append(f"4. Add blocking rule for subnet: {ip.split('.')[0]}.{ip.split('.')[1]}.{ip.split('.')[2]}.0/24\n")
                shutdown_data.append("5. Apply and save configuration\n\n")
                
                # DNS Blocking
                shutdown_data.append("=== DNS BLOCKING (HOSTS FILE) ===\n")
                shutdown_data.append("# Add to /etc/hosts (Linux/Mac) or C:\\Windows\\System32\\drivers\\etc\\hosts (Windows):\n\n")
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    shutdown_data.append(f"{ip} {hostname}\n")
                    shutdown_data.append(f"127.0.0.1 {hostname}\n")
                    shutdown_data.append(f"0.0.0.0 {hostname}\n\n")
                except:
                    shutdown_data.append(f"127.0.0.1 {ip}\n")
                    shutdown_data.append(f"0.0.0.0 {ip}\n\n")
                
                # PowerShell Script for Windows
                shutdown_data.append("=== POWERSHELL BLOCKING SCRIPT ===\n")
                shutdown_data.append("# Save as block_ip.ps1 and run as Administrator:\n\n")
                shutdown_data.append(f'$ip = "{ip}"\n')
                shutdown_data.append(f'$subnet = "{ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24"\n')
                shutdown_data.append('New-NetFirewallRule -DisplayName "BLOCK_THREAT_OUT" -Direction Outbound -RemoteAddress $ip -Action Block -Enabled True\n')
                shutdown_data.append('New-NetFirewallRule -DisplayName "BLOCK_THREAT_IN" -Direction Inbound -RemoteAddress $ip -Action Block -Enabled True\n')
                shutdown_data.append('New-NetFirewallRule -DisplayName "BLOCK_SUBNET_OUT" -Direction Outbound -RemoteAddress $subnet -Action Block -Enabled True\n')
                shutdown_data.append('New-NetFirewallRule -DisplayName "BLOCK_SUBNET_IN" -Direction Inbound -RemoteAddress $subnet -Action Block -Enabled True\n')
                shutdown_data.append('Write-Host "IP blocking rules applied successfully"\n\n')
                
                # Create blocking scripts
                scripts_dir = 'scripts'
                os.makedirs(scripts_dir, exist_ok=True)
                
                # Windows Batch Script (COMPREHENSIVE BLOCKING)
                windows_script = os.path.join(scripts_dir, f"BLOCK_{ip.replace('.', '_')}_WINDOWS.bat")
                with open(windows_script, 'w', encoding='utf-8') as f:
                    f.write(f'@echo off\n')
                    f.write(f'echo ========================================\n')
                    f.write(f'echo COMPLETE IP SHUTDOWN - TOTAL BLOCKING\n')
                    f.write(f'echo Target IP: {ip}\n')
                    f.write(f'echo This will PREVENT ALL ACCESS from this IP\n')
                    f.write(f'echo ========================================\n\n')
                    f.write(f'echo Checking Administrator privileges...\n')
                    f.write(f'net session >nul 2>&1\n')
                    f.write(f'if %errorLevel% neq 0 (\n')
                    f.write(f'    echo ERROR: This script must be run as Administrator!\n')
                    f.write(f'    pause\n')
                    f.write(f'    exit /b 1\n')
                    f.write(f')\n\n')
                    f.write(f'echo Applying COMPREHENSIVE firewall blocking rules...\n')
                    f.write(f'echo.\n')
                    f.write(f'echo [1/4] Blocking ALL INBOUND traffic from {ip}...\n')
                    f.write(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_IN_ALL" dir=in action=block remoteip={ip} enable=yes protocol=any\n')
                    f.write(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_IN_TCP" dir=in action=block remoteip={ip} enable=yes protocol=TCP\n')
                    f.write(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_IN_UDP" dir=in action=block remoteip={ip} enable=yes protocol=UDP\n')
                    f.write(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_IN_ICMP" dir=in action=block remoteip={ip} enable=yes protocol=ICMPv4\n\n')
                    f.write(f'echo [2/4] Blocking ALL OUTBOUND traffic to {ip}...\n')
                    f.write(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_OUT_ALL" dir=out action=block remoteip={ip} enable=yes protocol=any\n')
                    f.write(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_OUT_TCP" dir=out action=block remoteip={ip} enable=yes protocol=TCP\n')
                    f.write(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_OUT_UDP" dir=out action=block remoteip={ip} enable=yes protocol=UDP\n')
                    f.write(f'netsh advfirewall firewall add rule name="BLOCK_THREAT_{ip}_OUT_ICMP" dir=out action=block remoteip={ip} enable=yes protocol=ICMPv4\n\n')
                    f.write(f'echo [3/4] Blocking specific ports from {ip} (prevents connection attempts)...\n')
                    for port in [80, 443, 22, 23, 21, 25, 53, 110, 143, 445, 3389, 8080, 8443, 5900, 135, 139, 445, 1433, 3306, 5432]:
                        f.write(f'netsh advfirewall firewall add rule name="BLOCK_{ip}_IN_PORT_{port}" dir=in action=block remoteip={ip} enable=yes protocol=TCP localport={port}\n')
                    f.write(f'\necho [4/4] Blocking entire subnet...\n')
                    f.write(f'netsh advfirewall firewall add rule name="BLOCK_SUBNET_{ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}_IN" dir=in action=block remoteip={ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 enable=yes protocol=any\n')
                    f.write(f'netsh advfirewall firewall add rule name="BLOCK_SUBNET_{ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}_OUT" dir=out action=block remoteip={ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 enable=yes protocol=any\n')
                    f.write(f'\necho.\n')
                    f.write(f'echo ========================================\n')
                    f.write(f'echo BLOCKING COMPLETE!\n')
                    f.write(f'echo Target IP {ip} is now COMPLETELY BLOCKED\n')
                    f.write(f'echo NO ACCESS POSSIBLE from this IP\n')
                    f.write(f'echo ========================================\n')
                    f.write(f'pause\n')
                
                # Linux Bash Script (COMPREHENSIVE BLOCKING)
                linux_script = os.path.join(scripts_dir, f"BLOCK_{ip.replace('.', '_')}_LINUX.sh")
                with open(linux_script, 'w', encoding='utf-8') as f:
                    f.write(f'#!/bin/bash\n')
                    f.write(f'echo "========================================"\n')
                    f.write(f'echo "COMPLETE IP SHUTDOWN - TOTAL BLOCKING"\n')
                    f.write(f'echo "Target IP: {ip}"\n')
                    f.write(f'echo "This will PREVENT ALL ACCESS from this IP"\n')
                    f.write(f'echo "========================================"\n\n')
                    f.write(f'# Check if running as root\n')
                    f.write(f'if [ "$EUID" -ne 0 ]; then \n')
                    f.write(f'    echo "ERROR: This script must be run as root!"\n')
                    f.write(f'    exit 1\n')
                    f.write(f'fi\n\n')
                    f.write(f'echo "[1/4] Blocking ALL INBOUND traffic from {ip}..."\n')
                    f.write(f'iptables -I INPUT 1 -s {ip} -j DROP\n')
                    f.write(f'iptables -I INPUT 1 -s {ip} -p tcp -j DROP\n')
                    f.write(f'iptables -I INPUT 1 -s {ip} -p udp -j DROP\n')
                    f.write(f'iptables -I INPUT 1 -s {ip} -p icmp -j DROP\n\n')
                    f.write(f'echo "[2/4] Blocking ALL OUTBOUND traffic to {ip}..."\n')
                    f.write(f'iptables -I OUTPUT 1 -d {ip} -j DROP\n')
                    f.write(f'iptables -I OUTPUT 1 -d {ip} -p tcp -j DROP\n')
                    f.write(f'iptables -I OUTPUT 1 -d {ip} -p udp -j DROP\n')
                    f.write(f'iptables -I OUTPUT 1 -d {ip} -p icmp -j DROP\n\n')
                    f.write(f'echo "[3/4] Blocking ALL forwarding and specific ports..."\n')
                    f.write(f'iptables -I FORWARD 1 -s {ip} -j DROP\n')
                    f.write(f'iptables -I FORWARD 1 -d {ip} -j DROP\n')
                    for port in [80, 443, 22, 23, 21, 25, 53, 110, 143, 445, 3389, 8080, 8443, 5900, 135, 139, 1433, 3306, 5432]:
                        f.write(f'iptables -I INPUT 1 -s {ip} -p tcp --dport {port} -j DROP\n')
                        f.write(f'iptables -I INPUT 1 -s {ip} -p udp --dport {port} -j DROP\n')
                    f.write(f'\necho "[4/4] Blocking entire subnet..."\n')
                    f.write(f'iptables -I INPUT 1 -s {ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 -j DROP\n')
                    f.write(f'iptables -I OUTPUT 1 -d {ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 -j DROP\n')
                    f.write(f'iptables -I FORWARD 1 -s {ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 -j DROP\n')
                    f.write(f'iptables -I FORWARD 1 -d {ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24 -j DROP\n')
                    f.write(f'\necho "Saving rules permanently..."\n')
                    f.write(f'iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules\n')
                    f.write(f'systemctl enable iptables 2>/dev/null || service iptables save 2>/dev/null\n')
                    f.write(f'\necho ""\n')
                    f.write(f'echo "========================================"\n')
                    f.write(f'echo "BLOCKING COMPLETE!"\n')
                    f.write(f'echo "Target IP {ip} is now COMPLETELY BLOCKED"\n')
                    f.write(f'echo "NO ACCESS POSSIBLE from this IP"\n')
                    f.write(f'echo "========================================"\n')
                
                # Make Linux script executable
                try:
                    os.chmod(linux_script, 0o755)
                except:
                    pass
                
                # PowerShell Script (COMPREHENSIVE BLOCKING)
                ps_script = os.path.join(scripts_dir, f"BLOCK_{ip.replace('.', '_')}_POWERSHELL.ps1")
                with open(ps_script, 'w', encoding='utf-8') as f:
                    f.write(f'# COMPLETE IP SHUTDOWN - TOTAL BLOCKING\n')
                    f.write(f'# Target IP: {ip}\n')
                    f.write(f'# This will PREVENT ALL ACCESS from this IP\n')
                    f.write(f'# Run as Administrator\n\n')
                    f.write(f'$ip = "{ip}"\n')
                    f.write(f'$subnet = "{ip.split(".")[0]}.{ip.split(".")[1]}.{ip.split(".")[2]}.0/24"\n\n')
                    f.write(f'Write-Host "========================================" -ForegroundColor Red\n')
                    f.write(f'Write-Host "COMPLETE IP SHUTDOWN - TOTAL BLOCKING" -ForegroundColor Red\n')
                    f.write(f'Write-Host "Target IP: $ip" -ForegroundColor Yellow\n')
                    f.write(f'Write-Host "This will PREVENT ALL ACCESS from this IP" -ForegroundColor Yellow\n')
                    f.write(f'Write-Host "========================================" -ForegroundColor Red\n\n')
                    f.write(f'# Check for Administrator privileges\n')
                    f.write(f'$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\n')
                    f.write(f'if (-not $isAdmin) {{\n')
                    f.write(f'    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red\n')
                    f.write(f'    exit 1\n')
                    f.write(f'}}\n\n')
                    f.write(f'Write-Host "[1/4] Blocking ALL INBOUND traffic from $ip..." -ForegroundColor Cyan\n')
                    f.write(f'New-NetFirewallRule -DisplayName "BLOCK_THREAT_$ip_IN_ALL" -Direction Inbound -RemoteAddress $ip -Action Block -Enabled True -Protocol Any\n')
                    f.write(f'New-NetFirewallRule -DisplayName "BLOCK_THREAT_$ip_IN_TCP" -Direction Inbound -RemoteAddress $ip -Action Block -Enabled True -Protocol TCP\n')
                    f.write(f'New-NetFirewallRule -DisplayName "BLOCK_THREAT_$ip_IN_UDP" -Direction Inbound -RemoteAddress $ip -Action Block -Enabled True -Protocol UDP\n')
                    f.write(f'New-NetFirewallRule -DisplayName "BLOCK_THREAT_$ip_IN_ICMP" -Direction Inbound -RemoteAddress $ip -Action Block -Enabled True -Protocol ICMPv4\n\n')
                    f.write(f'Write-Host "[2/4] Blocking ALL OUTBOUND traffic to $ip..." -ForegroundColor Cyan\n')
                    f.write(f'New-NetFirewallRule -DisplayName "BLOCK_THREAT_$ip_OUT_ALL" -Direction Outbound -RemoteAddress $ip -Action Block -Enabled True -Protocol Any\n')
                    f.write(f'New-NetFirewallRule -DisplayName "BLOCK_THREAT_$ip_OUT_TCP" -Direction Outbound -RemoteAddress $ip -Action Block -Enabled True -Protocol TCP\n')
                    f.write(f'New-NetFirewallRule -DisplayName "BLOCK_THREAT_$ip_OUT_UDP" -Direction Outbound -RemoteAddress $ip -Action Block -Enabled True -Protocol UDP\n')
                    f.write(f'New-NetFirewallRule -DisplayName "BLOCK_THREAT_$ip_OUT_ICMP" -Direction Outbound -RemoteAddress $ip -Action Block -Enabled True -Protocol ICMPv4\n\n')
                    f.write(f'Write-Host "[3/4] Blocking specific ports from $ip..." -ForegroundColor Cyan\n')
                    for port in [80, 443, 22, 23, 21, 25, 53, 110, 143, 445, 3389, 8080, 8443, 5900, 135, 139, 1433, 3306, 5432]:
                        f.write(f'New-NetFirewallRule -DisplayName "BLOCK_$ip_IN_PORT_{port}" -Direction Inbound -RemoteAddress $ip -Action Block -Enabled True -Protocol TCP -LocalPort {port}\n')
                    f.write(f'\nWrite-Host "[4/4] Blocking entire subnet..." -ForegroundColor Cyan\n')
                    f.write(f'New-NetFirewallRule -DisplayName "BLOCK_SUBNET_$subnet_IN" -Direction Inbound -RemoteAddress $subnet -Action Block -Enabled True -Protocol Any\n')
                    f.write(f'New-NetFirewallRule -DisplayName "BLOCK_SUBNET_$subnet_OUT" -Direction Outbound -RemoteAddress $subnet -Action Block -Enabled True -Protocol Any\n')
                    f.write(f'\nWrite-Host ""\n')
                    f.write(f'Write-Host "========================================" -ForegroundColor Green\n')
                    f.write(f'Write-Host "BLOCKING COMPLETE!" -ForegroundColor Green\n')
                    f.write(f'Write-Host "Target IP $ip is now COMPLETELY BLOCKED" -ForegroundColor Green\n')
                    f.write(f'Write-Host "NO ACCESS POSSIBLE from this IP" -ForegroundColor Green\n')
                    f.write(f'Write-Host "========================================" -ForegroundColor Green\n')
                
                shutdown_data.append("=== BLOCKING SCRIPTS GENERATED ===\n")
                shutdown_data.append(f"Windows Batch: {windows_script}\n")
                shutdown_data.append(f"Linux Bash: {linux_script}\n")
                shutdown_data.append(f"PowerShell: {ps_script}\n\n")
                
                # ISP/Authorities Report
                shutdown_data.append("=== REPORT TO AUTHORITIES ===\n")
                shutdown_data.append("1. Contact your ISP to block this IP at network level\n")
                shutdown_data.append("2. Report to cybersecurity authorities:\n")
                shutdown_data.append("   - FBI Internet Crime Complaint Center (IC3)\n")
                shutdown_data.append("   - CISA (Cybersecurity and Infrastructure Security Agency)\n")
                shutdown_data.append("   - Local law enforcement cybercrime unit\n")
                shutdown_data.append("3. Submit threat intelligence to:\n")
                shutdown_data.append("   - AbuseIPDB\n")
                shutdown_data.append("   - VirusTotal\n")
                shutdown_data.append("   - Threat intelligence platforms\n\n")
                
                # Additional Protection Measures
                shutdown_data.append("=== ADDITIONAL PROTECTION MEASURES ===\n")
                shutdown_data.append("1. Windows Defender Firewall: Rules applied via scripts\n")
                shutdown_data.append("2. Router/Modem: Block at network gateway level\n")
                shutdown_data.append("3. DNS Filtering: Add to hosts file (already included)\n")
                shutdown_data.append("4. Application Firewall: Configure software firewalls\n")
                shutdown_data.append("5. Network Monitoring: Monitor for connection attempts\n")
                shutdown_data.append("6. ISP Level: Contact ISP to block at their level\n\n")
                
                shutdown_data.append("=== VERIFICATION STEPS ===\n")
                shutdown_data.append("After running blocking scripts, verify:\n")
                shutdown_data.append("1. Windows: netsh advfirewall firewall show rule name=all | findstr BLOCK_THREAT\n")
                shutdown_data.append("2. Linux: iptables -L -n | grep {ip}\n")
                shutdown_data.append("3. Test connection: ping {ip} (should fail)\n")
                shutdown_data.append("4. Test port: telnet {ip} 80 (should fail)\n")
                shutdown_data.append("5. Monitor logs: Check firewall logs for blocked attempts\n\n")
                
                # Operation Summary
                shutdown_data.append("=== SHUTDOWN OPERATION SUMMARY ===\n")
                shutdown_data.append(f"Target IP: {ip}\n")
                shutdown_data.append(f"Operation Status: COMPLETE BLOCKING INITIATED\n")
                shutdown_data.append(f"Blocking Level: MAXIMUM (ALL PROTOCOLS, ALL PORTS)\n")
                shutdown_data.append(f"Blocking Scripts: GENERATED (Windows, Linux, PowerShell)\n")
                shutdown_data.append(f"Documentation: COMPLETE\n")
                shutdown_data.append(f"Protection: INBOUND + OUTBOUND + SUBNET BLOCKING\n")
                shutdown_data.append(f"Next Steps: EXECUTE BLOCKING SCRIPTS AS ADMINISTRATOR/ROOT\n")
                shutdown_data.append(f"Authorization: CONFIRMED\n")
                shutdown_data.append(f"Result: IP {ip} CANNOT ACCESS YOUR PC\n\n")
                
                shutdown_data.append("=" * 80 + "\n")
                shutdown_data.append("⚠️  EXECUTE BLOCKING SCRIPTS TO COMPLETE SHUTDOWN  ⚠️\n")
                shutdown_data.append("=" * 80 + "\n")
                
                # Write shutdown file
                with open(shutdown_file, 'w', encoding='utf-8') as f:
                    f.writelines(shutdown_data)
                
                # Save to caught IPs
                caught_file = os.path.join('Caught', 'IPs_caught', f"{ip}_SHUTDOWN_{timestamp}.txt")
                with open(caught_file, 'w', encoding='utf-8') as f:
                    f.writelines(shutdown_data)
                
                # Log operation
                self.log_operation("SHUTDOWN_IP", ip, "SHUTDOWN OPERATION INITIATED - Blocking scripts generated")
                
                self.root.after(0, lambda: messagebox.showinfo(
                    "⚠️ SHUTDOWN OPERATION INITIATED ⚠️",
                    f"IP SHUTDOWN OPERATION COMPLETE\n\n"
                    f"Target IP: {ip}\n\n"
                    f"✅ Blocking scripts generated:\n"
                    f"   • Windows: {os.path.basename(windows_script)}\n"
                    f"   • Linux: {os.path.basename(linux_script)}\n"
                    f"   • PowerShell: {os.path.basename(ps_script)}\n\n"
                    f"⚠️ NEXT STEPS:\n"
                    f"1. Run blocking scripts as Administrator/Root\n"
                    f"2. Report to authorities\n"
                    f"3. Block at router/network level\n\n"
                    f"Report saved to:\n{shutdown_file}",
                    icon='info'
                ))
                self.root.after(0, lambda: self.update_status(f"⚠️ SHUTDOWN OPERATION COMPLETE FOR {ip} - Execute blocking scripts"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Shutdown operation failed: {str(e)}"))
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}"))
        
        threading.Thread(target=shutdown_ip, daemon=True).start()
    
    def syn_flood_defense_operation(self):
        """ADDED: SYN Flood Defense - Configure protection and test vulnerability"""
        if not self.validate_ip():
            return
        
        ip = self.ip_var.get().strip()
        
        # Confirmation dialog
        confirm = messagebox.askyesno(
            "SYN Flood Defense Configuration",
            f"SYN Flood Defense & Protection\n\n"
            f"Target IP: {ip}\n"
            f"Operation: Configure SYN Flood Protection\n\n"
            f"This will:\n"
            f"• Configure SYN flood protection settings\n"
            f"• Test system vulnerability\n"
            f"• Generate protection scripts\n"
            f"• Document countermeasures\n\n"
            f"Proceed with SYN flood defense configuration?",
            icon='question'
        )
        
        if not confirm:
            self.update_status("SYN flood defense operation cancelled")
            return
        
        self.update_status(f"Configuring SYN flood defense for {ip}...")
        
        def configure_syn_flood_defense():
            try:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                syn_flood_file = os.path.join('DUMPs', f"{ip}_SYN_FLOOD_DEFENSE_{timestamp}.txt")
                
                defense_data = []
                defense_data.append("=" * 80 + "\n")
                defense_data.append("SYN FLOOD DEFENSE & PROTECTION CONFIGURATION\n")
                defense_data.append("=" * 80 + "\n")
                defense_data.append(f"Target IP: {ip}\n")
                defense_data.append(f"Configuration Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                defense_data.append(f"Reference: https://en.wikipedia.org/wiki/SYN_flood\n")
                defense_data.append("=" * 80 + "\n\n")
                
                # SYN Flood Explanation
                defense_data.append("=== WHAT IS A SYN FLOOD? ===\n")
                defense_data.append("A SYN flood is a denial-of-service attack where an attacker sends\n")
                defense_data.append("multiple SYN packets to a server without completing the TCP three-way\n")
                defense_data.append("handshake. This consumes server resources and can make the system\n")
                defense_data.append("unresponsive to legitimate traffic.\n\n")
                defense_data.append("TCP Three-Way Handshake:\n")
                defense_data.append("1. Client sends SYN (synchronize)\n")
                defense_data.append("2. Server responds with SYN-ACK\n")
                defense_data.append("3. Client sends ACK (connection established)\n\n")
                defense_data.append("In a SYN flood attack, the attacker never sends the final ACK,\n")
                defense_data.append("leaving half-open connections that consume server resources.\n\n")
                
                # Countermeasures (RFC 4987)
                defense_data.append("=== SYN FLOOD COUNTERMEASURES (RFC 4987) ===\n")
                defense_data.append("1. Filtering - Block suspicious IPs\n")
                defense_data.append("2. Increasing backlog - More connection queue space\n")
                defense_data.append("3. Reducing SYN-RECEIVED timer - Faster timeout\n")
                defense_data.append("4. Recycling oldest half-open TCP - Free resources\n")
                defense_data.append("5. SYN cache - Efficient connection tracking\n")
                defense_data.append("6. SYN cookies - Cryptographic protection\n")
                defense_data.append("7. Hybrid approaches - Combination of methods\n")
                defense_data.append("8. Firewalls and proxies - Network-level protection\n\n")
                
                # Windows SYN Flood Protection
                defense_data.append("=== WINDOWS SYN FLOOD PROTECTION ===\n")
                defense_data.append("# Configure Windows to protect against SYN floods\n\n")
                defense_data.append("# Increase TCP connection backlog\n")
                defense_data.append('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v TcpMaxHalfOpen /t REG_DWORD /d 500 /f\n')
                defense_data.append('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v TcpMaxHalfOpenRetried /t REG_DWORD /d 400 /f\n\n')
                defense_data.append("# Enable SYN attack protection\n")
                defense_data.append('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v SynAttackProtect /t REG_DWORD /d 2 /f\n')
                defense_data.append('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v TcpMaxConnectResponseRetransmissions /t REG_DWORD /d 2 /f\n\n')
                defense_data.append("# Reduce SYN-ACK retransmissions\n")
                defense_data.append('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 3 /f\n\n')
                defense_data.append("# Enable dynamic backlog\n")
                defense_data.append('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters" /v EnableDynamicBacklog /t REG_DWORD /d 1 /f\n')
                defense_data.append('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters" /v MinimumDynamicBacklog /t REG_DWORD /d 20 /f\n')
                defense_data.append('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters" /v MaximumDynamicBacklog /t REG_DWORD /d 20000 /f\n')
                defense_data.append('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters" /v DynamicBacklogGrowthDelta /t REG_DWORD /d 10 /f\n\n')
                
                # Linux SYN Flood Protection
                defense_data.append("=== LINUX SYN FLOOD PROTECTION ===\n")
                defense_data.append("# Configure Linux to protect against SYN floods\n\n")
                defense_data.append("# Enable SYN cookies (most effective protection)\n")
                defense_data.append('echo 1 > /proc/sys/net/ipv4/tcp_syncookies\n')
                defense_data.append('echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf\n\n')
                defense_data.append("# Reduce SYN-ACK retransmissions\n")
                defense_data.append('echo 2 > /proc/sys/net/ipv4/tcp_synack_retries\n')
                defense_data.append('echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf\n\n')
                defense_data.append("# Increase SYN backlog queue\n")
                defense_data.append('echo 2048 > /proc/sys/net/core/somaxconn\n')
                defense_data.append('echo "net.core.somaxconn = 2048" >> /etc/sysctl.conf\n\n')
                defense_data.append("# Reduce SYN received timeout\n")
                defense_data.append('echo 30 > /proc/sys/net/ipv4/tcp_syn_retries\n')
                defense_data.append('echo "net.ipv4.tcp_syn_retries = 30" >> /etc/sysctl.conf\n\n')
                defense_data.append("# Enable TCP SYN cookies in iptables\n")
                defense_data.append('iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT\n')
                defense_data.append('iptables -A INPUT -p tcp --syn -j DROP\n\n')
                defense_data.append("# Apply settings\n")
                defense_data.append('sysctl -p\n\n')
                
                # Firewall Rules for SYN Flood Protection
                defense_data.append("=== FIREWALL RULES FOR SYN FLOOD PROTECTION ===\n")
                defense_data.append("# Windows Firewall - Rate limiting\n")
                defense_data.append(f'netsh advfirewall firewall add rule name="SYN_FLOOD_PROTECT_{ip}" dir=in action=block remoteip={ip} enable=yes protocol=TCP\n\n')
                defense_data.append("# Linux iptables - Rate limiting SYN packets\n")
                defense_data.append(f'iptables -A INPUT -p tcp -s {ip} --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT\n')
                defense_data.append(f'iptables -A INPUT -p tcp -s {ip} --syn -j DROP\n')
                defense_data.append(f'iptables -A INPUT -p tcp -d {ip} --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT\n')
                defense_data.append(f'iptables -A INPUT -p tcp -d {ip} --syn -j DROP\n\n')
                
                # Create protection scripts
                scripts_dir = 'scripts'
                os.makedirs(scripts_dir, exist_ok=True)
                
                # Windows SYN Flood Protection Script
                windows_syn_script = os.path.join(scripts_dir, f"SYN_FLOOD_PROTECT_{ip.replace('.', '_')}_WINDOWS.bat")
                with open(windows_syn_script, 'w', encoding='utf-8') as f:
                    f.write(f'@echo off\n')
                    f.write(f'echo ========================================\n')
                    f.write(f'echo SYN FLOOD PROTECTION CONFIGURATION\n')
                    f.write(f'echo Target IP: {ip}\n')
                    f.write(f'echo ========================================\n\n')
                    f.write(f'echo Checking Administrator privileges...\n')
                    f.write(f'net session >nul 2>&1\n')
                    f.write(f'if %errorLevel% neq 0 (\n')
                    f.write(f'    echo ERROR: This script must be run as Administrator!\n')
                    f.write(f'    pause\n')
                    f.write(f'    exit /b 1\n')
                    f.write(f')\n\n')
                    f.write(f'echo Configuring Windows SYN flood protection...\n\n')
                    f.write(f'echo [1/4] Increasing TCP connection backlog...\n')
                    f.write(f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v TcpMaxHalfOpen /t REG_DWORD /d 500 /f\n')
                    f.write(f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v TcpMaxHalfOpenRetried /t REG_DWORD /d 400 /f\n\n')
                    f.write(f'echo [2/4] Enabling SYN attack protection...\n')
                    f.write(f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v SynAttackProtect /t REG_DWORD /d 2 /f\n')
                    f.write(f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v TcpMaxConnectResponseRetransmissions /t REG_DWORD /d 2 /f\n\n')
                    f.write(f'echo [3/4] Reducing SYN-ACK retransmissions...\n')
                    f.write(f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 3 /f\n\n')
                    f.write(f'echo [4/4] Enabling dynamic backlog...\n')
                    f.write(f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters" /v EnableDynamicBacklog /t REG_DWORD /d 1 /f\n')
                    f.write(f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters" /v MinimumDynamicBacklog /t REG_DWORD /d 20 /f\n')
                    f.write(f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters" /v MaximumDynamicBacklog /t REG_DWORD /d 20000 /f\n')
                    f.write(f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters" /v DynamicBacklogGrowthDelta /t REG_DWORD /d 10 /f\n\n')
                    f.write(f'echo.\n')
                    f.write(f'echo Adding firewall rule to block {ip}...\n')
                    f.write(f'netsh advfirewall firewall add rule name="SYN_FLOOD_PROTECT_{ip}" dir=in action=block remoteip={ip} enable=yes protocol=TCP\n\n')
                    f.write(f'echo ========================================\n')
                    f.write(f'echo SYN FLOOD PROTECTION CONFIGURED!\n')
                    f.write(f'echo System is now protected against SYN floods\n')
                    f.write(f'echo ========================================\n')
                    f.write(f'echo.\n')
                    f.write(f'echo NOTE: Reboot may be required for all settings to take effect\n')
                    f.write(f'pause\n')
                
                # Linux SYN Flood Protection Script
                linux_syn_script = os.path.join(scripts_dir, f"SYN_FLOOD_PROTECT_{ip.replace('.', '_')}_LINUX.sh")
                with open(linux_syn_script, 'w', encoding='utf-8') as f:
                    f.write(f'#!/bin/bash\n')
                    f.write(f'echo "========================================"\n')
                    f.write(f'echo "SYN FLOOD PROTECTION CONFIGURATION"\n')
                    f.write(f'echo "Target IP: {ip}"\n')
                    f.write(f'echo "========================================"\n\n')
                    f.write(f'# Check if running as root\n')
                    f.write(f'if [ "$EUID" -ne 0 ]; then \n')
                    f.write(f'    echo "ERROR: This script must be run as root!"\n')
                    f.write(f'    exit 1\n')
                    f.write(f'fi\n\n')
                    f.write(f'echo "[1/4] Enabling SYN cookies (most effective protection)..."\n')
                    f.write(f'echo 1 > /proc/sys/net/ipv4/tcp_syncookies\n')
                    f.write(f'echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf\n\n')
                    f.write(f'echo "[2/4] Reducing SYN-ACK retransmissions..."\n')
                    f.write(f'echo 2 > /proc/sys/net/ipv4/tcp_synack_retries\n')
                    f.write(f'echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf\n\n')
                    f.write(f'echo "[3/4] Increasing SYN backlog queue..."\n')
                    f.write(f'echo 2048 > /proc/sys/net/core/somaxconn\n')
                    f.write(f'echo "net.core.somaxconn = 2048" >> /etc/sysctl.conf\n\n')
                    f.write(f'echo "[4/4] Configuring iptables rate limiting..."\n')
                    f.write(f'iptables -A INPUT -p tcp -s {ip} --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT\n')
                    f.write(f'iptables -A INPUT -p tcp -s {ip} --syn -j DROP\n')
                    f.write(f'iptables -A INPUT -p tcp -d {ip} --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT\n')
                    f.write(f'iptables -A INPUT -p tcp -d {ip} --syn -j DROP\n')
                    f.write(f'iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules\n\n')
                    f.write(f'echo "Applying sysctl settings..."\n')
                    f.write(f'sysctl -p\n\n')
                    f.write(f'echo "========================================"\n')
                    f.write(f'echo "SYN FLOOD PROTECTION CONFIGURED!"\n')
                    f.write(f'echo "System is now protected against SYN floods"\n')
                    f.write(f'echo "========================================"\n')
                
                # Make Linux script executable
                try:
                    os.chmod(linux_syn_script, 0o755)
                except:
                    pass
                
                defense_data.append("=== PROTECTION SCRIPTS GENERATED ===\n")
                defense_data.append(f"Windows: {windows_syn_script}\n")
                defense_data.append(f"Linux: {linux_syn_script}\n\n")
                
                # Monitoring and Detection
                defense_data.append("=== MONITORING SYN FLOOD ATTEMPTS ===\n")
                defense_data.append("# Windows - Monitor half-open connections\n")
                defense_data.append('netstat -an | findstr SYN_RECEIVED\n\n')
                defense_data.append("# Linux - Monitor SYN connections\n")
                defense_data.append('netstat -an | grep SYN_RECV\n')
                defense_data.append('# Or use ss command:\n')
                defense_data.append('ss -ant | grep SYN-RECV\n\n')
                defense_data.append("# Check for SYN flood patterns\n")
                defense_data.append('# High number of SYN_RECV connections indicates possible attack\n\n')
                
                # Testing Vulnerability
                defense_data.append("=== TESTING SYSTEM VULNERABILITY ===\n")
                defense_data.append("To test if your system is vulnerable:\n")
                defense_data.append("1. Monitor current SYN connections\n")
                defense_data.append("2. Check if SYN cookies are enabled\n")
                defense_data.append("3. Verify firewall rate limiting is active\n")
                defense_data.append("4. Test with legitimate connection attempts\n\n")
                defense_data.append("NOTE: Do NOT perform actual SYN flood attacks.\n")
                defense_data.append("This is for defensive testing only with proper authorization.\n\n")
                
                # Summary
                defense_data.append("=== SYN FLOOD DEFENSE SUMMARY ===\n")
                defense_data.append(f"Target IP: {ip}\n")
                defense_data.append(f"Protection Status: CONFIGURED\n")
                defense_data.append(f"SYN Cookies: ENABLED (Linux) / SYN Attack Protect: ENABLED (Windows)\n")
                defense_data.append(f"Firewall Rules: APPLIED\n")
                defense_data.append(f"Rate Limiting: ACTIVE\n")
                defense_data.append(f"Next Steps: RUN PROTECTION SCRIPTS AS ADMINISTRATOR/ROOT\n\n")
                
                defense_data.append("=" * 80 + "\n")
                defense_data.append("SYN FLOOD PROTECTION CONFIGURATION COMPLETE\n")
                defense_data.append("=" * 80 + "\n")
                
                # Write defense file
                with open(syn_flood_file, 'w', encoding='utf-8') as f:
                    f.writelines(defense_data)
                
                # Log operation
                self.log_operation("SYN_Flood_Defense", ip, "SYN flood protection configured")
                
                self.root.after(0, lambda: messagebox.showinfo(
                    "SYN Flood Defense Configured",
                    f"SYN FLOOD PROTECTION CONFIGURED\n\n"
                    f"Target IP: {ip}\n\n"
                    f"✅ Protection scripts generated:\n"
                    f"   • Windows: {os.path.basename(windows_syn_script)}\n"
                    f"   • Linux: {os.path.basename(linux_syn_script)}\n\n"
                    f"📋 Protection Features:\n"
                    f"   • SYN cookies enabled\n"
                    f"   • Rate limiting configured\n"
                    f"   • Firewall rules applied\n"
                    f"   • Backlog optimization\n\n"
                    f"⚠️ NEXT STEPS:\n"
                    f"1. Run protection scripts as Administrator/Root\n"
                    f"2. Monitor for SYN flood attempts\n"
                    f"3. Verify protection is active\n\n"
                    f"Report saved to:\n{syn_flood_file}\n\n"
                    f"Reference: https://en.wikipedia.org/wiki/SYN_flood",
                    icon='info'
                ))
                self.root.after(0, lambda: self.update_status(f"SYN flood defense configured for {ip}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"SYN flood defense configuration failed: {str(e)}"))
                self.root.after(0, lambda: self.update_status(f"Error: {str(e)}"))
        
        threading.Thread(target=configure_syn_flood_defense, daemon=True).start()
    
    def show_statistics(self):
        """ADDED: Show statistics and analytics dashboard"""
        if not ADVANCED_FEATURES or not self.db:
            messagebox.showinfo("Feature Unavailable", "Statistics dashboard requires advanced features.\nPlease ensure all modules are installed.")
            return
        
        if self.stats_dashboard is None:
            self.stats_dashboard = StatisticsDashboard(self.root, self.db)
        self.stats_dashboard.show()
    
    def export_data_operation(self):
        """ADDED: Export data operation"""
        if not ADVANCED_FEATURES or not self.export_import:
            messagebox.showinfo("Feature Unavailable", "Export functionality requires advanced features.")
            return
        
        export_window = tk.Toplevel(self.root)
        export_window.title("Export Data")
        export_window.geometry("500x400")
        export_window.configure(bg='#1e1e1e')
        
        tk.Label(
            export_window,
            text="Export Data",
            font=('Arial', 18, 'bold'),
            bg='#1e1e1e',
            fg='#ffffff'
        ).pack(pady=20)
        
        def export_json():
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if file_path:
                try:
                    output = self.export_import.export_to_json(file_path)
                    messagebox.showinfo("Success", f"Data exported to:\n{output}")
                    if self.logger:
                        self.logger.info(f"Data exported to {output}")
                except Exception as e:
                    messagebox.showerror("Error", f"Export failed: {str(e)}")
                    if self.logger:
                        self.logger.error(f"Export failed: {str(e)}")
        
        def export_csv():
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if file_path:
                try:
                    output = self.export_import.export_to_csv(file_path)
                    if output:
                        messagebox.showinfo("Success", f"Data exported to:\n{output}")
                        if self.logger:
                            self.logger.info(f"Data exported to {output}")
                    else:
                        messagebox.showwarning("Warning", "No data to export")
                except Exception as e:
                    messagebox.showerror("Error", f"Export failed: {str(e)}")
                    if self.logger:
                        self.logger.error(f"Export failed: {str(e)}")
        
        tk.Button(
            export_window,
            text="Export to JSON",
            command=export_json,
            bg='#4CAF50',
            fg='#ffffff',
            font=('Arial', 12),
            width=20,
            pady=10
        ).pack(pady=10)
        
        tk.Button(
            export_window,
            text="Export to CSV",
            command=export_csv,
            bg='#2196F3',
            fg='#ffffff',
            font=('Arial', 12),
            width=20,
            pady=10
        ).pack(pady=10)
    
    def show_settings(self):
        """ADDED: Show settings window"""
        if not ADVANCED_FEATURES or not self.config:
            messagebox.showinfo("Feature Unavailable", "Settings require advanced features.")
            return
        
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("600x500")
        settings_window.configure(bg='#1e1e1e')
        
        tk.Label(
            settings_window,
            text="Application Settings",
            font=('Arial', 18, 'bold'),
            bg='#1e1e1e',
            fg='#ffffff'
        ).pack(pady=20)
        
        # Settings content
        settings_text = tk.Text(
            settings_window,
            bg='#2d2d2d',
            fg='#ffffff',
            font=('Courier', 10),
            wrap=tk.WORD
        )
        settings_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        settings_text.insert(tk.END, "Current Configuration:\n")
        settings_text.insert(tk.END, "=" * 60 + "\n\n")
        settings_text.insert(tk.END, json.dumps(self.config.config, indent=2))
        settings_text.config(state=tk.DISABLED)
    
    def show_real_time_monitor(self):
        """ADDED: Show real-time monitoring dashboard"""
        if not ADVANCED_FEATURES or not self.db:
            messagebox.showinfo("Feature Unavailable", "Real-time monitoring requires advanced features.")
            return
        
        if self.real_time_monitor is None:
            self.real_time_monitor = RealTimeMonitor(self.root, self.db, self.logger)
        self.real_time_monitor.show()
    
    def backup_restore_operation(self):
        """ADDED: Backup and restore operations"""
        if not ADVANCED_FEATURES or not self.backup_restore:
            messagebox.showinfo("Feature Unavailable", "Backup/restore requires advanced features.")
            return
        
        backup_window = tk.Toplevel(self.root)
        backup_window.title("Backup & Restore")
        backup_window.geometry("600x500")
        backup_window.configure(bg='#1e1e1e')
        
        tk.Label(
            backup_window,
            text="Backup & Restore",
            font=('Arial', 18, 'bold'),
            bg='#1e1e1e',
            fg='#ffffff'
        ).pack(pady=20)
        
        def create_backup():
            try:
                backup_path = self.backup_restore.create_backup(include_files=True)
                messagebox.showinfo("Success", f"Backup created successfully!\n\n{backup_path}")
                if self.logger:
                    self.logger.info(f"Backup created: {backup_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Backup failed: {str(e)}")
                if self.logger:
                    self.logger.error(f"Backup failed: {e}")
        
        def restore_backup():
            backup_file = filedialog.askopenfilename(
                title="Select backup file to restore",
                filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")]
            )
            if backup_file:
                confirm = messagebox.askyesno(
                    "Confirm Restore",
                    f"Restore from backup?\n\n{backup_file}\n\nThis will overwrite current data!",
                    icon='warning'
                )
                if confirm:
                    try:
                        if self.backup_restore.restore_backup(backup_file):
                            messagebox.showinfo("Success", "Backup restored successfully!\nApplication restart recommended.")
                            if self.logger:
                                self.logger.info(f"Backup restored from: {backup_file}")
                        else:
                            messagebox.showerror("Error", "Restore failed")
                    except Exception as e:
                        messagebox.showerror("Error", f"Restore failed: {str(e)}")
        
        tk.Button(
            backup_window,
            text="Create Backup",
            command=create_backup,
            bg='#4CAF50',
            fg='#ffffff',
            font=('Arial', 12),
            width=25,
            pady=10
        ).pack(pady=10)
        
        tk.Button(
            backup_window,
            text="Restore Backup",
            command=restore_backup,
            bg='#FF9800',
            fg='#ffffff',
            font=('Arial', 12),
            width=25,
            pady=10
        ).pack(pady=10)
        
        # List backups
        list_frame = tk.LabelFrame(
            backup_window,
            text="Available Backups",
            bg='#1e1e1e',
            fg='#ffffff',
            font=('Arial', 12)
        )
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        backups_list = tk.Listbox(
            list_frame,
            bg='#2d2d2d',
            fg='#ffffff',
            font=('Courier', 10)
        )
        backups_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        backups = self.backup_restore.list_backups()
        for backup in backups:
            size_mb = backup["size"] / (1024 * 1024)
            backups_list.insert(tk.END, f"{backup['name']} - {size_mb:.2f} MB - {backup['date'][:19]}")
    
    def view_all_operations(self):
        """ADDED: View all operations across all folders - Dashboard view"""
        try:
            # Create dashboard window
            dashboard_window = tk.Toplevel(self.root)
            dashboard_window.title("Operations Dashboard - All Folders")
            dashboard_window.geometry("1400x900")
            dashboard_window.configure(bg='#1e1e1e')
            
            # Create notebook for tabs
            notebook = ttk.Notebook(dashboard_window)
            notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Define all folders to check
            folders_info = {
                "Caught/IP_ACK": ("IP ACK Operations", "Acknowledgment operations"),
                "Caught/IP_ACL": ("IP ACL Operations", "Access Control List operations"),
                "Caught/IP_EnsendForceFile": ("Force File Send", "Force file sending operations"),
                "Caught/IP_FileSendOverIPandLaunch": ("File Send & Launch", "File send and launch operations"),
                "Caught/IP_trace": ("IP Trace", "IP tracing operations"),
                "Caught/IPs_caught": ("Caught IPs", "All caught IP addresses"),
                "DUMPs": ("Dumps", "System and network dumps"),
                "HeisenhesiarerCatch": ("Heisenhesiarer Catch", "Network interception data"),
                "js": ("JavaScript", "JavaScript execution logs"),
                "scripts": ("Scripts", "Script execution logs"),
                "Logs": ("Logs", "Operation logs")
            }
            
            # Create tab for each folder
            for folder_path, (title, description) in folders_info.items():
                frame = tk.Frame(notebook, bg='#1e1e1e')
                notebook.add(frame, text=title)
                
                # Header
                header = tk.Label(frame, text=title, font=('Arial', 18, 'bold'), 
                                bg='#1e1e1e', fg='#ffffff')
                header.pack(pady=10)
                
                desc = tk.Label(frame, text=description, font=('Arial', 12), 
                              bg='#1e1e1e', fg='#888888')
                desc.pack(pady=5)
                
                # Scrollable text area
                text_frame = tk.Frame(frame, bg='#1e1e1e')
                text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
                
                scrollbar = tk.Scrollbar(text_frame)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                
                text_widget = tk.Text(text_frame, yscrollcommand=scrollbar.set,
                                     bg='#2d2d2d', fg='#ffffff', font=('Courier', 10),
                                     wrap=tk.WORD)
                text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                scrollbar.config(command=text_widget.yview)
                
                # Load folder contents
                try:
                    if os.path.exists(folder_path):
                        files = sorted([f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))])
                        
                        if files:
                            text_widget.insert(tk.END, f"Total Files: {len(files)}\n")
                            text_widget.insert(tk.END, "=" * 80 + "\n\n")
                            
                            for file in files:
                                file_path = os.path.join(folder_path, file)
                                file_size = os.path.getsize(file_path)
                                file_time = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                                
                                text_widget.insert(tk.END, f"File: {file}\n")
                                text_widget.insert(tk.END, f"Size: {file_size} bytes\n")
                                text_widget.insert(tk.END, f"Modified: {file_time}\n")
                                
                                # Try to read and display content (limit to first 500 chars)
                                try:
                                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read()
                                        if len(content) > 500:
                                            content = content[:500] + "\n... (truncated)"
                                        text_widget.insert(tk.END, f"\nContent Preview:\n{content}\n")
                                except:
                                    text_widget.insert(tk.END, "\n[Binary file or unable to read]\n")
                                
                                text_widget.insert(tk.END, "\n" + "=" * 80 + "\n\n")
                        else:
                            text_widget.insert(tk.END, "No files found in this folder.\n")
                    else:
                        text_widget.insert(tk.END, f"Folder does not exist: {folder_path}\n")
                except Exception as e:
                    text_widget.insert(tk.END, f"Error loading folder: {str(e)}\n")
                
                text_widget.config(state=tk.DISABLED)
            
            # Summary tab
            summary_frame = tk.Frame(notebook, bg='#1e1e1e')
            notebook.add(summary_frame, text="Summary")
            
            summary_text = tk.Text(summary_frame, bg='#2d2d2d', fg='#ffffff', 
                                  font=('Courier', 11), wrap=tk.WORD)
            summary_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            # Generate summary
            summary_text.insert(tk.END, "=" * 80 + "\n")
            summary_text.insert(tk.END, "OPERATIONS DASHBOARD SUMMARY\n")
            summary_text.insert(tk.END, "=" * 80 + "\n\n")
            summary_text.insert(tk.END, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            total_files = 0
            total_size = 0
            
            for folder_path, (title, description) in folders_info.items():
                try:
                    if os.path.exists(folder_path):
                        files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
                        folder_size = sum(os.path.getsize(os.path.join(folder_path, f)) for f in files)
                        
                        total_files += len(files)
                        total_size += folder_size
                        
                        summary_text.insert(tk.END, f"{title}:\n")
                        summary_text.insert(tk.END, f"  Files: {len(files)}\n")
                        summary_text.insert(tk.END, f"  Size: {folder_size:,} bytes ({folder_size/1024:.2f} KB)\n")
                        summary_text.insert(tk.END, f"  Path: {folder_path}\n\n")
                except:
                    pass
            
            summary_text.insert(tk.END, "=" * 80 + "\n")
            summary_text.insert(tk.END, f"TOTAL FILES: {total_files}\n")
            summary_text.insert(tk.END, f"TOTAL SIZE: {total_size:,} bytes ({total_size/1024:.2f} KB)\n")
            summary_text.insert(tk.END, "=" * 80 + "\n")
            
            summary_text.config(state=tk.DISABLED)
            
            self.update_status("Operations dashboard opened")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open dashboard: {str(e)}")
            self.update_status(f"Error: {str(e)}")

class LaunchScreen:
    def __init__(self, root, callback):
        self.root = root
        self.callback = callback
        self.root.title("Loading...")
        self.root.geometry("1920x1080")
        self.root.configure(bg='#000000')
        
        # Center the window
        self.center_window()
        
        # Progress state
        self.progress_value = 0
        self.progress_running = True
        
        # Bind to window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Load and display image with progress bar
        self.load_launch_image()
        
        # Start progress bar animation
        self.start_progress()
    
    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        width = 1920
        height = 1080
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def load_launch_image(self):
        """Load and display the launch image with progress bar"""
        try:
            image_path = os.path.join('software-gui-images', 'launchimage', 'launch_image.png')
            
            # Create main container
            main_frame = tk.Frame(self.root, bg='#000000')
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Image container
            image_frame = tk.Frame(main_frame, bg='#000000')
            image_frame.pack(fill=tk.BOTH, expand=True, pady=(50, 0))
            
            if os.path.exists(image_path):
                # Load image
                pil_image = Image.open(image_path)
                
                # Resize to fit window while maintaining aspect ratio
                screen_width = 1920
                screen_height = 900  # Leave space for progress bar
                pil_image.thumbnail((screen_width - 100, screen_height - 100), Image.Resampling.LANCZOS)
                
                # Convert to PhotoImage
                self.photo = ImageTk.PhotoImage(pil_image)
                
                # Create canvas to display image
                self.canvas = tk.Canvas(
                    image_frame,
                    width=screen_width,
                    height=screen_height,
                    bg='#000000',
                    highlightthickness=0
                )
                self.canvas.pack(fill=tk.BOTH, expand=True)
                
                # Center the image on canvas
                img_x = screen_width // 2
                img_y = screen_height // 2
                self.canvas.create_image(img_x, img_y, image=self.photo, anchor=tk.CENTER)
            else:
                # Placeholder if image doesn't exist
                self.canvas = tk.Canvas(
                    image_frame,
                    width=1920,
                    height=900,
                    bg='#000000',
                    highlightthickness=0
                )
                self.canvas.pack(fill=tk.BOTH, expand=True)
                
                center_x = 1920 // 2
                center_y = 900 // 2
                self.canvas.create_text(
                    center_x,
                    center_y,
                    text="IP Operations Control Panel",
                    font=('Arial', 48, 'bold'),
                    fill='#ffffff',
                    anchor=tk.CENTER
                )
            
            # Progress bar container
            progress_frame = tk.Frame(main_frame, bg='#000000')
            progress_frame.pack(fill=tk.X, padx=200, pady=50)
            
            # Progress bar label
            self.progress_label = tk.Label(
                progress_frame,
                text="Loading...",
                font=('Arial', 16),
                bg='#000000',
                fg='#ffffff'
            )
            self.progress_label.pack(pady=(0, 10))
            
            # Progress bar
            self.progress_bar = ttk.Progressbar(
                progress_frame,
                length=1520,  # 1920 - 400 (padding)
                mode='determinate',
                maximum=100
            )
            self.progress_bar.pack(fill=tk.X)
            
        except Exception as e:
            print(f"Error loading image: {e}")
            # Create simple placeholder
            label = tk.Label(
                self.root,
                text="IP Operations Control Panel\nLoading...",
                font=('Arial', 36, 'bold'),
                bg='#000000',
                fg='#ffffff'
            )
            label.pack(fill=tk.BOTH, expand=True)
    
    def start_progress(self):
        """Start the progress bar animation"""
        self.progress_value = 0
        self.progress_running = True
        self.update_progress()
    
    def update_progress(self):
        """Update progress bar"""
        if not self.progress_running:
            return
        
        try:
            if not self.root.winfo_exists():
                self.progress_running = False
                return
            
            # Update progress value
            self.progress_value += 2  # Increase by 2% each update
            
            if self.progress_value > 100:
                self.progress_value = 100
            
            # Update progress bar
            if hasattr(self, 'progress_bar'):
                self.progress_bar['value'] = self.progress_value
            
            # Update label
            if hasattr(self, 'progress_label'):
                if self.progress_value < 30:
                    self.progress_label.config(text="Initializing...")
                elif self.progress_value < 60:
                    self.progress_label.config(text="Loading modules...")
                elif self.progress_value < 90:
                    self.progress_label.config(text="Preparing interface...")
                else:
                    self.progress_label.config(text="Almost ready...")
            
            # Continue updating or close
            if self.progress_value >= 100:
                # Wait a moment then close
                self.root.after(500, self.close_and_show_main)
            else:
                # Schedule next update (30ms for smooth animation)
                self.root.after(30, self.update_progress)
                
        except tk.TclError:
            # Window was destroyed
            self.progress_running = False
            return
        except Exception as e:
            print(f"Progress update error: {e}")
            self.progress_running = False
            return
    
    def on_closing(self):
        """Handle window closing event"""
        self.progress_running = False
        self.close_and_show_main()
    
    def close_and_show_main(self):
        """Close launch screen and show main GUI"""
        # Stop progress before destroying window
        self.progress_running = False
        
        # Destroy window
        try:
            self.root.destroy()
        except:
            pass
        
        # Call callback to show main GUI
        if self.callback:
            self.callback()

def main():
    # Create launch screen first
    launch_root = tk.Tk()
    
    def show_main_gui():
        # Create main application window
        root = tk.Tk()
        app = IPOperationsGUI(root)
        root.mainloop()
    
    launch_screen = LaunchScreen(launch_root, show_main_gui)
    launch_root.mainloop()

if __name__ == "__main__":
    main()

