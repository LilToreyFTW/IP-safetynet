"""
Real-Time Monitoring System
"""
import tkinter as tk
from tkinter import ttk
import threading
import time
from datetime import datetime
from threat_database import ThreatDatabase

class RealTimeMonitor:
    def __init__(self, parent, db: ThreatDatabase, logger=None):
        self.parent = parent
        self.db = db
        self.logger = logger
        self.window = None
        self.monitoring = False
        self.monitor_thread = None
    
    def show(self):
        """Show real-time monitoring dashboard"""
        if self.window:
            self.window.lift()
            return
        
        self.window = tk.Toplevel(self.parent)
        self.window.title("Real-Time Threat Monitoring")
        self.window.geometry("1200x800")
        self.window.configure(bg='#1e1e1e')
        
        # Header
        header = tk.Frame(self.window, bg='#1e1e1e')
        header.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            header,
            text="Real-Time Threat Monitoring",
            font=('Arial', 20, 'bold'),
            bg='#1e1e1e',
            fg='#ffffff'
        ).pack(side=tk.LEFT)
        
        # Control buttons
        control_frame = tk.Frame(header, bg='#1e1e1e')
        control_frame.pack(side=tk.RIGHT)
        
        self.start_btn = tk.Button(
            control_frame,
            text="Start Monitoring",
            command=self.start_monitoring,
            bg='#4CAF50',
            fg='#ffffff',
            font=('Arial', 12),
            padx=10
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(
            control_frame,
            text="Stop Monitoring",
            command=self.stop_monitoring,
            bg='#F44336',
            fg='#ffffff',
            font=('Arial', 12),
            padx=10,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Status indicator
        self.status_label = tk.Label(
            header,
            text="Status: STOPPED",
            font=('Arial', 12),
            bg='#1e1e1e',
            fg='#888888'
        )
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        # Monitoring display
        display_frame = tk.Frame(self.window, bg='#1e1e1e')
        display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Text widget with scrollbar
        text_frame = tk.Frame(display_frame, bg='#1e1e1e')
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.monitor_text = tk.Text(
            text_frame,
            yscrollcommand=scrollbar.set,
            bg='#2d2d2d',
            fg='#00ff00',
            font=('Courier', 11),
            wrap=tk.WORD
        )
        self.monitor_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.monitor_text.yview)
        
        # Initial message
        self.monitor_text.insert(tk.END, "Real-Time Monitoring Dashboard\n")
        self.monitor_text.insert(tk.END, "=" * 80 + "\n\n")
        self.monitor_text.insert(tk.END, "Click 'Start Monitoring' to begin real-time threat monitoring...\n\n")
        self.monitor_text.config(state=tk.DISABLED)
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="Status: MONITORING", fg='#4CAF50')
        
        self.monitor_text.config(state=tk.NORMAL)
        self.monitor_text.insert(tk.END, f"\n[{datetime.now().strftime('%H:%M:%S')}] Monitoring started...\n")
        self.monitor_text.see(tk.END)
        self.monitor_text.config(state=tk.DISABLED)
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Status: STOPPED", fg='#888888')
        
        self.monitor_text.config(state=tk.NORMAL)
        self.monitor_text.insert(tk.END, f"\n[{datetime.now().strftime('%H:%M:%S')}] Monitoring stopped.\n")
        self.monitor_text.see(tk.END)
        self.monitor_text.config(state=tk.DISABLED)
    
    def monitor_loop(self):
        """Monitoring loop"""
        while self.monitoring:
            try:
                # Get latest statistics
                stats = self.db.get_operations_stats()
                threats = self.db.get_all_threats()
                
                # Update display
                self.parent.after(0, self.update_display, stats, threats)
                
                # Sleep for check interval
                time.sleep(10)  # Check every 10 seconds
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Monitoring error: {e}")
                time.sleep(10)
    
    def update_display(self, stats, threats):
        """Update monitoring display"""
        if not self.monitoring:
            return
        
        self.monitor_text.config(state=tk.NORMAL)
        self.monitor_text.insert(tk.END, f"\n[{datetime.now().strftime('%H:%M:%S')}] Monitoring Update:\n")
        self.monitor_text.insert(tk.END, f"  Total Operations: {stats.get('total_operations', 0)}\n")
        self.monitor_text.insert(tk.END, f"  Threat IPs: {stats.get('total_threats', 0)}\n")
        self.monitor_text.insert(tk.END, f"  Active Alerts: {stats.get('unacknowledged_alerts', 0)}\n")
        self.monitor_text.see(tk.END)
        self.monitor_text.config(state=tk.DISABLED)
    
    def on_closing(self):
        """Handle window closing"""
        self.stop_monitoring()
        self.window.destroy()
        self.window = None

