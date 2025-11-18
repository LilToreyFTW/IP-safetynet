"""
Statistics and Analytics Dashboard
"""
import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta
from threat_database import ThreatDatabase
import json

class StatisticsDashboard:
    def __init__(self, parent, db: ThreatDatabase):
        self.parent = parent
        self.db = db
        self.window = None
    
    def show(self):
        """Show statistics dashboard"""
        if self.window:
            self.window.lift()
            return
        
        self.window = tk.Toplevel(self.parent)
        self.window.title("Statistics & Analytics Dashboard")
        self.window.geometry("1400x900")
        self.window.configure(bg='#1e1e1e')
        
        # Create notebook for tabs
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Overview tab
        overview_frame = tk.Frame(notebook, bg='#1e1e1e')
        notebook.add(overview_frame, text="Overview")
        self.create_overview_tab(overview_frame)
        
        # Threats tab
        threats_frame = tk.Frame(notebook, bg='#1e1e1e')
        notebook.add(threats_frame, text="Threat Intelligence")
        self.create_threats_tab(threats_frame)
        
        # Operations tab
        operations_frame = tk.Frame(notebook, bg='#1e1e1e')
        notebook.add(operations_frame, text="Operations")
        self.create_operations_tab(operations_frame)
        
        # Network Scans tab
        scans_frame = tk.Frame(notebook, bg='#1e1e1e')
        notebook.add(scans_frame, text="Network Scans")
        self.create_scans_tab(scans_frame)
        
        # Alerts tab
        alerts_frame = tk.Frame(notebook, bg='#1e1e1e')
        notebook.add(alerts_frame, text="Alerts")
        self.create_alerts_tab(alerts_frame)
        
        # Refresh button
        refresh_btn = tk.Button(
            self.window,
            text="Refresh Data",
            command=self.refresh_all,
            bg='#4CAF50',
            fg='#ffffff',
            font=('Arial', 12, 'bold'),
            padx=20,
            pady=10
        )
        refresh_btn.pack(pady=10)
    
    def create_overview_tab(self, parent):
        """Create overview statistics tab"""
        stats = self.db.get_operations_stats()
        
        # Stats frame
        stats_frame = tk.Frame(parent, bg='#1e1e1e')
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Key metrics
        metrics_frame = tk.Frame(stats_frame, bg='#1e1e1e')
        metrics_frame.pack(fill=tk.X, pady=10)
        
        metrics = [
            ("Total Operations", stats.get("total_operations", 0), "#4CAF50"),
            ("Threat IPs", stats.get("total_threats", 0), "#F44336"),
            ("Active Alerts", stats.get("unacknowledged_alerts", 0), "#FF9800")
        ]
        
        for i, (label, value, color) in enumerate(metrics):
            metric_frame = tk.Frame(metrics_frame, bg=color, relief=tk.RAISED, bd=2)
            metric_frame.grid(row=0, column=i, padx=10, sticky="ew")
            metrics_frame.columnconfigure(i, weight=1)
            
            tk.Label(
                metric_frame,
                text=label,
                font=('Arial', 14),
                bg=color,
                fg='#ffffff'
            ).pack(pady=5)
            
            tk.Label(
                metric_frame,
                text=str(value),
                font=('Arial', 32, 'bold'),
                bg=color,
                fg='#ffffff'
            ).pack(pady=5)
        
        # Operations by type
        ops_frame = tk.LabelFrame(
            stats_frame,
            text="Operations by Type",
            bg='#1e1e1e',
            fg='#ffffff',
            font=('Arial', 12, 'bold')
        )
        ops_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ops_text = tk.Text(
            ops_frame,
            bg='#2d2d2d',
            fg='#ffffff',
            font=('Courier', 11),
            wrap=tk.WORD
        )
        ops_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ops_by_type = stats.get("operations_by_type", {})
        for op_type, count in sorted(ops_by_type.items(), key=lambda x: x[1], reverse=True):
            ops_text.insert(tk.END, f"{op_type:30s} : {count:5d}\n")
        
        ops_text.config(state=tk.DISABLED)
    
    def create_threats_tab(self, parent):
        """Create threats tab"""
        threats = self.db.get_all_threats()
        
        # Treeview for threats
        tree_frame = tk.Frame(parent, bg='#1e1e1e')
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tree = ttk.Treeview(
            tree_frame,
            columns=("IP", "Threat Level", "Type", "Hostname", "First Seen", "Last Seen", "Status"),
            show="headings"
        )
        
        tree.heading("IP", text="IP Address")
        tree.heading("Threat Level", text="Threat Level")
        tree.heading("Type", text="Type")
        tree.heading("Hostname", text="Hostname")
        tree.heading("First Seen", text="First Seen")
        tree.heading("Last Seen", text="Last Seen")
        tree.heading("Status", text="Status")
        
        tree.column("IP", width=150)
        tree.column("Threat Level", width=120)
        tree.column("Type", width=150)
        tree.column("Hostname", width=200)
        tree.column("First Seen", width=150)
        tree.column("Last Seen", width=150)
        tree.column("Status", width=100)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        for threat in threats:
            tree.insert("", tk.END, values=(
                threat.get("ip_address", ""),
                threat.get("threat_level", ""),
                threat.get("threat_type", ""),
                threat.get("hostname", ""),
                threat.get("first_seen", ""),
                threat.get("last_seen", ""),
                threat.get("status", "")
            ))
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_operations_tab(self, parent):
        """Create operations log tab"""
        text_frame = tk.Frame(parent, bg='#1e1e1e')
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        text_widget = tk.Text(
            text_frame,
            bg='#2d2d2d',
            fg='#ffffff',
            font=('Courier', 10),
            wrap=tk.WORD
        )
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        # Get recent operations (would need to add method to database)
        text_widget.insert(tk.END, "Recent Operations:\n")
        text_widget.insert(tk.END, "=" * 80 + "\n\n")
        text_widget.insert(tk.END, "Operation logs will be displayed here...\n")
        text_widget.config(state=tk.DISABLED)
    
    def create_scans_tab(self, parent):
        """Create network scans tab"""
        text_frame = tk.Frame(parent, bg='#1e1e1e')
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        text_widget = tk.Text(
            text_frame,
            bg='#2d2d2d',
            fg='#ffffff',
            font=('Courier', 10),
            wrap=tk.WORD
        )
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        text_widget.insert(tk.END, "Network Scan History:\n")
        text_widget.insert(tk.END, "=" * 80 + "\n\n")
        text_widget.insert(tk.END, "Scan results will be displayed here...\n")
        text_widget.config(state=tk.DISABLED)
    
    def create_alerts_tab(self, parent):
        """Create alerts tab"""
        text_frame = tk.Frame(parent, bg='#1e1e1e')
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        text_widget = tk.Text(
            text_frame,
            bg='#2d2d2d',
            fg='#ffffff',
            font=('Courier', 10),
            wrap=tk.WORD
        )
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        text_widget.insert(tk.END, "Active Alerts:\n")
        text_widget.insert(tk.END, "=" * 80 + "\n\n")
        text_widget.insert(tk.END, "Alerts will be displayed here...\n")
        text_widget.config(state=tk.DISABLED)
    
    def refresh_all(self):
        """Refresh all data"""
        if self.window:
            self.window.destroy()
            self.window = None
            self.show()

