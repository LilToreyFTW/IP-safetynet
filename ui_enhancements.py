"""
UI Enhancements and Themes
"""
import tkinter as tk
from tkinter import ttk

class UIThemes:
    THEMES = {
        "dark": {
            "bg": "#1e1e1e",
            "fg": "#ffffff",
            "entry_bg": "#2d2d2d",
            "button_bg": "#4CAF50",
            "accent": "#00BCD4"
        },
        "light": {
            "bg": "#ffffff",
            "fg": "#000000",
            "entry_bg": "#f0f0f0",
            "button_bg": "#4CAF50",
            "accent": "#2196F3"
        },
        "cyber": {
            "bg": "#0a0a0a",
            "fg": "#00ff00",
            "entry_bg": "#1a1a1a",
            "button_bg": "#00ff00",
            "accent": "#ff00ff"
        }
    }
    
    @staticmethod
    def get_theme(theme_name="dark"):
        return UIThemes.THEMES.get(theme_name, UIThemes.THEMES["dark"])

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.widget.bind('<Enter>', self.on_enter)
        self.widget.bind('<Leave>', self.on_leave)
    
    def on_enter(self, event=None):
        self.show_tooltip()
    
    def on_leave(self, event=None):
        self.hide_tooltip()
    
    def show_tooltip(self):
        x, y, _, _ = self.widget.bbox("insert") if hasattr(self.widget, 'bbox') else (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        
        self.tip_window = tk.Toplevel(self.widget)
        self.tip_window.wm_overrideredirect(True)
        self.tip_window.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(
            self.tip_window,
            text=self.text,
            bg='#ffffe0',
            fg='#000000',
            font=('Arial', 9),
            relief=tk.SOLID,
            borderwidth=1
        )
        label.pack()
    
    def hide_tooltip(self):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

