import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import logging
import threading
import json
import webbrowser
from datetime import datetime
import os
import base64
from io import BytesIO
from typing import Dict, List, Any, Optional, Callable
import urllib.parse

# Try to import PIL for icon handling
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Import our modules
from phiscanner import PhishingScanner
from database import PhishingDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('phiscanner.ui')

class PhishingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Link Scanner")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Set application icon
        self.set_app_icon()
        
        # Initialize status variable first
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        # Set up the scanner and database
        self.db = PhishingDatabase()
        self.scanner = None  # Will be initialized with API keys from settings
        
        # Load settings
        self.settings = self.load_settings()
        self.initialize_scanner()
        
        # Create the main notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Set up the tabs
        self.setup_scan_tab()
        self.setup_history_tab()
        self.setup_settings_tab()
        
        # Set up the status bar
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Configure styles
        self.configure_styles()
        
    def set_app_icon(self):
        """Create and set the application icon."""
        if HAS_PIL:
            try:
                # Create a shield icon
                icon_size = 64
                img = Image.new('RGBA', (icon_size, icon_size), (0, 0, 0, 0))
                
                # Draw a shield shape
                from PIL import ImageDraw
                draw = ImageDraw.Draw(img)
                
                # Shield outline
                shield_color = (65, 105, 225)  # Royal Blue
                draw.polygon([(5, 5), (icon_size-5, 5), (icon_size-5, 45), 
                              (icon_size//2, icon_size-5), (5, 45)], 
                             fill=shield_color, outline=(0, 0, 0))
                
                # Add a lock symbol
                lock_color = (255, 255, 255)  # White
                # Lock body
                draw.rectangle([icon_size//2-10, icon_size//2-5, 
                               icon_size//2+10, icon_size//2+15], 
                              fill=lock_color, outline=(0, 0, 0))
                # Lock shackle
                draw.arc([icon_size//2-15, icon_size//2-20, 
                         icon_size//2+15, icon_size//2+10], 
                        start=0, end=180, fill=lock_color, width=5)
                
                # Convert to PhotoImage and set as icon
                icon_photo = ImageTk.PhotoImage(img)
                self.root.iconphoto(True, icon_photo)
                
                # Save reference to prevent garbage collection
                self.icon_photo = icon_photo
                
                logger.info("Set custom application icon")
            except Exception as e:
                logger.error(f"Error setting application icon: {str(e)}")
        
    def create_visual_risk_indicator(self, risk_level, canvas_width=150, canvas_height=30):
        """Create a visual risk indicator for the given risk level."""
        risk_canvas = tk.Canvas(width=canvas_width, height=canvas_height, 
                               bg='white', highlightthickness=0)
        
        # Define colors for risk levels
        colors = {
            'low': '#4CAF50',    # Green
            'medium': '#FF9800', # Orange
            'high': '#F44336'    # Red
        }
        
        # Get color for current risk level
        color = colors.get(risk_level.lower(), '#9E9E9E')  # Grey for unknown
        
        # Calculate indicator position based on risk level
        if risk_level.lower() == 'low':
            indicator_pos = canvas_width * 0.2
        elif risk_level.lower() == 'medium':
            indicator_pos = canvas_width * 0.5
        elif risk_level.lower() == 'high':
            indicator_pos = canvas_width * 0.8
        else:
            indicator_pos = canvas_width * 0.5
        
        # Draw simplified background gradient with fixed colors to avoid errors
        # Green section (Low risk)
        for i in range(int(canvas_width * 0.33)):
            risk_canvas.create_line(i, 0, i, canvas_height, fill='#4CAF50')
            
        # Orange section (Medium risk)    
        for i in range(int(canvas_width * 0.33), int(canvas_width * 0.67)):
            risk_canvas.create_line(i, 0, i, canvas_height, fill='#FF9800')
            
        # Red section (High risk)
        for i in range(int(canvas_width * 0.67), canvas_width):
            risk_canvas.create_line(i, 0, i, canvas_height, fill='#F44336')
        
        # Draw indicator triangle
        risk_canvas.create_polygon(
            indicator_pos, canvas_height,
            indicator_pos - 10, canvas_height - 15,
            indicator_pos + 10, canvas_height - 15,
            fill=color, outline='black'
        )
        
        # Add text labels
        risk_canvas.create_text(canvas_width * 0.2, 10, 
                               text="Low", fill='black', font=('Helvetica', 8, 'bold'))
        risk_canvas.create_text(canvas_width * 0.5, 10, 
                               text="Medium", fill='black', font=('Helvetica', 8, 'bold'))
        risk_canvas.create_text(canvas_width * 0.8, 10, 
                               text="High", fill='black', font=('Helvetica', 8, 'bold'))
        
        return risk_canvas
        
    def configure_styles(self):
        """Configure ttk styles for the application."""
        style = ttk.Style()
        
        # Set theme if available
        try:
            # Try to use a more modern theme if available
            style.theme_use('clam')  # Other options: 'alt', 'default', 'classic'
        except:
            # If theme not available, continue with default
            pass
        
        # Configure common elements
        style.configure('TLabel', font=('Helvetica', 10))
        style.configure('TButton', padding=6, font=('Helvetica', 10))
        style.configure('TEntry', font=('Helvetica', 10))
        
        # Configure frames
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabelframe', background='#f0f0f0')
        style.configure('TLabelframe.Label', font=('Helvetica', 10, 'bold'))
        
        # Configure notebook tabs
        style.configure('TNotebook.Tab', padding=[10, 2], font=('Helvetica', 10))
        style.map('TNotebook.Tab', background=[('selected', '#4a6984'), ('active', '#90a4ae')],
                  foreground=[('selected', 'white'), ('active', 'black')])
        
        # Configure scan button with special style
        style.configure('Scan.TButton', font=('Helvetica', 12, 'bold'), padding=8)
        style.map('Scan.TButton', background=[('active', '#4caf50'), ('pressed', '#388e3c')], 
                  foreground=[('active', 'white')])
        
        # Configure status bar
        style.configure('Status.TLabel', padding=3, relief='sunken', background='#e0e0e0')
        
        # Configure the Treeview
        style.configure('Treeview', font=('Helvetica', 9), rowheight=25)
        style.configure('Treeview.Heading', font=('Helvetica', 10, 'bold'))
        
        # Additional UI enhancements for modern look
        self.root.configure(background='#f0f0f0')
        self.notebook.configure(padding=3)
        
        # Configure status bar with new style
        self.status_bar.configure(style='Status.TLabel')
        
    def initialize_scanner(self):
        """Initialize the scanner with API keys from settings."""
        vt_api_key = self.settings.get('vt_api_key', '')
        gsb_api_key = self.settings.get('gsb_api_key', '')
        self.scanner = PhishingScanner(vt_api_key=vt_api_key, gsb_api_key=gsb_api_key)
        
    def load_settings(self) -> Dict[str, str]:
        """Load settings from file or return defaults."""
        try:
            if os.path.exists('settings.json'):
                with open('settings.json', 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading settings: {str(e)}")
        
        # Default settings
        return {
            'vt_api_key': '',
            'gsb_api_key': ''
        }
        
    def save_settings(self):
        """Save current settings to file."""
        try:
            with open('settings.json', 'w') as f:
                json.dump(self.settings, f, indent=4)
            logger.info("Settings saved successfully")
        except Exception as e:
            logger.error(f"Error saving settings: {str(e)}")
            messagebox.showerror("Error", f"Could not save settings: {str(e)}")
    
    def setup_scan_tab(self):
        """Set up the URL scanning tab."""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="Scan URL")
        
        # URL input area
        url_frame = ttk.Frame(scan_frame)
        url_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(url_frame, text="Enter URL to scan:").pack(side=tk.LEFT, padx=(0, 10))
        self.url_entry = ttk.Entry(url_frame, width=50)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        scan_button = ttk.Button(
            url_frame, 
            text="Scan", 
            command=self.scan_url,
            style='Scan.TButton'
        )
        scan_button.pack(side=tk.RIGHT)
        
        # Results area
        results_frame = ttk.LabelFrame(scan_frame, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create a results text area with scrollbars
        self.results_text = scrolledtext.ScrolledText(
            results_frame, 
            wrap=tk.WORD,
            width=80,
            height=20
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.results_text.config(state=tk.DISABLED)  # Make it read-only initially
        
    def setup_history_tab(self):
        """Set up the scan history tab."""
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text="History")
        
        # Search area
        search_frame = ttk.Frame(history_frame)
        search_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 10))
        self.search_entry = ttk.Entry(search_frame, width=30)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        search_button = ttk.Button(
            search_frame, 
            text="Search", 
            command=self.search_history
        )
        search_button.pack(side=tk.LEFT, padx=(0, 10))
        
        refresh_button = ttk.Button(
            search_frame, 
            text="Refresh", 
            command=self.refresh_history
        )
        refresh_button.pack(side=tk.RIGHT)
        
        # Table for history
        table_frame = ttk.Frame(history_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Treeview for the table
        columns = ("id", "url", "timestamp", "risk_level")
        self.history_table = ttk.Treeview(
            table_frame, 
            columns=columns,
            show="headings",
            yscrollcommand=scrollbar.set
        )
        
        # Configure columns
        self.history_table.heading("id", text="ID")
        self.history_table.heading("url", text="URL")
        self.history_table.heading("timestamp", text="Date/Time")
        self.history_table.heading("risk_level", text="Risk Level")
        
        # Set column widths
        self.history_table.column("id", width=50, stretch=False)
        self.history_table.column("url", width=300, stretch=True)
        self.history_table.column("timestamp", width=150, stretch=False)
        self.history_table.column("risk_level", width=100, stretch=False)
        
        self.history_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.history_table.yview)
        
        # Bind double-click to view details
        self.history_table.bind("<Double-1>", self.view_scan_details)
        
        # Button frame for actions
        button_frame = ttk.Frame(history_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        view_button = ttk.Button(
            button_frame,
            text="View Details",
            command=lambda: self.view_scan_details(None)
        )
        view_button.pack(side=tk.LEFT, padx=(0, 10))
        
        delete_button = ttk.Button(
            button_frame,
            text="Delete Selected",
            command=self.delete_selected_scan
        )
        delete_button.pack(side=tk.LEFT)
        
        # Load initial history
        self.refresh_history()
        
    def setup_settings_tab(self):
        """Set up the settings tab."""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")
        
        # API key settings
        api_frame = ttk.LabelFrame(settings_frame, text="API Keys")
        api_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # VirusTotal API Key
        vt_frame = ttk.Frame(api_frame)
        vt_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(vt_frame, text="VirusTotal API Key:").pack(side=tk.LEFT, padx=(0, 10))
        self.vt_api_entry = ttk.Entry(vt_frame, width=50)
        self.vt_api_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.vt_api_entry.insert(0, self.settings.get('vt_api_key', ''))
        
        # Google Safe Browsing API Key
        gsb_frame = ttk.Frame(api_frame)
        gsb_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(gsb_frame, text="Google Safe Browsing API Key:").pack(side=tk.LEFT, padx=(0, 10))
        self.gsb_api_entry = ttk.Entry(gsb_frame, width=50)
        self.gsb_api_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.gsb_api_entry.insert(0, self.settings.get('gsb_api_key', ''))
        
        # Help text
        help_frame = ttk.LabelFrame(settings_frame, text="API Key Information")
        help_frame.pack(fill=tk.X, padx=10, pady=10)
        
        help_text = (
            "VirusTotal API Key: Sign up at virustotal.com to get a free API key.\n"
            "Google Safe Browsing API Key: Sign up for a Google Cloud account and enable the Safe Browsing API."
        )
        
        help_label = ttk.Label(help_frame, text=help_text, wraplength=600, justify=tk.LEFT)
        help_label.pack(padx=10, pady=10, fill=tk.X)
        
        # Buttons
        button_frame = ttk.Frame(settings_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        save_button = ttk.Button(
            button_frame,
            text="Save Settings",
            command=self.save_settings_from_ui
        )
        save_button.pack(side=tk.RIGHT)
        
    def scan_url(self):
        """Scan the URL(s) entered by the user."""
        url_input = self.url_entry.get().strip()
        if not url_input:
            messagebox.showwarning("Input Error", "Please enter a URL to scan.")
            return
        
        # Check if multiple URLs were entered
        # Split by common separators (commas, spaces, newlines)
        urls = []
        for separator in [',', ' ', '\n']:
            if separator in url_input:
                urls = [u.strip() for u in url_input.split(separator) if u.strip()]
                break
        
        # If no separators found, treat as single URL
        if not urls:
            urls = [url_input]
        
        # Filter out any empty strings
        urls = [url for url in urls if url]
        
        # Confirm if multiple URLs detected
        if len(urls) > 1:
            if not messagebox.askyesno("Batch Scan", 
                                      f"Found {len(urls)} URLs to scan. Proceed with batch scan?"):
                return
            
            # Clear the entry and replace with first URL only
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, urls[0])
        
        # Process each URL
        for i, url in enumerate(urls):
            # Add http:// if not present
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                if i == 0:  # Only update the entry for the first URL
                    self.url_entry.delete(0, tk.END)
                    self.url_entry.insert(0, url)
                urls[i] = url  # Update the URL in our list
            
            # Show busy status
            self.status_var.set(f"Scanning URL {i+1}/{len(urls)}: {url}...")
            self.root.update_idletasks()
            
            # Clear results for first URL only
            if i == 0:
                self.results_text.config(state=tk.NORMAL)
                self.results_text.delete(1.0, tk.END)
                if len(urls) > 1:
                    self.results_text.insert(tk.END, f"Batch scanning {len(urls)} URLs...\n\n")
                self.results_text.insert(tk.END, f"Scanning {url}...\n\n")
                self.results_text.config(state=tk.DISABLED)
                self.root.update_idletasks()
            
            # Run the scan in a separate thread to prevent UI freezing
            # For multiple URLs, we'll scan them sequentially but still in a background thread
            scanning_thread = threading.Thread(
                target=self._run_scan_thread,
                args=(url, i == len(urls) - 1),  # Pass whether this is the last URL
                daemon=True
            )
            scanning_thread.start()
            
            # For batch mode, wait for each scan to complete before starting the next
            if len(urls) > 1 and i < len(urls) - 1:
                # Wait a bit to prevent overwhelming the APIs and give user feedback
                self.root.after(1000)  
    
    def _run_scan_thread(self, url, is_last_url=True):
        """Run the scan in a separate thread to prevent UI freezing."""
        try:
            # Perform the scan
            result = self.scanner.scan_url(url)
            
            # Save to database
            scan_id = self.db.save_scan_result(result)
            
            # Update UI with results
            self.root.after(0, lambda: self._display_scan_results(result, scan_id, is_last_url))
            
        except Exception as e:
            error_msg = f"Error scanning URL {url}: {str(e)}"
            logger.error(error_msg)
            self.root.after(0, lambda: self._display_error(error_msg))
    
    def _display_scan_results(self, result, scan_id, is_last_url=True):
        """Display scan results in the UI."""
        # For a single URL or the last URL in batch, clear the results first
        if is_last_url:
            self.results_text.config(state=tk.NORMAL)
            self.results_text.delete(1.0, tk.END)
        else:
            # For batch scanning, just append results
            self.results_text.config(state=tk.NORMAL)
        
        # Configure tags first
        self.results_text.tag_configure("url", font=("Helvetica", 12, "bold"))
        self.results_text.tag_configure("time", font=("Helvetica", 10))
        self.results_text.tag_configure("label", font=("Helvetica", 10, "bold"))
        self.results_text.tag_configure("section", font=("Helvetica", 11, "bold"))
        self.results_text.tag_configure("info", foreground="blue")
        self.results_text.tag_configure("error", foreground="red")
        self.results_text.tag_configure("warning", foreground="orange")
        self.results_text.tag_configure("threat", foreground="red")
        self.results_text.tag_configure("suspicious", foreground="orange")
        self.results_text.tag_configure("clean", foreground="green")
        self.results_text.tag_configure("count", font=("Helvetica", 10))
        self.results_text.tag_configure("link", foreground="blue", underline=1)
        
        # Risk level colors with background for better visibility
        self.results_text.tag_configure("risk_low", foreground="white", background="green", 
                                        font=("Helvetica", 12, "bold"))
        self.results_text.tag_configure("risk_medium", foreground="white", background="orange", 
                                        font=("Helvetica", 12, "bold"))
        self.results_text.tag_configure("risk_high", foreground="white", background="red", 
                                        font=("Helvetica", 12, "bold"))
        
        # Basic information
        url = result.get('url', 'Unknown')
        risk_level = result.get('risk_level', 'Unknown')
        timestamp = result.get('timestamp', datetime.now().isoformat())
        
        # Format the timestamp for display
        try:
            dt = datetime.fromisoformat(timestamp)
            formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            formatted_time = timestamp
        
        # Display header with color based on risk level
        self.results_text.insert(tk.END, f"Scan Results for: {url}\n", "url")
        self.results_text.insert(tk.END, f"Time: {formatted_time}\n", "time")
        
        # Create a more prominent risk level display
        self.results_text.insert(tk.END, "Risk Level: ", "label")
        
        # Add risk level with appropriate color and padding
        risk_tag = f"risk_{risk_level.lower()}"
        # Add padding around the risk level text for better visibility
        self.results_text.insert(tk.END, f" {risk_level} ", risk_tag)
        self.results_text.insert(tk.END, "\n")
        
        # Create visual risk indicator
        risk_indicator = self.create_visual_risk_indicator(risk_level)
        
        # Insert the risk indicator canvas at the current position
        current_pos = self.results_text.index(tk.END)
        self.results_text.window_create(current_pos, window=risk_indicator)
        self.results_text.insert(tk.END, "\n\n")
        
        # Add a separator line
        self.results_text.insert(tk.END, "─" * 50 + "\n\n")
        
        # Display reason for flagging (if suspicious)
        if risk_level.lower() != "low":
            if result.get('heuristic_suspicious', False):
                self.results_text.insert(tk.END, "⚠️ SUSPICIOUS URL DETECTED!\n", "warning")
                # Look for log message about why it was flagged
                try:
                    if isinstance(result.get('virustotal'), dict):
                        vt_stats = result.get('virustotal', {}).get('data', {}).get('attributes', {}).get('stats', {})
                        if vt_stats and vt_stats.get('malicious', 0) > 0:
                            self.results_text.insert(tk.END, f"VirusTotal flagged this URL as malicious.\n", "warning")
                    
                    if isinstance(result.get('google_safe_browsing'), dict) and result.get('google_safe_browsing', {}).get('matches'):
                        self.results_text.insert(tk.END, f"Google Safe Browsing flagged this URL as harmful.\n", "warning")
                    
                    # Add additional explanation
                    self.results_text.insert(tk.END, "This URL has characteristics commonly found in phishing sites.\n\n", "warning")
                except Exception as e:
                    logger.error(f"Error adding suspicious reason: {str(e)}")
        
        # Heuristic check results
        heuristic = result.get('heuristic_suspicious', False)
        self.results_text.insert(tk.END, "Heuristic Analysis:\n", "section")
        if heuristic:
            self.results_text.insert(tk.END, "- URL contains suspicious patterns\n\n", "suspicious")
        else:
            self.results_text.insert(tk.END, "- No suspicious patterns detected\n\n", "clean")
        
        # VirusTotal results if available
        vt_result = result.get('virustotal')
        self.results_text.insert(tk.END, "VirusTotal Results:\n", "section")
        if vt_result:
            try:
                stats = vt_result.get('data', {}).get('attributes', {}).get('stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                
                total = malicious + suspicious + harmless + undetected
                
                if total > 0:
                    self.results_text.insert(tk.END, f"- Malicious: {malicious}/{total}\n", "count")
                    self.results_text.insert(tk.END, f"- Suspicious: {suspicious}/{total}\n", "count")
                    self.results_text.insert(tk.END, f"- Harmless: {harmless}/{total}\n", "count")
                    self.results_text.insert(tk.END, f"- Undetected: {undetected}/{total}\n\n", "count")
                else:
                    self.results_text.insert(tk.END, "- No results available\n\n", "info")
            except Exception as e:
                logger.error(f"Error parsing VirusTotal results: {str(e)}")
                self.results_text.insert(tk.END, "- Error parsing VirusTotal results\n\n", "error")
        else:
            # Check for web results
            vt_web_result = result.get('virustotal_web')
            if vt_web_result:
                try:
                    detected = vt_web_result.get('detected')
                    detection_note = vt_web_result.get('detection_note', 'No additional information')
                    
                    if detected is True:
                        self.results_text.insert(tk.END, "- Web check: URL flagged as malicious\n", "suspicious")
                        self.results_text.insert(tk.END, f"- Details: {detection_note}\n\n", "info")
                    elif detected is False:
                        self.results_text.insert(tk.END, "- Web check: URL appears to be clean\n", "clean")
                        self.results_text.insert(tk.END, f"- Details: {detection_note}\n\n", "info")
                    else:
                        self.results_text.insert(tk.END, "- Web check: Status undetermined\n", "info")
                        self.results_text.insert(tk.END, f"- Details: {detection_note}\n\n", "info")
                except Exception as e:
                    logger.error(f"Error parsing VirusTotal web results: {str(e)}")
                    self.results_text.insert(tk.END, "- Error parsing VirusTotal web results\n\n", "error")
            else:
                self.results_text.insert(tk.END, "- Not available (API key not configured)\n", "info")
                # Add clickable link to check on VirusTotal
                self.results_text.insert(tk.END, "- ")
                
                # Create a button to check on VirusTotal
                check_vt_button = ttk.Button(
                    self.results_text,
                    text="Check on VirusTotal",
                    command=lambda u=url: self.open_url_in_virustotal(u)
                )
                self.results_text.window_create(tk.END, window=check_vt_button)
                self.results_text.insert(tk.END, "\n\n")
        
        # Google Safe Browsing results if available
        gsb_result = result.get('google_safe_browsing')
        self.results_text.insert(tk.END, "Google Safe Browsing Results:\n", "section")
        if gsb_result:
            if 'matches' in gsb_result and gsb_result['matches']:
                matches = gsb_result['matches']
                self.results_text.insert(tk.END, f"- Found {len(matches)} threat(s):\n", "warning")
                for match in matches:
                    threat_type = match.get('threatType', 'Unknown')
                    platform = match.get('platformType', 'Unknown')
                    self.results_text.insert(tk.END, f"  - {threat_type} ({platform})\n", "threat")
                self.results_text.insert(tk.END, "\n")
            else:
                self.results_text.insert(tk.END, "- No threats detected\n\n", "clean")
        else:
            # Check for web results
            gsb_web_result = result.get('google_safe_browsing_web')
            if gsb_web_result:
                try:
                    detected = gsb_web_result.get('detected')
                    detection_note = gsb_web_result.get('detection_note', 'No additional information')
                    
                    if detected is True:
                        self.results_text.insert(tk.END, "- Web check: URL flagged as unsafe\n", "threat")
                        self.results_text.insert(tk.END, f"- Details: {detection_note}\n\n", "info")
                    elif detected is False:
                        self.results_text.insert(tk.END, "- Web check: URL appears to be safe\n", "clean")
                        self.results_text.insert(tk.END, f"- Details: {detection_note}\n\n", "info")
                    else:
                        self.results_text.insert(tk.END, "- Web check: Status undetermined\n", "info")
                        self.results_text.insert(tk.END, f"- Details: {detection_note}\n\n", "info")
                except Exception as e:
                    logger.error(f"Error parsing Google Safe Browsing web results: {str(e)}")
                    self.results_text.insert(tk.END, "- Error parsing Google Safe Browsing web results\n\n", "error")
            else:
                self.results_text.insert(tk.END, "- Not available (API key not configured)\n", "info")
                # Add clickable link to check on Google Safe Browsing
                self.results_text.insert(tk.END, "- ")
                
                # Create a button to check on Google Safe Browsing
                check_gsb_button = ttk.Button(
                    self.results_text,
                    text="Check on Google Safe Browsing",
                    command=lambda u=url: self.open_url_in_gsb(u)
                )
                self.results_text.window_create(tk.END, window=check_gsb_button)
                self.results_text.insert(tk.END, "\n\n")
        
        # Add another separator
        self.results_text.insert(tk.END, "─" * 50 + "\n\n")
        
        # Database information
        self.results_text.insert(tk.END, f"Scan saved to database with ID: {scan_id}\n", "info")
        
        # If this is part of a batch scan and not the last URL, add a page break
        if not is_last_url:
            self.results_text.insert(tk.END, "\n\n" + "=" * 80 + "\n\n")
        
        self.results_text.config(state=tk.DISABLED)
        
        # Update status
        self.status_var.set(f"Scan completed for {url}")
        
        # Refresh history to show the new scan
        self.refresh_history()
    
    def open_url_in_virustotal(self, url):
        """Open the URL in VirusTotal for additional analysis."""
        # URL encode the target URL
        encoded_url = urllib.parse.quote(url)
        vt_analysis_url = f"https://www.virustotal.com/gui/home/url?q={encoded_url}"
        
        try:
            # Update status
            self.status_var.set(f"Opening {url} in VirusTotal...")
            
            # Open in default browser
            webbrowser.open(vt_analysis_url)
            
            # Log the action
            logger.info(f"Opened URL in VirusTotal: {url}")
            
            # Update status again
            self.root.after(2000, lambda: self.status_var.set("Ready"))
        except Exception as e:
            logger.error(f"Error opening VirusTotal in browser: {str(e)}")
            messagebox.showerror("Error", f"Could not open VirusTotal: {str(e)}")
    
    def open_url_in_gsb(self, url):
        """Open the URL in Google Safe Browsing Transparency Report for additional analysis."""
        # URL encode the target URL
        encoded_url = urllib.parse.quote(url)
        gsb_analysis_url = f"https://transparencyreport.google.com/safe-browsing/search?url={encoded_url}"
        
        try:
            # Update status
            self.status_var.set(f"Opening {url} in Google Safe Browsing...")
            
            # Open in default browser
            webbrowser.open(gsb_analysis_url)
            
            # Log the action
            logger.info(f"Opened URL in Google Safe Browsing: {url}")
            
            # Update status again
            self.root.after(2000, lambda: self.status_var.set("Ready"))
        except Exception as e:
            logger.error(f"Error opening Google Safe Browsing in browser: {str(e)}")
            messagebox.showerror("Error", f"Could not open Google Safe Browsing: {str(e)}")
    
    def _display_error(self, error_msg):
        """Display an error message in the results area."""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Error: {error_msg}\n", "error")
        self.results_text.tag_configure("error", foreground="red", font=("Helvetica", 10, "bold"))
        self.results_text.config(state=tk.DISABLED)
        
        # Update status
        self.status_var.set("Error occurred during scan")
    
    def refresh_history(self):
        """Refresh the history table with the latest data."""
        # Clear the current table
        for item in self.history_table.get_children():
            self.history_table.delete(item)
        
        # Get the history from the database
        history = self.db.get_scan_history()
        
        # Populate the table
        for entry in history:
            scan_id = entry.get('id', '')
            url = entry.get('url', '')
            timestamp = entry.get('timestamp', '')
            risk_level = entry.get('risk_level', 'Unknown')
            
            # Try to format the timestamp
            try:
                dt = datetime.fromisoformat(timestamp)
                formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                formatted_time = timestamp
                
            # Add to table with tag based on risk level
            tag = risk_level.lower()
            self.history_table.insert('', 'end', values=(scan_id, url, formatted_time, risk_level), tags=(tag,))
            
        # Configure the tags for risk levels
        self.history_table.tag_configure('low', foreground='green')
        self.history_table.tag_configure('medium', foreground='orange')
        self.history_table.tag_configure('high', foreground='red')
        
        # Update status
        self.status_var.set(f"Loaded {len(history)} scan entries from history")
    
    def search_history(self):
        """Search the history for a URL substring."""
        query = self.search_entry.get().strip()
        if not query:
            self.refresh_history()
            return
            
        # Clear the current table
        for item in self.history_table.get_children():
            self.history_table.delete(item)
        
        # Search the database
        results = self.db.search_scans(query)
        
        # Populate the table
        for entry in results:
            scan_id = entry.get('id', '')
            url = entry.get('url', '')
            timestamp = entry.get('timestamp', '')
            risk_level = entry.get('risk_level', 'Unknown')
            
            # Try to format the timestamp
            try:
                dt = datetime.fromisoformat(timestamp)
                formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                formatted_time = timestamp
                
            # Add to table with tag based on risk level
            tag = risk_level.lower()
            self.history_table.insert('', 'end', values=(scan_id, url, formatted_time, risk_level), tags=(tag,))
        
        # Update status
        self.status_var.set(f"Found {len(results)} matching scan entries")
    
    def view_scan_details(self, event):
        """View detailed information for a selected scan."""
        # Get the selected item
        selection = self.history_table.selection()
        if not selection:
            messagebox.showinfo("Selection", "Please select a scan to view.")
            return
            
        # Get the scan ID from the selected item
        scan_id = self.history_table.item(selection[0], 'values')[0]
        
        # Get the scan details from the database
        details = self.db.get_scan_details(scan_id)
        if not details:
            messagebox.showerror("Error", f"Could not retrieve details for scan ID {scan_id}")
            return
        
        # Create a new window to show details
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Scan Details - ID: {scan_id}")
        details_window.geometry("800x600")
        details_window.minsize(600, 400)
        details_window.configure(background='#f0f0f0')
        
        # Main frame
        main_frame = ttk.Frame(details_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Header section
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        # URL and Timestamp
        url = details.get('url', 'Unknown')
        timestamp = details.get('timestamp', '')
        risk_level = details.get('risk_level', 'Unknown')
        
        # Format timestamp
        try:
            dt = datetime.fromisoformat(timestamp)
            formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            formatted_time = timestamp
        
        # Header info
        ttk.Label(header_frame, text=f"URL: {url}", 
                  font=('Helvetica', 12, 'bold')).pack(anchor=tk.W)
        ttk.Label(header_frame, text=f"Scan Time: {formatted_time}", 
                  font=('Helvetica', 10)).pack(anchor=tk.W)
        
        # Risk level with color
        risk_frame = ttk.Frame(header_frame)
        risk_frame.pack(anchor=tk.W, pady=5)
        ttk.Label(risk_frame, text="Risk Level: ", 
                  font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT)
        
        # Display risk level with appropriate color
        risk_color = "green"
        if risk_level.lower() == "medium":
            risk_color = "orange"
        elif risk_level.lower() == "high":
            risk_color = "red"
            
        risk_label = ttk.Label(risk_frame, text=risk_level, 
                              font=('Helvetica', 10, 'bold'))
        risk_label.pack(side=tk.LEFT)
        risk_label.configure(foreground=risk_color)
        
        # Add button to check on VirusTotal
        vt_button = ttk.Button(
            header_frame,
            text="Check on VirusTotal",
            command=lambda: self.open_url_in_virustotal(url)
        )
        vt_button.pack(anchor=tk.W, pady=5)
        
        # Add button to check on Google Safe Browsing
        gsb_button = ttk.Button(
            header_frame,
            text="Check on Google Safe Browsing",
            command=lambda: self.open_url_in_gsb(url)
        )
        gsb_button.pack(anchor=tk.W, pady=5)
        
        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        # Create notebook for different result sections
        results_notebook = ttk.Notebook(main_frame)
        results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Summary tab
        summary_frame = ttk.Frame(results_notebook)
        results_notebook.add(summary_frame, text="Summary")
        
        # Summary content
        summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD)
        summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Fill summary text
        summary_text.insert(tk.END, f"Scan ID: {scan_id}\n", "label")
        summary_text.insert(tk.END, f"URL: {url}\n", "value")
        summary_text.insert(tk.END, f"Scan Time: {formatted_time}\n", "value")
        summary_text.insert(tk.END, f"Risk Level: {risk_level}\n\n", "value")
        
        # Heuristic results
        heuristic = details.get('heuristic_suspicious', False)
        summary_text.insert(tk.END, "Heuristic Analysis:\n", "section")
        if heuristic:
            summary_text.insert(tk.END, "- URL contains suspicious patterns\n\n", "suspicious")
        else:
            summary_text.insert(tk.END, "- No suspicious patterns detected\n\n", "clean")
        
        # VT overview
        vt_result = details.get('virustotal')
        summary_text.insert(tk.END, "VirusTotal Results:\n", "section")
        if vt_result:
            stats = vt_result.get('data', {}).get('attributes', {}).get('stats', {})
            malicious = stats.get('malicious', 0)
            
            if malicious > 0:
                summary_text.insert(tk.END, f"- {malicious} security vendors flagged as malicious\n\n", "suspicious")
            else:
                summary_text.insert(tk.END, f"- No security vendors flagged as malicious\n\n", "clean")
        else:
            # Check for web results
            vt_web_result = details.get('virustotal_web')
            if vt_web_result:
                detected = vt_web_result.get('detected')
                detection_note = vt_web_result.get('detection_note', 'No additional information')
                
                if detected is True:
                    summary_text.insert(tk.END, "- Web check: URL flagged as malicious\n", "suspicious")
                    summary_text.insert(tk.END, f"- Details: {detection_note}\n\n", "info")
                elif detected is False:
                    summary_text.insert(tk.END, "- Web check: URL appears to be clean\n", "clean")
                    summary_text.insert(tk.END, f"- Details: {detection_note}\n\n", "info")
                else:
                    summary_text.insert(tk.END, "- Web check status undetermined\n\n", "info")
            else:
                summary_text.insert(tk.END, "- Not available (API key not configured)\n\n", "info")
        
        # GSB overview
        gsb_result = details.get('google_safe_browsing')
        summary_text.insert(tk.END, "Google Safe Browsing Results:\n", "section")
        if gsb_result:
            if 'matches' in gsb_result and gsb_result['matches']:
                matches = gsb_result['matches']
                summary_text.insert(tk.END, f"- Found in {len(matches)} threat lists\n\n", "suspicious")
            else:
                summary_text.insert(tk.END, "- No threats detected\n\n", "clean")
        else:
            # Check for web results
            gsb_web_result = details.get('google_safe_browsing_web')
            if gsb_web_result:
                detected = gsb_web_result.get('detected')
                detection_note = gsb_web_result.get('detection_note', 'No additional information')
                
                if detected is True:
                    summary_text.insert(tk.END, "- Web check: URL flagged as unsafe\n", "threat")
                    summary_text.insert(tk.END, f"- Details: {detection_note}\n\n", "info")
                elif detected is False:
                    summary_text.insert(tk.END, "- Web check: URL appears to be safe\n", "clean")
                    summary_text.insert(tk.END, f"- Details: {detection_note}\n\n", "info")
                else:
                    summary_text.insert(tk.END, "- Web check status undetermined\n\n", "info")
            else:
                summary_text.insert(tk.END, "- Not available (API key not configured)\n\n", "info")
        
        # Configure summary text tags
        summary_text.tag_configure("label", font=("Helvetica", 10, "bold"))
        summary_text.tag_configure("value", font=("Helvetica", 10))
        summary_text.tag_configure("section", font=("Helvetica", 11, "bold"))
        summary_text.tag_configure("info", foreground="blue")
        summary_text.tag_configure("error", foreground="red")
        summary_text.tag_configure("suspicious", foreground="orange")
        summary_text.tag_configure("clean", foreground="green")
        summary_text.config(state=tk.DISABLED)
        
        # Raw data tab
        raw_frame = ttk.Frame(results_notebook)
        results_notebook.add(raw_frame, text="Raw Data")
        
        # Raw content - text widget to display the details
        raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.WORD)
        raw_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Format the details nicely
        formatted_details = json.dumps(details, indent=4)
        raw_text.insert(tk.END, formatted_details)
        
        # Make it read-only
        raw_text.config(state=tk.DISABLED)
        
        # Add button frame at bottom
        button_frame = ttk.Frame(details_window)
        button_frame.pack(fill=tk.X, pady=10, padx=15)
        
        close_button = ttk.Button(
            button_frame,
            text="Close",
            command=details_window.destroy
        )
        close_button.pack(side=tk.RIGHT)
    
    def delete_selected_scan(self):
        """Delete the selected scan from the database."""
        # Get the selected item
        selection = self.history_table.selection()
        if not selection:
            messagebox.showinfo("Selection", "Please select a scan to delete.")
            return
            
        # Get the scan ID from the selected item
        scan_id = self.history_table.item(selection[0], 'values')[0]
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete scan ID {scan_id}?"):
            return
        
        # Delete from database
        success = self.db.delete_scan(scan_id)
        if success:
            messagebox.showinfo("Success", f"Scan ID {scan_id} deleted successfully.")
            # Refresh the history table
            self.refresh_history()
        else:
            messagebox.showerror("Error", f"Failed to delete scan ID {scan_id}")
    
    def save_settings_from_ui(self):
        """Save settings from the UI to the settings file and update the scanner."""
        # Get values from UI
        vt_api_key = self.vt_api_entry.get().strip()
        gsb_api_key = self.gsb_api_entry.get().strip()
        
        # Update settings
        self.settings['vt_api_key'] = vt_api_key
        self.settings['gsb_api_key'] = gsb_api_key
        
        # Save to file
        self.save_settings()
        
        # Reinitialize scanner with new keys
        self.initialize_scanner()
        
        # Update status
        self.status_var.set("Settings saved successfully")
        messagebox.showinfo("Settings", "Settings saved successfully.")

def main():
    root = tk.Tk()
    app = PhishingApp(root)
    root.mainloop()

if __name__ == "__main__":
    main() 