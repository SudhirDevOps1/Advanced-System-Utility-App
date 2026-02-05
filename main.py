# import os
# import sys
# from gui_app import SystemUtilityApp
# import tkinter as tk


# def main():
#     print("Advanced System Utility App")
#     print("===========================")
#     print("Launching GUI application...")
    
#     # Launch the GUI application
#     root = tk.Tk()
#     app = SystemUtilityApp(root)
#     root.mainloop()


# if __name__ == "__main__":
#     main()

import os
import sys
import time
import logging
import argparse
import platform
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from pathlib import Path

# Try importing the GUI app
try:
    from gui_app import SystemUtilityApp
except ImportError as e:
    print(f"❌ Error: Could not import gui_app module: {e}")
    sys.exit(1)


# ============== CONFIGURATION ==============

APP_NAME = "Advanced System Utility"
APP_VERSION = "2.0.0"
APP_AUTHOR = "Your Name"
LOG_DIR = Path("logs")
CONFIG_DIR = Path("config")
TEMP_DIR = Path("temp")


# ============== LOGGING SETUP ==============

def setup_logging(debug_mode=False):
    """Setup logging configuration"""
    LOG_DIR.mkdir(exist_ok=True)
    
    log_level = logging.DEBUG if debug_mode else logging.INFO
    log_file = LOG_DIR / f"app_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)


# ============== SPLASH SCREEN ==============

class SplashScreen:
    """Beautiful splash screen while app loads"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("")
        self.root.overrideredirect(True)  # Remove window decorations
        
        # Window size and position (center of screen)
        width, height = 500, 300
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        # Create splash content
        self._create_splash_content()
        
        # Make window stay on top
        self.root.attributes('-topmost', True)
        
    def _create_splash_content(self):
        """Create splash screen UI"""
        # Main frame with gradient-like effect
        main_frame = tk.Frame(self.root, bg='#1a1a2e')
        main_frame.pack(fill='both', expand=True)
        
        # Border effect
        border_frame = tk.Frame(main_frame, bg='#0f3460', padx=3, pady=3)
        border_frame.pack(fill='both', expand=True, padx=2, pady=2)
        
        content_frame = tk.Frame(border_frame, bg='#16213e')
        content_frame.pack(fill='both', expand=True)
        
        # App Icon/Logo (using text as placeholder)
        logo_label = tk.Label(
            content_frame,
            text="⚙️",
            font=('Segoe UI Emoji', 50),
            bg='#16213e',
            fg='#e94560'
        )
        logo_label.pack(pady=(40, 10))
        
        # App name
        name_label = tk.Label(
            content_frame,
            text=APP_NAME,
            font=('Segoe UI', 24, 'bold'),
            bg='#16213e',
            fg='#ffffff'
        )
        name_label.pack()
        
        # Version
        version_label = tk.Label(
            content_frame,
            text=f"Version {APP_VERSION}",
            font=('Segoe UI', 10),
            bg='#16213e',
            fg='#a0a0a0'
        )
        version_label.pack(pady=(5, 30))
        
        # Progress bar
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(
            "Custom.Horizontal.TProgressbar",
            troughcolor='#1a1a2e',
            background='#e94560',
            darkcolor='#e94560',
            lightcolor='#e94560',
            bordercolor='#16213e'
        )
        
        self.progress = ttk.Progressbar(
            content_frame,
            style="Custom.Horizontal.TProgressbar",
            length=350,
            mode='determinate'
        )
        self.progress.pack(pady=10)
        
        # Status label
        self.status_label = tk.Label(
            content_frame,
            text="Initializing...",
            font=('Segoe UI', 9),
            bg='#16213e',
            fg='#a0a0a0'
        )
        self.status_label.pack(pady=5)
        
        # Copyright
        copyright_label = tk.Label(
            content_frame,
            text=f"© 2024 {APP_AUTHOR}. All rights reserved.",
            font=('Segoe UI', 8),
            bg='#16213e',
            fg='#606060'
        )
        copyright_label.pack(side='bottom', pady=10)
    
    def update_progress(self, value, status_text=""):
        """Update progress bar and status"""
        self.progress['value'] = value
        if status_text:
            self.status_label.config(text=status_text)
        self.root.update()
    
    def close(self):
        """Close splash screen"""
        self.root.destroy()


# ============== SYSTEM CHECKS ==============

class SystemChecker:
    """Perform system compatibility checks"""
    
    def __init__(self, logger):
        self.logger = logger
        self.issues = []
    
    def check_python_version(self):
        """Check Python version compatibility"""
        required_version = (3, 8)
        current_version = sys.version_info[:2]
        
        if current_version >= required_version:
            self.logger.info(f"✅ Python version: {sys.version}")
            return True
        else:
            self.issues.append(f"Python {required_version[0]}.{required_version[1]}+ required")
            self.logger.error(f"❌ Python version too old: {sys.version}")
            return False
    
    def check_os_compatibility(self):
        """Check OS compatibility"""
        supported_os = ['Windows', 'Linux', 'Darwin']
        current_os = platform.system()
        
        if current_os in supported_os:
            self.logger.info(f"✅ Operating System: {current_os} {platform.release()}")
            return True
        else:
            self.issues.append(f"Unsupported OS: {current_os}")
            self.logger.warning(f"⚠️ Unsupported OS: {current_os}")
            return False
    
    def check_dependencies(self):
        """Check required dependencies"""
        required_modules = [
            ('tkinter', 'tkinter'),
            ('PIL', 'Pillow'),
            ('psutil', 'psutil'),
        ]
        
        all_ok = True
        for module_name, package_name in required_modules:
            try:
                __import__(module_name)
                self.logger.info(f"✅ Module '{module_name}' is available")
            except ImportError:
                self.issues.append(f"Missing module: {package_name}")
                self.logger.warning(f"⚠️ Module '{module_name}' not found. Install with: pip install {package_name}")
                all_ok = False
        
        return all_ok
    
    def check_disk_space(self, min_space_mb=100):
        """Check available disk space"""
        try:
            import shutil
            total, used, free = shutil.disk_usage("/")
            free_mb = free // (1024 * 1024)
            
            if free_mb >= min_space_mb:
                self.logger.info(f"✅ Free disk space: {free_mb} MB")
                return True
            else:
                self.issues.append(f"Low disk space: {free_mb} MB")
                self.logger.warning(f"⚠️ Low disk space: {free_mb} MB")
                return False
        except Exception as e:
            self.logger.warning(f"⚠️ Could not check disk space: {e}")
            return True
    
    def check_display(self):
        """Check display availability"""
        try:
            test_root = tk.Tk()
            screen_width = test_root.winfo_screenwidth()
            screen_height = test_root.winfo_screenheight()
            test_root.destroy()
            
            self.logger.info(f"✅ Display: {screen_width}x{screen_height}")
            return True
        except Exception as e:
            self.issues.append("No display available")
            self.logger.error(f"❌ Display error: {e}")
            return False
    
    def run_all_checks(self):
        """Run all system checks"""
        self.logger.info("🔍 Running system checks...")
        
        checks = [
            ("Python Version", self.check_python_version),
            ("OS Compatibility", self.check_os_compatibility),
            ("Dependencies", self.check_dependencies),
            ("Disk Space", self.check_disk_space),
            ("Display", self.check_display),
        ]
        
        results = {}
        for name, check_func in checks:
            results[name] = check_func()
        
        all_passed = all(results.values())
        
        if all_passed:
            self.logger.info("✅ All system checks passed!")
        else:
            self.logger.warning(f"⚠️ Some checks failed: {self.issues}")
        
        return all_passed, results, self.issues


# ============== SINGLE INSTANCE CHECK ==============

class SingleInstance:
    """Ensure only one instance of the app runs"""
    
    def __init__(self, app_name):
        self.lockfile = TEMP_DIR / f"{app_name}.lock"
        self.is_locked = False
    
    def acquire(self):
        """Try to acquire the lock"""
        TEMP_DIR.mkdir(exist_ok=True)
        
        try:
            if self.lockfile.exists():
                # Check if the process is still running
                try:
                    with open(self.lockfile, 'r') as f:
                        old_pid = int(f.read().strip())
                    
                    # Check if process exists (platform-specific)
                    if platform.system() == 'Windows':
                        import subprocess
                        result = subprocess.run(
                            ['tasklist', '/FI', f'PID eq {old_pid}'],
                            capture_output=True, text=True
                        )
                        if str(old_pid) in result.stdout:
                            return False
                    else:
                        os.kill(old_pid, 0)
                        return False
                except (ProcessLookupError, ValueError, FileNotFoundError):
                    pass  # Process doesn't exist, we can proceed
            
            # Create lock file with current PID
            with open(self.lockfile, 'w') as f:
                f.write(str(os.getpid()))
            
            self.is_locked = True
            return True
            
        except Exception:
            return True  # On error, allow running
    
    def release(self):
        """Release the lock"""
        if self.is_locked and self.lockfile.exists():
            try:
                self.lockfile.unlink()
            except Exception:
                pass


# ============== COMMAND LINE ARGUMENTS ==============

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} - A comprehensive system utility tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Normal launch
  python main.py --debug            # Launch with debug mode
  python main.py --no-splash        # Skip splash screen
  python main.py --theme dark       # Use dark theme
  python main.py --minimize         # Start minimized
        """
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'{APP_NAME} v{APP_VERSION}'
    )
    
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug mode with verbose logging'
    )
    
    parser.add_argument(
        '--no-splash',
        action='store_true',
        help='Skip the splash screen'
    )
    
    parser.add_argument(
        '--no-checks',
        action='store_true',
        help='Skip system compatibility checks'
    )
    
    parser.add_argument(
        '--theme', '-t',
        choices=['light', 'dark', 'system'],
        default='system',
        help='Set application theme (default: system)'
    )
    
    parser.add_argument(
        '--minimize', '-m',
        action='store_true',
        help='Start application minimized to system tray'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default=None,
        help='Path to custom configuration file'
    )
    
    parser.add_argument(
        '--reset',
        action='store_true',
        help='Reset all settings to default'
    )
    
    parser.add_argument(
        '--portable',
        action='store_true',
        help='Run in portable mode (no system changes)'
    )
    
    return parser.parse_args()


# ============== CONFIGURATION MANAGER ==============

class ConfigManager:
    """Manage application configuration"""
    
    DEFAULT_CONFIG = {
        'theme': 'system',
        'language': 'en',
        'auto_update': True,
        'start_minimized': False,
        'remember_window_size': True,
        'window_width': 1200,
        'window_height': 800,
        'last_directory': '',
        'recent_files': [],
        'show_hidden_files': False,
    }
    
    def __init__(self, config_path=None):
        CONFIG_DIR.mkdir(exist_ok=True)
        self.config_file = config_path or (CONFIG_DIR / "settings.json")
        self.config = self.load()
    
    def load(self):
        """Load configuration from file"""
        try:
            if self.config_file.exists():
                import json
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults (in case new options were added)
                    return {**self.DEFAULT_CONFIG, **loaded_config}
        except Exception as e:
            print(f"⚠️ Could not load config: {e}")
        
        return self.DEFAULT_CONFIG.copy()
    
    def save(self):
        """Save configuration to file"""
        try:
            import json
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"⚠️ Could not save config: {e}")
            return False
    
    def get(self, key, default=None):
        """Get a configuration value"""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """Set a configuration value"""
        self.config[key] = value
        self.save()
    
    def reset(self):
        """Reset configuration to defaults"""
        self.config = self.DEFAULT_CONFIG.copy()
        self.save()


# ============== MAIN APPLICATION LAUNCHER ==============

class AppLauncher:
    """Main application launcher with all features"""
    
    def __init__(self, args):
        self.args = args
        self.logger = setup_logging(args.debug)
        self.config = ConfigManager(args.config)
        self.single_instance = SingleInstance(APP_NAME.replace(" ", "_"))
        self.splash = None
        
    def print_banner(self):
        """Print startup banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ⚙️  {APP_NAME:^45}  ║
║                                                              ║
║     Version: {APP_VERSION:^43}   ║
║     Author:  {APP_AUTHOR:^43}   ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Platform: {platform.system()} {platform.release():^40} ║
║  Python:   {sys.version.split()[0]:^45} ║
║  Time:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^45} ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
        self.logger.info(f"Starting {APP_NAME} v{APP_VERSION}")
    
    def check_single_instance(self):
        """Ensure only one instance is running"""
        if not self.single_instance.acquire():
            self.logger.warning("Another instance is already running!")
            messagebox.showwarning(
                "Already Running",
                f"{APP_NAME} is already running.\n\n"
                "Please check your system tray or task manager."
            )
            return False
        return True
    
    def run_system_checks(self):
        """Run system compatibility checks"""
        if self.args.no_checks:
            self.logger.info("Skipping system checks (--no-checks)")
            return True
        
        checker = SystemChecker(self.logger)
        passed, results, issues = checker.run_all_checks()
        
        if not passed:
            response = messagebox.askquestion(
                "System Check Warning",
                f"Some system checks failed:\n\n"
                f"• " + "\n• ".join(issues) + "\n\n"
                "Do you want to continue anyway?",
                icon='warning'
            )
            return response == 'yes'
        
        return True
    
    def show_splash(self):
        """Show splash screen with loading animation"""
        if self.args.no_splash:
            self.logger.info("Skipping splash screen (--no-splash)")
            return
        
        self.splash = SplashScreen()
        
        # Simulate loading steps
        loading_steps = [
            (10, "Loading configuration..."),
            (25, "Checking system resources..."),
            (40, "Initializing modules..."),
            (55, "Loading plugins..."),
            (70, "Preparing user interface..."),
            (85, "Applying theme..."),
            (95, "Almost ready..."),
            (100, "Launching application..."),
        ]
        
        for progress, status in loading_steps:
            self.splash.update_progress(progress, status)
            time.sleep(0.2)  # Brief delay for visual effect
        
        time.sleep(0.3)
        self.splash.close()
    
    def apply_theme(self, root):
        """Apply the selected theme"""
        theme = self.args.theme
        if theme == 'system':
            theme = self.config.get('theme', 'light')
        
        self.logger.info(f"Applying theme: {theme}")
        
        # Theme colors
        themes = {
            'light': {
                'bg': '#ffffff',
                'fg': '#000000',
                'accent': '#0078d4'
            },
            'dark': {
                'bg': '#1e1e1e',
                'fg': '#ffffff',
                'accent': '#0078d4'
            }
        }
        
        if theme in themes:
            colors = themes[theme]
            root.configure(bg=colors['bg'])
            # Additional theme configuration can be added here
    
    def setup_exception_handler(self, root):
        """Setup global exception handler"""
        def handle_exception(exc_type, exc_value, exc_traceback):
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return
            
            self.logger.error(
                "Uncaught exception:",
                exc_info=(exc_type, exc_value, exc_traceback)
            )
            
            messagebox.showerror(
                "Error",
                f"An unexpected error occurred:\n\n{exc_value}\n\n"
                "Please check the log file for details."
            )
        
        sys.excepthook = handle_exception
        
        # Also handle Tkinter exceptions
        def handle_tk_exception(*args):
            self.logger.error(f"Tkinter exception: {args}")
        
        root.report_callback_exception = handle_tk_exception
    
    def launch_app(self):
        """Launch the main application"""
        self.logger.info("Launching main application...")
        
        try:
            # Create main window
            root = tk.Tk()
            
            # Setup exception handling
            self.setup_exception_handler(root)
            
            # Apply theme
            self.apply_theme(root)
            
            # Window configuration
            root.title(f"{APP_NAME} v{APP_VERSION}")
            
            # Set window size from config
            width = self.config.get('window_width', 1200)
            height = self.config.get('window_height', 800)
            
            # Center window
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()
            x = (screen_width - width) // 2
            y = (screen_height - height) // 2
            root.geometry(f"{width}x{height}+{x}+{y}")
            
            # Set minimum size
            root.minsize(800, 600)
            
            # Set window icon (if available)
            try:
                if platform.system() == 'Windows':
                    icon_path = Path("assets/icon.ico")
                    if icon_path.exists():
                        root.iconbitmap(str(icon_path))
                else:
                    icon_path = Path("assets/icon.png")
                    if icon_path.exists():
                        icon = tk.PhotoImage(file=str(icon_path))
                        root.iconphoto(True, icon)
            except Exception as e:
                self.logger.warning(f"Could not set window icon: {e}")
            
            # Start minimized if requested
            if self.args.minimize or self.config.get('start_minimized'):
                root.iconify()
            
            # Create the main application
            app = SystemUtilityApp(root)
            
            # Pass configuration to app if it supports it
            if hasattr(app, 'set_config'):
                app.set_config(self.config)
            
            # Handle window close
            def on_closing():
                # Save window size
                if self.config.get('remember_window_size'):
                    self.config.set('window_width', root.winfo_width())
                    self.config.set('window_height', root.winfo_height())
                
                self.logger.info("Application closing...")
                self.cleanup()
                root.destroy()
            
            root.protocol("WM_DELETE_WINDOW", on_closing)
            
            # Start main loop
            self.logger.info("Application started successfully!")
            root.mainloop()
            
        except Exception as e:
            self.logger.error(f"Failed to launch application: {e}")
            messagebox.showerror(
                "Launch Error",
                f"Failed to launch {APP_NAME}:\n\n{e}"
            )
            self.cleanup()
            sys.exit(1)
    
    def cleanup(self):
        """Cleanup resources on exit"""
        self.logger.info("Cleaning up resources...")
        self.single_instance.release()
        self.config.save()
        
        # Clean old log files (keep last 10)
        try:
            log_files = sorted(LOG_DIR.glob("app_*.log"), reverse=True)
            for old_log in log_files[10:]:
                old_log.unlink()
        except Exception:
            pass
    
    def run(self):
        """Main entry point"""
        try:
            # Print banner
            self.print_banner()
            
            # Handle reset flag
            if self.args.reset:
                self.config.reset()
                self.logger.info("Configuration reset to defaults")
            
            # Check single instance
            if not self.check_single_instance():
                return 1
            
            # Show splash screen
            self.show_splash()
            
            # Run system checks
            if not self.run_system_checks():
                self.cleanup()
                return 1
            
            # Launch main application
            self.launch_app()
            
            return 0
            
        except KeyboardInterrupt:
            self.logger.info("Application interrupted by user")
            self.cleanup()
            return 0
            
        except Exception as e:
            self.logger.error(f"Critical error: {e}")
            self.cleanup()
            return 1


# ============== MAIN ENTRY POINT ==============

def main():
    """Main entry point"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Create and run launcher
    launcher = AppLauncher(args)
    exit_code = launcher.run()
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()