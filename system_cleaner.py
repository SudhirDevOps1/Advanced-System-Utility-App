import os
import shutil
import psutil
import tempfile
from pathlib import Path
import datetime


class SystemCleaner:
    def __init__(self):
        self.cleaned_items = []
    
    def cleanup_system(self):
        """Perform general system cleanup"""
        print("Starting system cleanup...")
        
        # Clean temp files
        temp_cleaned = self._clean_temp_directories()
        
        # Clean recycle bin (Windows specific)
        recycle_cleaned = self._clean_recycle_bin()
        
        # Clean log files
        logs_cleaned = self._clean_log_files()
        
        # Show disk usage before and after
        self._show_disk_usage()
        
        total_cleaned = temp_cleaned + recycle_cleaned + logs_cleaned
        print(f"\nSystem cleanup completed. Total items cleaned: {total_cleaned}")
        
        return total_cleaned
    
    def _clean_temp_directories(self):
        """Clean various temporary directories"""
        print("Cleaning temporary directories...")
        
        temp_dirs = [
            os.path.join(os.environ['WINDIR'], 'Temp'),  # Windows temp
            os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Temp'),  # User temp
            tempfile.gettempdir(),  # Python's temp dir
        ]
        
        cleaned_count = 0
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                for root, dirs, files in os.walk(temp_dir, topdown=False):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            # Check if file is older than 7 days
                            file_time = os.path.getctime(file_path)
                            file_date = datetime.datetime.fromtimestamp(file_time)
                            if datetime.datetime.now() - file_date > datetime.timedelta(days=7):
                                os.remove(file_path)
                                self.cleaned_items.append(file_path)
                                cleaned_count += 1
                        except Exception as e:
                            # Skip files that can't be removed (in use, permissions, etc.)
                            continue
                    
                    # Remove empty directories
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        try:
                            if not os.listdir(dir_path):  # Directory is empty
                                os.rmdir(dir_path)
                        except Exception:
                            # Skip directories that can't be removed
                            continue
        
        print(f"Cleaned {cleaned_count} temporary files.")
        return cleaned_count
    
    def _clean_recycle_bin(self):
        """Clean the recycle bin (Windows specific)"""
        print("Checking Recycle Bin...")
        
        # Note: Python doesn't have direct access to Recycle Bin
        # This is a placeholder - actual implementation would require external tools
        print("Recycle Bin cleaning requires special permissions and external tools.")
        print("Skipping Recycle Bin cleanup.")
        return 0
    
    def _clean_log_files(self):
        """Clean common log files"""
        print("Cleaning log files...")
        
        log_extensions = ['.log', '.txt']
        log_locations = [
            os.path.join(os.environ['WINDIR'], 'Logs'),
            os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local'),
            os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming'),
        ]
        
        cleaned_count = 0
        for location in log_locations:
            if os.path.exists(location):
                for root, dirs, files in os.walk(location):
                    for file in files:
                        if any(file.lower().endswith(ext) for ext in log_extensions):
                            file_path = os.path.join(root, file)
                            try:
                                # Only remove logs older than 30 days
                                file_time = os.path.getctime(file_path)
                                file_date = datetime.datetime.fromtimestamp(file_time)
                                if datetime.datetime.now() - file_date > datetime.timedelta(days=30):
                                    os.remove(file_path)
                                    self.cleaned_items.append(file_path)
                                    cleaned_count += 1
                            except Exception:
                                # Skip files that can't be removed
                                continue
        
        print(f"Cleaned {cleaned_count} log files.")
        return cleaned_count
    
    def _show_disk_usage(self):
        """Show disk usage statistics"""
        print("\nDisk Usage Information:")
        print("-" * 30)
        
        # Get disk usage for the main drive
        try:
            disk_usage = psutil.disk_usage('/')
            total = disk_usage.total / (1024**3)  # Convert to GB
            used = disk_usage.used / (1024**3)
            free = disk_usage.free / (1024**3)
            
            print(f"Total space: {total:.2f} GB")
            print(f"Used space: {used:.2f} GB")
            print(f"Free space: {free:.2f} GB")
        except:
            print("Could not retrieve disk usage information.")
    
    def optimize_startup_programs(self):
        """List and optionally disable startup programs (placeholder)"""
        print("Listing startup programs...")
        print("This feature would list programs that run at startup.")
        print("Actual implementation would require platform-specific code.")
        # Actual implementation would vary by OS and require admin rights