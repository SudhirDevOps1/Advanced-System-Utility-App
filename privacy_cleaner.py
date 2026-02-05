import os
import shutil
import tempfile
from pathlib import Path
import datetime


class PrivacyCleaner:
    def __init__(self):
        self.cleaned_items = []
    
    def clean_temp_files(self):
        """Clean temporary files from the system"""
        print("Cleaning temporary files...")
        
        temp_dirs = [
            tempfile.gettempdir(),  # System temp directory
            os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Temp'),  # Windows temp
            os.path.expanduser('~/.cache'),  # User cache (Linux/Mac)
        ]
        
        cleaned_count = 0
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                for root, dirs, files in os.walk(temp_dir, topdown=False):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            # Check if file is older than 1 day
                            file_time = os.path.getctime(file_path)
                            file_date = datetime.datetime.fromtimestamp(file_time)
                            if datetime.datetime.now() - file_date > datetime.timedelta(days=1):
                                os.remove(file_path)
                                self.cleaned_items.append(file_path)
                                cleaned_count += 1
                                print(f"Removed: {file_path}")
                        except Exception as e:
                            print(f"Could not remove {file_path}: {str(e)}")
                    
                    # Remove empty directories
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        try:
                            if not os.listdir(dir_path):  # Directory is empty
                                os.rmdir(dir_path)
                                print(f"Removed empty directory: {dir_path}")
                        except Exception as e:
                            print(f"Could not remove directory {dir_path}: {str(e)}")
        
        print(f"Cleaned {cleaned_count} temporary files.")
        return cleaned_count
    
    def clean_recent_documents(self):
        """Clean recent documents list (Windows specific)"""
        print("Cleaning recent documents...")
        
        recent_docs_path = os.path.join(os.environ['USERPROFILE'], 'Recent')
        
        if os.path.exists(recent_docs_path):
            try:
                for item in os.listdir(recent_docs_path):
                    item_path = os.path.join(recent_docs_path, item)
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                        self.cleaned_items.append(item_path)
                        print(f"Removed recent document: {item_path}")
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                        print(f"Removed recent folder: {item_path}")
                        
                print("Recent documents cleared.")
                return True
            except Exception as e:
                print(f"Error cleaning recent documents: {str(e)}")
                return False
        else:
            print("Recent documents folder not found.")
            return False
    
    def clean_browser_cache(self):
        """Clean browser cache files"""
        print("Cleaning browser cache...")
        
        browser_cache_paths = [
            os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Cache'),
            os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'),
            os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles'),
        ]
        
        cleaned_size = 0
        for cache_path in browser_cache_paths:
            if os.path.exists(cache_path):
                for root, dirs, files in os.walk(cache_path, topdown=False):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            size = os.path.getsize(file_path)
                            os.remove(file_path)
                            self.cleaned_items.append(file_path)
                            cleaned_size += size
                            print(f"Removed cache file: {file_path}")
                        except Exception as e:
                            print(f"Could not remove {file_path}: {str(e)}")
        
        print(f"Browser cache cleaned. Freed approximately {cleaned_size / (1024*1024):.2f} MB.")
        return cleaned_size