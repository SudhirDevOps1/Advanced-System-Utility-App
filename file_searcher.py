# import os
# from pathlib import Path


# class FileSearcher:
#     def __init__(self):
#         self.results = []
    
#     def search_files(self, filename, directory):
#         """Search for files with the given name in the specified directory"""
#         print(f"Searching for '{filename}' in '{directory}'...")
        
#         self.results = []
        
#         # Walk through all subdirectories
#         for root, dirs, files in os.walk(directory):
#             for file in files:
#                 if filename.lower() in file.lower():  # Case-insensitive partial match
#                     file_path = os.path.join(root, file)
#                     self.results.append(file_path)
#                     print(f"Found: {file_path}")
        
#         if not self.results:
#             print(f"No files containing '{filename}' found in '{directory}'.")
#         else:
#             print(f"\nFound {len(self.results)} file(s).")
        
#         return self.results
    
#     def search_by_extension(self, extension, directory):
#         """Search for files with the given extension"""
#         print(f"Searching for files with extension '.{extension}' in '{directory}'...")
        
#         self.results = []
        
#         # Ensure extension starts with a dot
#         if not extension.startswith('.'):
#             extension = '.' + extension
        
#         # Walk through all subdirectories
#         for root, dirs, files in os.walk(directory):
#             for file in files:
#                 if file.lower().endswith(extension.lower()):
#                     file_path = os.path.join(root, file)
#                     self.results.append(file_path)
#                     print(f"Found: {file_path}")
        
#         if not self.results:
#             print(f"No files with extension '.{extension}' found in '{directory}'.")
#         else:
#             print(f"\nFound {len(self.results)} file(s).")
        
#         return self.results





import os
from pathlib import Path
from datetime import datetime


class FileSearcher:
    def __init__(self):
        self.results = []
        self.folder_results = []
    
    # ============== FILE SEARCH METHODS ==============
    
    def search_files(self, filename, directory):
        """Search for files with the given name in the specified directory"""
        print(f"🔍 Searching for '{filename}' in '{directory}'...")
        
        self.results = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if filename.lower() in file.lower():
                    file_path = os.path.join(root, file)
                    self.results.append(file_path)
                    print(f"  ✅ Found: {file_path}")
        
        self._print_file_summary(filename)
        return self.results
    
    def search_by_extension(self, extension, directory):
        """Search for files with the given extension"""
        if not extension.startswith('.'):
            extension = '.' + extension
            
        print(f"🔍 Searching for '*{extension}' files in '{directory}'...")
        
        self.results = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.lower().endswith(extension.lower()):
                    file_path = os.path.join(root, file)
                    self.results.append(file_path)
                    print(f"  ✅ Found: {file_path}")
        
        self._print_file_summary(extension)
        return self.results
    
    # ============== FOLDER SEARCH METHODS ==============
    
    def search_folders(self, foldername, directory):
        """Search for folders with the given name"""
        print(f"📁 Searching for folder '{foldername}' in '{directory}'...")
        
        self.folder_results = []
        
        for root, dirs, files in os.walk(directory):
            for dir_name in dirs:
                if foldername.lower() in dir_name.lower():
                    folder_path = os.path.join(root, dir_name)
                    self.folder_results.append(folder_path)
                    print(f"  ✅ Found: {folder_path}")
        
        self._print_folder_summary(foldername)
        return self.folder_results
    
    def search_empty_folders(self, directory):
        """Search for empty folders"""
        print(f"📁 Searching for empty folders in '{directory}'...")
        
        self.folder_results = []
        
        for root, dirs, files in os.walk(directory):
            for dir_name in dirs:
                folder_path = os.path.join(root, dir_name)
                # Check if folder is empty
                if not os.listdir(folder_path):
                    self.folder_results.append(folder_path)
                    print(f"  ✅ Empty: {folder_path}")
        
        self._print_folder_summary("empty folders")
        return self.folder_results
    
    def search_folders_by_size(self, directory, min_size_mb=0, max_size_mb=float('inf')):
        """Search folders by size (in MB)"""
        print(f"📁 Searching folders between {min_size_mb}MB and {max_size_mb}MB...")
        
        self.folder_results = []
        
        for root, dirs, files in os.walk(directory):
            for dir_name in dirs:
                folder_path = os.path.join(root, dir_name)
                size_mb = self._get_folder_size(folder_path) / (1024 * 1024)
                
                if min_size_mb <= size_mb <= max_size_mb:
                    self.folder_results.append({
                        'path': folder_path,
                        'size_mb': round(size_mb, 2)
                    })
                    print(f"  ✅ {folder_path} ({round(size_mb, 2)} MB)")
        
        print(f"\n📊 Found {len(self.folder_results)} folder(s).")
        return self.folder_results
    
    # ============== COMBINED SEARCH ==============
    
    def search_all(self, name, directory):
        """Search for both files and folders with the given name"""
        print(f"🔍 Searching for '{name}' (files & folders) in '{directory}'...")
        print("=" * 50)
        
        self.results = []
        self.folder_results = []
        
        for root, dirs, files in os.walk(directory):
            # Search folders
            for dir_name in dirs:
                if name.lower() in dir_name.lower():
                    folder_path = os.path.join(root, dir_name)
                    self.folder_results.append(folder_path)
                    print(f"  📁 Folder: {folder_path}")
            
            # Search files
            for file in files:
                if name.lower() in file.lower():
                    file_path = os.path.join(root, file)
                    self.results.append(file_path)
                    print(f"  📄 File: {file_path}")
        
        print("=" * 50)
        print(f"📊 Found {len(self.folder_results)} folder(s) and {len(self.results)} file(s).")
        
        return {
            'files': self.results,
            'folders': self.folder_results
        }
    
    # ============== ADVANCED SEARCH ==============
    
    def search_by_date(self, directory, start_date=None, end_date=None):
        """Search files modified between two dates"""
        print(f"🔍 Searching files by date in '{directory}'...")
        
        self.results = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                
                # Check date range
                if start_date and mod_time < start_date:
                    continue
                if end_date and mod_time > end_date:
                    continue
                
                self.results.append({
                    'path': file_path,
                    'modified': mod_time.strftime('%Y-%m-%d %H:%M:%S')
                })
                print(f"  ✅ {file_path} (Modified: {mod_time.strftime('%Y-%m-%d')})")
        
        print(f"\n📊 Found {len(self.results)} file(s).")
        return self.results
    
    def search_by_size(self, directory, min_size_kb=0, max_size_kb=float('inf')):
        """Search files by size (in KB)"""
        print(f"🔍 Searching files between {min_size_kb}KB and {max_size_kb}KB...")
        
        self.results = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                size_kb = os.path.getsize(file_path) / 1024
                
                if min_size_kb <= size_kb <= max_size_kb:
                    self.results.append({
                        'path': file_path,
                        'size_kb': round(size_kb, 2)
                    })
                    print(f"  ✅ {file_path} ({round(size_kb, 2)} KB)")
        
        print(f"\n📊 Found {len(self.results)} file(s).")
        return self.results
    
    def search_large_files(self, directory, min_size_mb=100):
        """Find large files (default: > 100MB)"""
        print(f"🔍 Searching files larger than {min_size_mb}MB...")
        
        self.results = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    size_mb = os.path.getsize(file_path) / (1024 * 1024)
                    if size_mb >= min_size_mb:
                        self.results.append({
                            'path': file_path,
                            'size_mb': round(size_mb, 2)
                        })
                        print(f"  ✅ {file_path} ({round(size_mb, 2)} MB)")
                except:
                    pass
        
        # Sort by size (largest first)
        self.results.sort(key=lambda x: x['size_mb'], reverse=True)
        print(f"\n📊 Found {len(self.results)} large file(s).")
        return self.results
    
    def search_duplicate_names(self, directory):
        """Find files with duplicate names"""
        print(f"🔍 Searching for duplicate file names in '{directory}'...")
        
        file_dict = {}
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if file.lower() in file_dict:
                    file_dict[file.lower()].append(file_path)
                else:
                    file_dict[file.lower()] = [file_path]
        
        # Filter only duplicates
        duplicates = {k: v for k, v in file_dict.items() if len(v) > 1}
        
        for filename, paths in duplicates.items():
            print(f"\n  📄 '{filename}' found {len(paths)} times:")
            for path in paths:
                print(f"      → {path}")
        
        print(f"\n📊 Found {len(duplicates)} duplicate file name(s).")
        return duplicates
    
    # ============== HELPER METHODS ==============
    
    def _get_folder_size(self, folder_path):
        """Calculate total size of a folder"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except:
                    pass
        return total_size
    
    def _print_file_summary(self, search_term):
        if not self.results:
            print(f"❌ No files containing '{search_term}' found.")
        else:
            print(f"\n📊 Found {len(self.results)} file(s).")
    
    def _print_folder_summary(self, search_term):
        if not self.folder_results:
            print(f"❌ No folders matching '{search_term}' found.")
        else:
            print(f"\n📊 Found {len(self.folder_results)} folder(s).")
    
    def get_stats(self, directory):
        """Get directory statistics"""
        print(f"📊 Calculating stats for '{directory}'...")
        
        total_files = 0
        total_folders = 0
        total_size = 0
        extensions = {}
        
        for root, dirs, files in os.walk(directory):
            total_folders += len(dirs)
            total_files += len(files)
            
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    total_size += os.path.getsize(file_path)
                except:
                    pass
                
                # Count extensions
                ext = os.path.splitext(file)[1].lower() or 'no extension'
                extensions[ext] = extensions.get(ext, 0) + 1
        
        stats = {
            'total_files': total_files,
            'total_folders': total_folders,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'extensions': dict(sorted(extensions.items(), key=lambda x: x[1], reverse=True)[:10])
        }
        
        print(f"\n  📁 Total Folders: {total_folders}")
        print(f"  📄 Total Files: {total_files}")
        print(f"  💾 Total Size: {stats['total_size_mb']} MB")
        print(f"  📋 Top Extensions: {stats['extensions']}")
        
        return stats


# ============== USAGE EXAMPLES ==============

if __name__ == "__main__":
    searcher = FileSearcher()
    
    # Set your search directory
    search_dir = "."  # Current directory (change as needed)
    
    print("\n" + "="*60)
    print("         FILE & FOLDER SEARCHER")
    print("="*60 + "\n")
    
    # Example 1: Search for files
    # searcher.search_files("test", search_dir)
    
    # Example 2: Search by extension
    # searcher.search_by_extension("py", search_dir)
    
    # Example 3: Search for folders ✨ NEW
    # searcher.search_folders("src", search_dir)
    
    # Example 4: Search for empty folders ✨ NEW
    # searcher.search_empty_folders(search_dir)
    
    # Example 5: Search both files and folders ✨ NEW
    # searcher.search_all("config", search_dir)
    
    # Example 6: Find large files ✨ NEW
    # searcher.search_large_files(search_dir, min_size_mb=10)
    
    # Example 7: Find duplicates ✨ NEW
    # searcher.search_duplicate_names(search_dir)
    
    # Example 8: Get directory stats ✨ NEW
    searcher.get_stats(search_dir)