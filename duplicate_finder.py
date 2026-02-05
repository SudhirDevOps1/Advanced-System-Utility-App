import os
import hashlib
from pathlib import Path


class DuplicateFinder:
    def __init__(self):
        self.duplicates = []
    
    def calculate_hash(self, file_path):
        """Calculate MD5 hash of a file"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            print(f"Error reading file {file_path}: {str(e)}")
            return None
    
    def find_duplicates(self, directory):
        """Find duplicate files in a given directory"""
        print(f"Scanning {directory} for duplicates...")
        
        # Dictionary to store file hashes and their paths
        hash_dict = {}
        
        # Walk through all subdirectories
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Calculate hash of the file
                file_hash = self.calculate_hash(file_path)
                
                if file_hash:
                    if file_hash in hash_dict:
                        # Found a duplicate
                        self.duplicates.append((file_path, hash_dict[file_hash]))
                        print(f"Duplicate found: \n  {file_path}\n  {hash_dict[file_hash]}")
                    else:
                        # Store the hash and file path
                        hash_dict[file_hash] = file_path
        
        if not self.duplicates:
            print("No duplicates found.")
        else:
            print(f"\nFound {len(self.duplicates)} duplicate file(s).")
        
        return self.duplicates