import subprocess
import sys
try:
    from importlib.metadata import distribution, distributions
except ImportError:
    # Python < 3.8
    from importlib_metadata import distribution, distributions


class PackageManager:
    def __init__(self):
        self.installed_packages = []
    
    def show_menu(self):
        """Display the package manager menu"""
        while True:
            print("\nPython Package Manager")
            print("======================")
            print("1. List installed packages")
            print("2. Install a package")
            print("3. Uninstall a package")
            print("4. Upgrade a package")
            print("5. Upgrade pip")
            print("6. Back to main menu")
            
            choice = input("\nEnter your choice (1-6): ")
            
            if choice == '1':
                self.list_packages()
            elif choice == '2':
                package = input("Enter package name to install: ")
                self.install_package(package)
            elif choice == '3':
                package = input("Enter package name to uninstall: ")
                self.uninstall_package(package)
            elif choice == '4':
                package = input("Enter package name to upgrade: ")
                self.upgrade_package(package)
            elif choice == '5':
                self.upgrade_pip()
            elif choice == '6':
                break
            else:
                print("Invalid choice. Please try again.")
    
    def list_packages(self):
        """List all installed packages"""
        print("\nInstalled packages:")
        print("-" * 50)
        
        try:
            # Get all installed distributions
            self.installed_packages = list(distributions())
            for package in sorted(self.installed_packages, key=lambda x: x.metadata['Name'].lower()):
                name = package.metadata['Name']
                version = package.metadata['Version']
                print(f"{name} ({version})")
        except Exception as e:
            print(f"Error listing packages: {str(e)}")
        
        print(f"\nTotal packages: {len(self.installed_packages)}")
    
    def install_package(self, package_name):
        """Install a package using pip"""
        try:
            print(f"Installing {package_name}...")
            result = subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
            if result == 0:
                print(f"Successfully installed {package_name}")
            else:
                print(f"Failed to install {package_name}")
        except subprocess.CalledProcessError as e:
            print(f"Error installing {package_name}: {str(e)}")
        except Exception as e:
            print(f"Unexpected error occurred: {str(e)}")
    
    def uninstall_package(self, package_name):
        """Uninstall a package using pip"""
        confirm = input(f"Are you sure you want to uninstall {package_name}? (y/N): ")
        if confirm.lower() == 'y':
            try:
                print(f"Uninstalling {package_name}...")
                result = subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", package_name])
                if result == 0:
                    print(f"Successfully uninstalled {package_name}")
                else:
                    print(f"Failed to uninstall {package_name}")
            except subprocess.CalledProcessError as e:
                print(f"Error uninstalling {package_name}: {str(e)}")
            except Exception as e:
                print(f"Unexpected error occurred: {str(e)}")
        else:
            print("Uninstall cancelled.")
    
    def upgrade_package(self, package_name):
        """Upgrade a package using pip"""
        try:
            print(f"Upgrading {package_name}...")
            result = subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", package_name])
            if result == 0:
                print(f"Successfully upgraded {package_name}")
            else:
                print(f"Failed to upgrade {package_name}")
        except subprocess.CalledProcessError as e:
            print(f"Error upgrading {package_name}: {str(e)}")
        except Exception as e:
            print(f"Unexpected error occurred: {str(e)}")
    
    def upgrade_pip(self):
        """Upgrade pip to the latest version"""
        try:
            print("Upgrading pip...")
            result = subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
            if result == 0:
                print("Successfully upgraded pip")
            else:
                print("Failed to upgrade pip")
        except subprocess.CalledProcessError as e:
            print(f"Error upgrading pip: {str(e)}")
        except Exception as e:
            print(f"Unexpected error occurred: {str(e)}")