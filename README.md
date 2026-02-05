# Advanced System Utility App

A comprehensive Windows utility application built with Python and Tkinter that provides multiple system utility functions in a single interface with an enhanced UI.

## Features

### 1. Duplicate File Finder
- Scans directories to find duplicate files using MD5 hashing
- Shows file paths of duplicate files found
- Helps free up disk space by identifying redundant files
- Clear results button for convenience

### 2. File/Folder Search
- Search for files and folders by name
- Search by file extension
- Specify directory to search in
- Displays all matching file/folder locations
- Clear results button for convenience

### 3. Privacy Cleaner
- Clean temporary files older than 1 day
- Clear recent documents history
- Remove browser cache files
- Clean all privacy data at once
- Clear clipboard functionality
- Organized in labeled frames for better UX

### 4. Package Manager
- View all installed Python packages
- Install new packages via pip
- Uninstall existing packages
- Upgrade packages to latest versions
- Upgrade pip itself
- Export package list to file
- Refresh packages list

### 5. System Cleaner
- Perform full system cleanup
- Remove old temporary files
- Clean log files older than 30 days
- Display disk usage information
- Empty recycle bin (Windows)
- Drive optimization (coming soon)

### 6. Additional Features
- System information display (OS, CPU, Memory)
- Disk usage analysis
- Find large files (>100MB)
- View startup programs (Windows)
- Check running processes
- Process monitoring

### 7. Terminal Emulator
- Full CMD and PowerShell access
- Switch between shells easily
- Command history display
- Real-time output
- Keyboard shortcuts (Enter to execute)

### 8. Professional File Information
- Detailed file information (size, modification date)
- Enhanced duplicate file detection with detailed metadata
- Professional file search results with comprehensive details

### 9. Dark Theme Support
- Toggle between light and dark themes
- Professional dark mode with optimized contrast
- Theme menu in the application menu bar
- Automatic color adjustment for all UI elements

### 10. Advanced Terminal Features
- Full PowerShell and CMD integration with proper directory navigation
- Command history with up/down arrow navigation
- Persistent command history
- Terminal reset functionality
- Clear history option
- Professional terminal-like interface with consistent styling
- Real-time command execution feedback

### 11. Real-Time Monitoring
- Live CPU, RAM, and disk usage monitoring
- Visual progress bars for system metrics
- Start/stop monitoring controls
- Real-time system performance tracking

### 12. Security Tools
- Password generator with customizable length
- Hash calculator (MD5, SHA256, SHA1)
- Secure password generation algorithms

### 13. Network Tools
- Ping tool for connectivity testing
- Port scanner for network security
- Host availability checking
- Network diagnostics

### 14. Developer Tools
- Base64 encoder/decoder
- JSON formatter and validator
- Code snippet utilities
- Development utilities

### 15. System Tools
- System information dashboard
- Hardware information viewer
- Network interface details
- Process manager with kill functionality
- Resource monitoring

### 16. User Profile & Personalization
- User profile management
- Display name and username customization
- Profile bio/description
- Avatar selection
- User statistics tracking
- Profile save/load functionality

### 17. Terminal Customization
- Font family selection
- Font size adjustment
- Text and background color customization
- Terminal settings application
- Professional terminal appearance

### 18. Color Tools
- Color picker with visual selector
- Multiple color code formats (HEX, RGB, HSL, etc.)
- Color palette display
- Color code conversion utilities
- Advanced color mixing tools
- Palette generator (complementary, analogous, triadic, etc.)
- Color utilities (contrast checker, lighten/darken, invert)

### 19. Advanced Terminal Customization
- Font family selection (50+ fonts supported)
- Font size and weight customization
- Font style options (normal, italic, bold)
- Letter spacing and line height controls
- Comprehensive color settings (text, background, cursor, selection)
- Status color customization (error, success, warning, info)
- Background options (solid, gradient, image)
- Effects and animations (typing, cursor blink, neon, rainbow text)
- Layout settings (dimensions, padding, margins, scrollbar)
- Position and mode controls (fullscreen, compact)

### 20. Enhanced User Profile & Personalization
- Social media links (GitHub, LinkedIn, Twitter)
- Login/logout system
- User statistics tracking (commands run, time spent)
- Last login timestamp
- Achievement badge counter
- Profile card export functionality

## Requirements

- Python 3.6 or higher
- Required packages listed in requirements.txt

## Installation

1. Clone or download this repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python main.py`

## Usage

Simply run `python main.py` to launch the GUI application. All functionality is organized into separate tabs for easy access.

## Enhanced UI Features

- Modern color scheme with blue accents
- Custom styled buttons with hover effects
- Organized sections with labeled frames
- Improved text areas with better contrast
- Responsive layout with proper padding
- Consistent styling across all tabs
- Centralized Settings menu with sub-options
- Professional menu organization
- Bug-fixed code for stable performance

## Modules

- `gui_app.py`: Main GUI application with all functionality
- `duplicate_finder.py`: Logic for finding duplicate files
- `file_searcher.py`: Logic for searching files/folders
- `privacy_cleaner.py`: Privacy cleaning utilities
- `package_manager.py`: Python package management
- `system_cleaner.py`: System cleanup utilities
- `main.py`: Entry point for the application

## License

This project is created for educational purposes.