SHA256 of CrunchHash_BETA.exe — 50310af75616d0375beeb3021d7a84ecf5993fc66d9ee31652636b7f2a97781c

SHA256 of CrunchHash_BETA.ps1 — 8d376dbfec655500b0248498a3b04e0319a393211069ef155d8f55ef28a8e63e

# CrunchHash BETA

A professional Windows Forms-based PowerShell GUI application for cryptographic hash operations with batch processing, verification, and HMAC support.

![crunchhash](https://img.shields.io/badge/version-BETA-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

## Features

### Core Capabilities
- **9 Hash Algorithms**: SHA256, SHA1, SHA512, MD5, SHA384, RIPEMD160, CRC32, HMACSHA256, HMACSHA512
- **Dual Mode Operation**: String hashing or file hashing with visual drag-and-drop feedback
- **Batch Processing**: Hash multiple files with configurable parallel processing (1-8 threads) and real-time result streaming
- **Hash Verification**: Compare computed hashes against expected values with real-time result streaming and batch log import
- **HMAC Support**: Dedicated key input fields for HMAC-based algorithms with visual state management
- **Recent Files**: Quick access to last 50 hashed files with horizontal scrolling and single/batch re-hash capability
- **Hash Caching**: Automatic caching of computed hashes - skips re-hashing unchanged files with [CACHED] markers
- **Network Path Support**: UNC paths and mapped drives with connection verification and timeout protection
- **Network Path Timeouts**: Configurable timeout (1-30s, default 5s) prevents hanging on unresponsive servers
- **Portable Mode**: Run with `-Portable` flag to disable config/cache persistence
- **Pre-flight Checks**: File locking detection, large file warnings (>10GB), and network path accessibility
- **Duplicate Finder**: Search any specified directory for duplicate files based on determined checksums. Includes recursive searching, hash algorithm selection and "Filter by extensions".

### Output Options
- **Multiple Formats**: Lowercase (default), UPPERCASE, hex with 0x prefix, Base64 encoded
- **Hash Comparison**: Built-in comparison field with visual color-coded results
- **Auto-copy**: Optional automatic clipboard copy on hash generation
- **Logging**: Persistent logs for main and batch operations

### User Experience
- **Dark Mode**: PlanetArchives theme with bold rich blue accents and cyan-blue output text
- **Visual Feedback**: Green highlight on drag-and-drop, color-coded hash comparison results
- **Progress Tracking**: Smooth progress bars with speed indicators (MB/s)
- **Real-time Updates**: Batch and verify results stream as files complete (250ms polling)
- **Responsive UI**: Background job processing prevents UI freezing on large files
- **Conditional Controls**: Smart button enable/disable based on context (e.g., Recent Files selection)
- **System Tray**: Minimize to tray during long operations
- **Toast Notifications**: Windows 10+ notifications for background operation completion
- **Horizontal Scrolling**: File lists support horizontal scrolling with dynamic extent calculation (font-size aware)

### Main Tab
Single file/string hashing with algorithm selection and HMAC key support.

### Batch Processing
Multi-file hashing with real-time progress and result streaming.

### Verification
Bulk hash verification from tab/space delimited format with MATCH/MISMATCH reporting.

## Installation

### Requirements
- Windows OS
- PowerShell 5.1 or higher
- .NET Framework 4.8 (included in Windows 10/11)

### Quick Start
1. Download `CrunchHash_BETA.ps1`
2. Right-click → **Run with PowerShell**
   
   *Or from PowerShell:*
   ```powershell
   powershell -ExecutionPolicy Bypass -File "CrunchHash_BETA.ps1"
   ```
   
   *Portable mode (no config/cache files):*
   ```powershell
   powershell -ExecutionPolicy Bypass -File "CrunchHash_BETA.ps1" -Portable
   ```

No installation or dependencies required - it's a single PowerShell script!

## Usage

### Single File/String Hashing
1. Select **String Mode** or **File Mode**
2. Enter text or browse for file (drag-and-drop supported with green highlight feedback)
3. Choose algorithm (SHA256 is default)
4. For HMAC algorithms, enter key in the dedicated field
6. Click **Generate Hash**
   - Clicking **Generate Hash** after clicking **Log to file** creates "Hash_GUI_Log.txt" in the directory of CrunchHash_BETA.exe/CrunchHash_BETA.ps1
   - Cached hashes are returned instantly if file hasn't changed
   - Large files (>10GB) trigger a confirmation dialog
   - Locked files are detected and reported
8. Optional: Compare with expected hash in the comparison field (color-coded results)

### Batch Processing
1. Navigate to **Batch** tab
2. Add files via **Add Files** button or drag-and-drop
3. Select algorithm and output format
4. Configure parallel threads (1-8) in Settings tab for faster processing
5. Click **Hash All** to process
   - Clicking **Hash All** after clicking **Log to file** creates "Batch_GUI_Log.txt" in the directory of CrunchHash_BETA.exe/CrunchHash_BETA.ps1
   - Pre-flight checks detect locked and large files
   - Results stream in real-time as each file completes
   - Cached hashes speed up processing of unchanged files (marked with [CACHED])
7. Use **Stop** to cancel
8. Export options:
   - **Export TXT/CSV**: Structured results
   - **HashCheck**: Individual .sha256/.md5/etc files
   - **SFV**: CRC32 format for verification
   - **Verify Log**: Compatible format for direct import to Verify tab

### Hash Verification
1. Navigate to **Verify** tab
2. Option A: Paste tab or space delimited hash list:
   ```
   a1b2c3d4<TAB>filename.txt...
   ```
   Option B: Click **Import Batch Log** to load exported batch results
3. Select algorithm (must match original)
4. Optionally set base directory for relative paths
5. Click **Verify All** to check all files
   - Results stream in real-time as each file is verified
6. Results show MATCH, MISMATCH, or MISSING for each file

### Recent Files
- Automatically tracks last 50 hashed files
- Horizontal scrolling with dynamic extent calculation (adjusts for font size 8-24pt)
- **Single selection**: Click "Re-Hash Selected" to quickly re-compute in Main tab
- **Multiple selection**: Click "Re-Hash Selected (Batch)" for batch processing
- Smart button enable/disable based on selection count
- Cached hashes provide instant results for unchanged files

## Configuration

Settings are automatically saved to `HashGUI_Config.json` (unless using `-Portable` mode):
- Algorithm preferences per tab
- Dark mode state
- Font size
- Hash output format
- Auto-copy preference
- Recent files list
- Parallel thread count
- System tray and toast notification preferences
- **Clear Hash Cache** button

Hash cache is stored in `HashCache.json` with automatic size limiting (1000 entries max).

## Technical Details

### Architecture
- **Single-file application**: ~5000 lines of PowerShell
- **Windows Forms GUI**: Native .NET Framework controls
- **Background jobs**: Async processing via `Start-Job` with temp file communication
- **Parallel processing**: Configurable thread count (1-8) for batch operations
- **Progress polling**: 250ms timer for smooth UI updates
- **CRC32 optimization**: Custom C# implementation with lookup table (10-20x faster)
- **Hash caching**: File path + modified time + algorithm key with JSON persistence
- **Network detection**: UNC path and mapped drive identification with accessibility checks

### Algorithm Support
Standard .NET crypto providers plus:
- **CRC32**: Polynomial 0xEDB88320, outputs 8-character lowercase hex
- **HMAC**: Key-based authentication with HMACSHA256/HMACSHA512

### Performance
- **Large files**: Background jobs prevent UI freezing
- **Progress smoothing**: Gradual animation reduces visual jitter
- **Batch throttling**: 250ms update intervals balance responsiveness and I/O efficiency

## Version History

### v2.8 (December 2025)
**Mutual Exclusion & UI Refinements:**
- **Hash Operation Mutual Exclusion**: Prevent simultaneous hash operations across tabs to avoid conflicts
  - Duplicate Finder, Batch Hash, and Verify operations now disable each other while running
  - Main tab Generate Hash button also participates in mutual exclusion
- **Recent Files Button State Fix**: Re-Hash buttons now correctly show black text when disabled
  - Fixed white text persisting after Clear List when files were selected
  - Button colors now properly reflect enabled/disabled state
- **Code Cleanup**: Corrected internal button variable references for consistency

### v2.5 (Current - December 2025)

✅ Now supports high contrast mode! Use by enabling high contrast mode in Windows settings.

✅ Smooth Progress Tracking - Dual progress bars (File % and Batch %) in Batch tab

✅ Speed Display - Real-time MB/s tracking

✅ Incremental Caching - Cache writes as files complete, not just at end

✅ Verify Tab Enhancements:
Green progress bar with smooth animation (18px tall!)
Stop button that actually works
Real-time incremental results display
Streaming hash computation for large files
Responsive form closing with user confirmation

✅ Import Optimization - StreamReader for fast batch log imports

✅ Performance Fixes - No more crashes or freezing!

### v2.4 (Current - December 2025)
**Major Features:**
- **Portable Mode**: Run with `-Portable` flag to disable config/cache file creation
- **Hash Caching**: Automatic caching of computed hashes - instant results for unchanged files
- **Network Path Support**: UNC paths and mapped drives with connection verification
- **Network Path Timeouts**: Configurable timeout (1-30s, default 5s) prevents hanging on unresponsive servers
- **Visual Drag-Drop Feedback**: Green highlight when dragging files over input fields
- **Pre-flight File Checks**: Detects locked files, warns about large files (>10GB), and verifies network paths
- **Parallel Batch Processing**: Configurable thread count (1-8) for faster multi-file hashing
- **PlanetArchives Dark Mode**: Bold theme with rich blue accents and cyan-blue output

**HMAC & Algorithm Enhancements:**
- HMAC algorithm support (HMACSHA256, HMACSHA512)
- Independent algorithm selectors for Main, Batch, and Verify tabs
- HMAC key fields with visual state management

**UI/UX Improvements:**
- Dual-button system in Recent Files (single vs batch re-hash with smart enable/disable)
- Enhanced Verify tab with progress bar and file-by-file tracking
- Real-time batch result streaming
- System tray minimization with toast notifications
- Color-coded hash comparison (green=MATCH, red=MISMATCH)
- Increased recent files limit to 50
- Comprehensive About tab with full feature documentation

**Export & Logging:**
- Multiple export formats: TXT/CSV, HashCheck (.sha256/.md5/etc), SFV
- Separate logs for single and batch operations
- Auto-refresh for log viewers

### v2.0
- 9 hash algorithms
- Batch processing
- Dark mode theme
- Basic verification


## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Development Notes
- See `copilot-instructions.md` for detailed architecture and development guidelines
- All code in single file for portability
- No external dependencies beyond PowerShell/.NET Framework

## License

This project is open source. Feel free to use, modify, and distribute.

## Author

**Dustin W. Deen**
- GitHub: [@thestickybullgod](https://github.com/thestickybullgod)
- Repository: [CrunchHash](https://github.com/thestickybullgod/crunchhash)

## Acknowledgments

- PlanetArchives dark mode theme inspiration
- .NET Framework cryptography providers
- PowerShell community
- Enhanced with assistance from GitHub Copilot (December 2025)

---

**Note**: This is a Windows-only application due to Windows Forms dependency. For cross-platform hash utilities, consider command-line alternatives like `sha256sum` or `certutil`.





























































