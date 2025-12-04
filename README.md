SHA256 of Hashps1_v2.1.exe — 0bf4dac5cf80667c46caa9b7965d6b750d582251403e873034040603bb275bb1

# Hashps1 v2.1

A professional Windows Forms-based PowerShell GUI application for cryptographic hash operations with batch processing, verification, and HMAC support.

![hashps1](https://img.shields.io/badge/version-2.1-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

## Features

### Core Capabilities
- **9 Hash Algorithms**: SHA256, SHA1, SHA512, MD5, SHA384, RIPEMD160, CRC32, HMACSHA256, HMACSHA512
- **Dual Mode Operation**: String hashing or file hashing with visual drag-and-drop feedback
- **Batch Processing**: Hash multiple files with configurable parallel processing (1-8 threads)
- **Hash Verification**: Compare computed hashes against expected values from tab/space delimited lists
- **HMAC Support**: Dedicated key input fields for HMAC-based algorithms with visual state management
- **Recent Files**: Quick access to last 50 hashed files with single/batch re-hash capability
- **Hash Caching**: Automatic caching of computed hashes - skips re-hashing unchanged files
- **Network Path Support**: UNC paths and mapped drives with connection verification
- **Portable Mode**: Run with `-Portable` flag to disable config/cache persistence
- **Pre-flight Checks**: File locking detection and large file warnings (>10GB)

### Output Options
- **Multiple Formats**: Lowercase (default), UPPERCASE, hex with 0x prefix, Base64 encoded
- **Hash Comparison**: Built-in comparison field with visual color-coded results
- **Auto-copy**: Optional automatic clipboard copy on hash generation
- **Logging**: Persistent logs for main and batch operations

### User Experience
- **Dark Mode**: PlanetArchives theme with bold rich blue accents and cyan-blue output text
- **Visual Feedback**: Green highlight on drag-and-drop, color-coded hash comparison results
- **Progress Tracking**: Smooth progress bars with speed indicators (MB/s)
- **Real-time Updates**: Batch results stream as files complete (250ms polling)
- **Responsive UI**: Background job processing prevents UI freezing on large files
- **Conditional Controls**: Smart button enable/disable based on context (e.g., Recent Files selection)
- **System Tray**: Minimize to tray during long operations
- **Toast Notifications**: Windows 10+ notifications for background operation completion

## Screenshots

### Main Tab - Dark Mode
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
1. Download `Hashps1_v2.1.ps1`
2. Right-click → **Run with PowerShell**
   
   *Or from PowerShell:*
   ```powershell
   powershell -ExecutionPolicy Bypass -File "Hashps1_v2.1.ps1"
   ```
   
   *Portable mode (no config/cache files):*
   ```powershell
   powershell -ExecutionPolicy Bypass -File "Hashps1_v2.1.ps1" -Portable
   ```

No installation or dependencies required - it's a single PowerShell script!

## Usage

### Single File/String Hashing
1. Select **String Mode** or **File Mode**
2. Enter text or browse for file (drag-and-drop supported with green highlight feedback)
3. Choose algorithm (SHA256 is default)
4. For HMAC algorithms, enter key in the dedicated field
5. Click **Generate Hash**
   - Cached hashes are returned instantly if file hasn't changed
   - Large files (>10GB) trigger a confirmation dialog
   - Locked files are detected and reported
6. Optional: Compare with expected hash in the comparison field (color-coded results)

### Batch Processing
1. Navigate to **Batch** tab
2. Add files via **Add Files** button or drag-and-drop
3. Select algorithm and output format
4. Configure parallel threads (1-8) in Settings tab for faster processing
5. Click **Hash All** to process
   - Pre-flight checks detect locked and large files
   - Results stream in real-time as each file completes
   - Cached hashes speed up processing of unchanged files
6. Use **Stop** to cancel, **Export** to save results (TXT/CSV, HashCheck, SFV formats)

### Hash Verification
1. Navigate to **Verify** tab
2. Paste tab or space delimited hash list:
   ```
   a1b2c3d4<TAB>filename.txt...
   ```
3. Select algorithm (must match original)
4. Optionally set base directory for relative paths
5. Click **Verify Hashes** to check all files
6. Results show MATCH, MISMATCH, or MISSING for each file

### Recent Files
- Automatically tracks last 50 hashed files
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

Hash cache is stored in `HashCache.json` with automatic size limiting (1000 entries max).

## Technical Details

### Architecture
- **Single-file application**: ~3500 lines of PowerShell
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

### v2.1 (Current - December 2024)
**Major Features:**
- **Portable Mode**: Run with `-Portable` flag to disable config/cache file creation
- **Hash Caching**: Automatic caching of computed hashes - instant results for unchanged files
- **Network Path Support**: UNC paths and mapped drives with connection verification
- **Visual Drag-Drop Feedback**: Green highlight when dragging files over input fields
- **Pre-flight File Checks**: Detects locked files and warns about large files (>10GB)
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
- Repository: [hashps1](https://github.com/thestickybullgod/hashps1)

## Acknowledgments

- PlanetArchives dark mode theme inspiration
- .NET Framework cryptography providers
- PowerShell community
- Enhanced with assistance from GitHub Copilot (December 2024)

---

**Note**: This is a Windows-only application due to Windows Forms dependency. For cross-platform hash utilities, consider command-line alternatives like `sha256sum` or `certutil`.








