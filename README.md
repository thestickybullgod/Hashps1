SHA256 of Hashps1_v2.1.exe — 0bf4dac5cf80667c46caa9b7965d6b750d582251403e873034040603bb275bb1

# hashps1 v2.1

A professional Windows Forms-based PowerShell GUI application for cryptographic hash operations with batch processing, verification, and HMAC support.

![hashps1](https://img.shields.io/badge/version-2.0-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

## Features

### Core Capabilities
- **9 Hash Algorithms**: SHA256, SHA1, SHA512, MD5, SHA384, RIPEMD160, CRC32, HMACSHA256, HMACSHA512
- **Dual Mode Operation**: String hashing or file hashing with drag-and-drop support
- **Batch Processing**: Hash multiple files with real-time progress tracking and result streaming
- **Hash Verification**: Compare computed hashes against expected values from tab/space delimited lists
- **HMAC Support**: Dedicated key input fields for HMAC-based algorithms with visual state management
- **Recent Files**: Quick access to last 50 hashed files with single/batch re-hash capability

### Output Options
- **Multiple Formats**: Lowercase (default), UPPERCASE, hex with 0x prefix, Base64 encoded
- **Hash Comparison**: Built-in comparison field with visual color-coded results
- **Auto-copy**: Optional automatic clipboard copy on hash generation
- **Logging**: Persistent logs for main and batch operations

### User Experience
- **Dark Mode**: PlanetArchives theme with rich blue accents and cyan-blue output text
- **Progress Tracking**: Smooth progress bars with speed indicators (MB/s)
- **Real-time Updates**: Batch results stream as files complete (250ms polling)
- **Responsive UI**: Background job processing prevents UI freezing on large files
- **Conditional Controls**: Smart button enable/disable based on context (e.g., Recent Files selection)

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
1. Download `Hashps1_v2.0.ps1`
2. Right-click → **Run with PowerShell**
   
   *Or from PowerShell:*
   ```powershell
   powershell -ExecutionPolicy Bypass -File "Hashps1_v2.0.ps1"
   ```

No installation or dependencies required - it's a single PowerShell script!

## Usage

### Single File/String Hashing
1. Select **String Mode** or **File Mode**
2. Enter text or browse for file (drag-and-drop supported)
3. Choose algorithm (SHA256 is default)
4. For HMAC algorithms, enter key in the dedicated field
5. Click **Generate Hash**
6. Optional: Compare with expected hash in the comparison field

### Batch Processing
1. Navigate to **Batch** tab
2. Add files via **Add Files** button or drag-and-drop
3. Select algorithm and output format
4. Click **Hash All** to process
5. Results stream in real-time as each file completes
6. Use **Stop** to cancel, **Export** to save results

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
- **Single selection**: Click "Re-Hash" to re-compute
- **Multiple selection**: Click "Re-Hash Selected (Batch)" for batch processing

## Configuration

Settings are automatically saved to `HashGUI_Config.json`:
- Algorithm preferences per tab
- Dark mode state
- Font size
- Hash output format
- Auto-copy preference
- Recent files list

## Technical Details

### Architecture
- **Single-file application**: ~3400 lines of PowerShell
- **Windows Forms GUI**: Native .NET Framework controls
- **Background jobs**: Async processing via `Start-Job` with temp file communication
- **Progress polling**: 250ms timer for smooth UI updates
- **CRC32 optimization**: Custom C# implementation with lookup table (10-20x faster)

### Algorithm Support
Standard .NET crypto providers plus:
- **CRC32**: Polynomial 0xEDB88320, outputs 8-character lowercase hex
- **HMAC**: Key-based authentication with HMACSHA256/HMACSHA512

### Performance
- **Large files**: Background jobs prevent UI freezing
- **Progress smoothing**: Gradual animation reduces visual jitter
- **Batch throttling**: 250ms update intervals balance responsiveness and I/O efficiency

## Version History

### v2.1 (Current)
- Added HMAC algorithm support (HMACSHA256, HMACSHA512)
- Independent algorithm selectors for Main, Batch, and Verify tabs
- HMAC key fields with visual state management (white when enabled, gray when disabled)
- Dual-button system in Recent Files (single vs batch re-hash)
- Enhanced Verify tab with progress bar
- Real-time batch result streaming
- Increased recent files limit to 50
- Comprehensive About tab documentation
- Tab reordering for better workflow
- Auto-refresh for batch log viewer
- Removed auto-populate from clipboard feature
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

- PlanetArchives dark mode theme
- .NET Framework cryptography providers
- PowerShell community

---

**Note**: This is a Windows-only application due to Windows Forms dependency. For cross-platform hash utilities, consider command-line alternatives like `sha256sum` or `certutil`.







