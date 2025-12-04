# hashps1 - AI Coding Agent Instructions

## Project Overview
**Hashps1** is a Windows Forms-based PowerShell GUI application for cryptographic hash operations. The app provides single-file hashing, batch processing, verification, and comparison features with a modern dark mode theme. Version 2.1 adds portable mode, hash caching, network path support, parallel processing, visual drag-drop feedback, and pre-flight file checks.

## Architecture & Components

### Core Application Structure
- **Single-file monolith**: All code in `Hashps1_v2.1.ps1` (~3500 lines)
- **Windows Forms GUI**: Uses `System.Windows.Forms` and `System.Drawing` assemblies
- **Async processing**: PowerShell background jobs for file hashing to prevent UI freezing
- **Parallel processing**: Configurable thread count (1-8) for batch operations
- **State management**: Script-scoped variables (`$script:`) for runtime state; JSON config for persistence
- **Portable mode**: `-Portable` flag disables all config/cache file creation
- **Hash caching**: Automatic caching in `HashCache.json` with 1000-entry limit
- **Network support**: UNC path and mapped drive detection with accessibility verification

### Tab Organization
Tabs ordered: **Main → Log Viewer → Batch → Batch Log Viewer → Recent Files → Verify → Settings → About**
- Each processing tab (Main, Batch, Verify) has independent algorithm selector
- Verify tab includes its own progress bar for multi-file verification

### Key Data Flows
1. **Single hash flow**: User input → Pre-flight checks (lock/size/network) → Cache lookup → Algorithm selection → Hash computation → Format output → Cache storage → Display/log
2. **Batch flow**: File list → Pre-flight checks → Parallel job spawning (1-8 threads) → Progress polling (250ms timer) → Temp file results → Display/export
3. **Verification flow**: Hash list input → Parse (tab/space delimited) → Cache lookup → Compute hashes → Compare → Report (MATCH/MISMATCH/MISSING)
4. **Drag-drop flow**: DragEnter → Green highlight → DragDrop → Restore color → Network path check → Populate input

## Critical Functions & Patterns

### Background Job Pattern (File Hashing)
```powershell
Start-Job -ScriptBlock { ... } -ArgumentList $params
# Communicate via temp files: hash_progress.tmp, hash_result.tmp, hash_error.tmp
# Poll with 250ms timer ($uiTimer.Add_Tick)
```
**Why**: Large files block UI thread. Jobs + temp files provide progress updates and keep UI responsive.

### Hash Algorithm Instantiation
```powershell
switch ($algoName) {
    "SHA256" { $algo = [System.Security.Cryptography.SHA256]::Create() }
    "CRC32" { $algo = $null } # Custom implementation
    "HMACSHA256" { $algo = [System.Security.Cryptography.HMACSHA256]::new($keyBytes) }
    # ... 9 algorithms total
}
```
**Supported**: SHA256, SHA1, SHA512, MD5, SHA384, RIPEMD160, CRC32, HMACSHA256, HMACSHA512

**CRC32 Note**: CRC32 uses custom implementation (polynomial 0xEDB88320) with lookup table for performance. Handled separately from .NET crypto algorithms.

**HMAC Key Fields**: Each tab (Main, Batch, Verify) has an HMAC key input field:
- **Visible always**, but **disabled (grayed out)** when non-HMAC algorithms selected
- **Enabled with white background** when HMACSHA256 or HMACSHA512 selected
- **Disabled colors**: Background `RGB(80,80,80)`, Foreground `RGB(120,120,120)`
- **Enabled colors**: Background `White`, Foreground `Black`
- Color state reapplied on form load and dark mode toggle to prevent theme override

### Hash Output Formatting (`Format-HashOutput`)
- **lowercase** (default): `a1b2c3...`
- **uppercase**: `A1B2C3...`
- **hex**: `0xa1b2c3...`
- **base64**: Convert hex bytes to Base64 string

### Hash Caching System (`Get-CachedHash`, `Set-CachedHash`)
Cache key format: `{filePath}|{algorithm}|{format}`
- Validates file hasn't changed using LastWriteTime and file size
- Returns cached hash instantly if match found
- Stores up to 1000 most recent entries (oldest purged automatically)
- Persists to `HashCache.json` (disabled in portable mode)

### Network Path Support (`Test-NetworkPath`, `Test-NetworkPathAccessible`)
- Detects UNC paths (`\\server\share`) and mapped drives
- Verifies connectivity before hashing
- Visual feedback in footer (green=connected, red=inaccessible)

### Pre-flight File Checks
- **Lock detection** (`Test-FileLocked`): Warns if file is open by another process
- **Large file warning** (`Test-LargeFile`): Confirmation dialog for files >10GB
- Runs before single and batch hash operations

### Persistent Configuration (`HashGUI_Config.json`)
Saves: algorithm selection, dark mode state, font size, hash format, auto-copy preference, recent files list (max 50), parallel thread count, system tray preferences, toast notification settings.
**Disabled** when using `-Portable` mode flag.

## Development Workflows

### Testing UI Changes
1. Edit `Hashps1_v2.1.ps1`
2. Run: `pwsh -File "Hashps1_v2.1.ps1"` (normal mode with config/cache)
3. Run: `pwsh -File "Hashps1_v2.1.ps1" -Portable` (portable mode - no persistence)
4. No build step required (PowerShell script)

### Adding New Algorithms
1. Add to `$comboAlgo.Items.AddRange()` (line ~345)
2. Add case to algorithm switches: single hash (string/file), batch job ScriptBlock, verify tab
3. Check if HMAC-style (requires key input) and update visibility logic
4. For non-.NET crypto algorithms (like CRC32), implement custom logic with separate code path

### Debugging Background Jobs
- Temp files: `hash_progress.tmp`, `hash_result.tmp`, `hash_error.tmp`, `hash_speed.tmp`, `batch_result.tmp`
- Job state: `Get-Job -Id $script:currentJobId | Select-Object State`
- Check `$script:hashProgress` and `$script:hashDone` in timer tick

### Dark Mode Implementation - PlanetArchives Theme
`Set-DarkMode` function applies theme recursively to all controls. Colors stored in `$script:Dark*` variables for reuse.
- **Background**: `RGB(10,15,35)` (deep navy)
- **Tab Color**: `RGB(18,24,45)` (deep tab background)
- **Header**: `RGB(45,85,150)` (rich bold blue header acting as titlebar)
- **Panel**: `RGB(25,30,50)` (deep panel background)
- **Accent/Buttons**: `RGB(100,160,255)` (bright blue buttons)
- **Foreground**: `RGB(240,240,245)` (nearly white text)
- **Output text**: `RGB(150,210,255)` (bright cyan-blue) for visibility

## Project-Specific Conventions

### Variable Scoping
- `$script:` for shared state across event handlers (e.g., `$script:generatedHash`, `$script:currentJobId`)
- Local function params passed explicitly (no global pollution)

### Event Handler Registration
```powershell
$button.Add_Click({ ... })
$control.Add_CheckedChanged({ ... })
```
Standard .NET event pattern. Avoid inline long logic; call helper functions.

### Recent Files Dual-Button Pattern
Recent Files tab uses conditional button enabling based on selection count:
- **No selection**: Both buttons disabled
- **Single selection**: "Re-Hash Selected" enabled (quick hash in Main tab), "Re-Hash Selected (Batch)" disabled
- **Multiple selection**: "Re-Hash Selected" disabled, "Re-Hash Selected (Batch)" enabled (batch processing)

Implemented via `ListBox.Add_SelectedIndexChanged` event handler checking `SelectedItems.Count`. Cached hashes provide instant results for unchanged files.

### Visual Drag-Drop Feedback
Input fields provide visual feedback during drag operations:
- **DragEnter**: Background changes to `LightGreen`
- **DragLeave/DragDrop**: Background restores to theme color (white for light mode, `$script:DarkPanelColor` for dark mode)
- **State tracking**: `$script:dragDropBorderActive` flag prevents color conflicts
- Applied to Main tab file input and Batch tab file list

### Error Handling Philosophy
- **UI operations**: Try-catch with MessageBox display
- **Background jobs**: Write errors to `hash_error.tmp`, UI polls and displays
- **Config I/O**: Silent fail with try-catch (don't interrupt UX)

### Progress Smoothing (Line ~1432)
Progress bar uses gradual step animation to reduce jitter:
```powershell
$step = [int]([math]::Max(1, ($targetWidth - $currentWidth) / 5))
$panelProgressFill.Width = [math]::Min($targetWidth, $currentWidth + $step)
```

## Integration Points

### External Dependencies
- **None** - Pure PowerShell + .NET Framework 4.8
- Requires Windows with PowerShell 5.1+ (uses `System.Windows.Forms`)

### File System Interactions
- **Config**: `HashGUI_Config.json` (read on startup, write on close/settings change)
- **Logs**: `Hash_GUI_Log.txt`, `Batch_GUI_Log.txt` (append-only, user-cleared)
- **Temp files**: Created in `$PSScriptRoot`, auto-cleaned after job completion

### Clipboard Integration
Auto-copy feature uses `[System.Windows.Forms.Clipboard]::SetText()` for seamless hash copying.

## Common Pitfalls

1. **Temp file race conditions**: Always use try-catch when reading temp files in timer tick (job may still be writing)
2. **Job cleanup**: Must call `Remove-Job` after completion or stop, else memory leak
3. **Dark mode inconsistency**: When adding controls, manually apply colors if created after initial theme setup. **CRITICAL**: HMAC key fields require color reapplication after `Set-DarkMode` runs (in form load and dark mode toggle events) to prevent override
4. **Recent files validation**: Always check `Test-Path` before re-hashing from recent list
5. **Duplicate event handlers**: Ensure only one `Add_SelectedIndexChanged` handler per control to prevent double-firing
6. **Portable mode checks**: Always check `$script:PortableMode` before config/cache I/O operations
7. **Drag-drop color restoration**: Must check dark mode state to restore correct background color after drag operations
8. **Cache invalidation**: Hash cache keys include algorithm and format - changing either invalidates cache
9. **Network path timeouts**: UNC path accessibility checks may hang - consider timeout mechanisms for unresponsive servers
10. **Parallel job throttling**: More threads ≠ always faster. I/O bottlenecks limit scaling beyond 4-6 threads for most storage

## Key Files Reference
- **Main script**: `Hashps1_v2.1.ps1` (entire application)
- **Config**: `HashGUI_Config.json` (user preferences - disabled in portable mode)
- **Cache**: `HashCache.json` (computed hash cache - disabled in portable mode)
- **Logs**: `Hash_GUI_Log.txt`, `Batch_GUI_Log.txt` (operation history)
- **Temp files**: `hash_progress.tmp`, `hash_result.tmp`, `hash_error.tmp`, `hash_speed.tmp`, `batch_results.tmp`, `batch_progress.tmp`

## Testing Strategies
- **Single hash**: Test string vs file mode, all 9 algorithms, all 4 output formats, verify cache hits on repeat hashing
- **Batch**: Mix of small/large files, test parallel threads (1-8), verify progress updates, test stop button, verify real-time result streaming
- **Verify**: Test tab/space delimited formats, relative/absolute paths, missing files, CRC32 8-char hashes, verify progress bar updates
- **Dark mode**: Toggle and verify all 8 tabs + nested controls render correctly, check drag-drop color restoration
- **Recent files**: Add >50 files to test limit, test dual-button enable/disable logic with 0/1/multiple selections, remove files from disk to test validation, verify cache provides instant results
- **CRC32**: Verify produces lowercase 8-character hex (e.g., `a1b2c3d4`), test with known checksums
- **HMAC fields**: Verify gray/disabled by default, white/enabled when HMAC selected, correct colors after dark mode toggle
- **Portable mode**: Run with `-Portable` flag, verify no config/cache files created, verify settings don't persist across runs
- **Drag-drop feedback**: Drag files over input fields, verify green highlight appears/disappears correctly in both themes
- **Pre-flight checks**: Test with locked files (open in another app), test >10GB files for confirmation dialog
- **Network paths**: Test UNC paths (`\\server\share\file.txt`), test mapped drives, verify connection status feedback
- **Cache behavior**: Hash same file twice, verify instant second result; modify file, verify cache invalidates; test 1000-entry limit
- **Parallel scaling**: Batch hash 20+ files, test thread counts 1/4/8, measure completion time differences
- **Export formats**: Test TXT/CSV export, HashCheck format (.sha256 files), SFV format for CRC32

## Version & Author
- **Current version**: 2.1 (December 2024)
- **Author**: Dustin W. Deen
- **GitHub**: https://github.com/thestickybullgod/hashps1
- **Enhanced with**: GitHub Copilot assistance

## New in v2.1
- Portable mode with `-Portable` command line flag
- Hash caching system with automatic invalidation
- Network path support (UNC and mapped drives)
- Visual drag-drop feedback with green highlights
- Pre-flight file checks (locking and size warnings)
- Configurable parallel batch processing (1-8 threads)
- PlanetArchives dark mode with bold rich colors
- System tray minimization with toast notifications
- Export to multiple formats (TXT/CSV, HashCheck, SFV)
- Enhanced Recent Files with smart dual-button system
- Comprehensive About tab documentation
