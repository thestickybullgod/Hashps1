# hashps1 - AI Coding Agent Instructions

## Project Overview
**Hashps1** is a Windows Forms-based PowerShell GUI application for cryptographic hash operations. The app provides single-file hashing, batch processing, verification, and comparison features with a modern dark mode theme.

## Architecture & Components

### Core Application Structure
- **Single-file monolith**: All code in `Hashps1_v2.0.ps1` (~2400 lines)
- **Windows Forms GUI**: Uses `System.Windows.Forms` and `System.Drawing` assemblies
- **Async processing**: PowerShell background jobs for file hashing to prevent UI freezing
- **State management**: Script-scoped variables (`$script:`) for runtime state; JSON config for persistence

### Tab Organization
Tabs ordered: **Main → Log Viewer → Batch → Batch Log Viewer → Recent Files → Verify → Settings → About**
- Each processing tab (Main, Batch, Verify) has independent algorithm selector
- Verify tab includes its own progress bar for multi-file verification

### Key Data Flows
1. **Single hash flow**: User input → Algorithm selection → Hash computation → Format output → Display/log
2. **Batch flow**: File list → Background job → Progress polling (250ms timer) → Temp file results → Display/export
3. **Verification flow**: Hash list input → Parse (tab/space delimited) → Compute hashes → Compare → Report (MATCH/MISMATCH/MISSING)

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

### Persistent Configuration (`HashGUI_Config.json`)
Saves: algorithm selection, dark mode state, font size, hash format, auto-copy preference, recent files list (max 50).

## Development Workflows

### Testing UI Changes
1. Edit `Hashps1_v2.0.ps1`
2. Run: `pwsh -File "Hashps1_v2.0.ps1"`
3. No build step required (PowerShell script)

### Adding New Algorithms
1. Add to `$comboAlgo.Items.AddRange()` (line ~345)
2. Add case to algorithm switches: single hash (string/file), batch job ScriptBlock, verify tab
3. Check if HMAC-style (requires key input) and update visibility logic
4. For non-.NET crypto algorithms (like CRC32), implement custom logic with separate code path

### Debugging Background Jobs
- Temp files: `hash_progress.tmp`, `hash_result.tmp`, `hash_error.tmp`, `hash_speed.tmp`, `batch_result.tmp`
- Job state: `Get-Job -Id $script:currentJobId | Select-Object State`
- Check `$script:hashProgress` and `$script:hashDone` in timer tick

### Dark Mode Implementation
`Set-DarkMode` function applies theme recursively to all controls. Colors stored in `$script:Dark*` variables for reuse.
- **Header**: `#2D5596` (rich blue)
- **Accent/Buttons**: `#64A0FF` (bright blue)
- **Output text**: `#96D2FF` (cyan-blue) for visibility

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
- **Single selection**: "Re-Hash" enabled, "Re-Hash Selected (Batch)" disabled
- **Multiple selection**: "Re-Hash" disabled, "Re-Hash Selected (Batch)" enabled

Implemented via `ListBox.Add_SelectedIndexChanged` event handler checking `SelectedItems.Count`.

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

## Key Files Reference
- **Main script**: `Hashps1_v2.0.ps1` (entire application)
- **Config**: `HashGUI_Config.json` (user preferences)
- **Logs**: `Hash_GUI_Log.txt`, `Batch_GUI_Log.txt` (operation history)

## Testing Strategies
- **Single hash**: Test string vs file mode, all 9 algorithms, all 4 output formats
- **Batch**: Mix of small/large files, verify progress updates, test stop button, verify real-time result streaming
- **Verify**: Test tab/space delimited formats, relative/absolute paths, missing files, CRC32 8-char hashes, verify progress bar updates
- **Dark mode**: Toggle and verify all 8 tabs + nested controls render correctly
- **Recent files**: Add >50 files to test limit, test dual-button enable/disable logic with 0/1/multiple selections, remove files from disk to test validation
- **CRC32**: Verify produces lowercase 8-character hex (e.g., `a1b2c3d4`), test with known checksums
- **HMAC fields**: Verify gray/disabled by default, white/enabled when HMAC selected, correct colors after dark mode toggle

## Version & Author
- **Current version**: 2.0
- **Author**: Dustin W. Deen
- **GitHub**: https://github.com/thestickybullgod/hashps1
