
# Parse command-line arguments (must be first)
param(
    [switch]$Portable,
    [switch]$Verbose
)

### Ensure Add-Type for System.Windows.Forms is called before creating ToolTip
$null = [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
$null = [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

$tooltip = New-Object System.Windows.Forms.ToolTip

# Portable mode flag - prevents config/cache file creation
$script:PortableMode = $Portable
$script:VerboseMode = $Verbose

# Function to write verbose output
function Write-VerboseOutput {
    param([string]$Message)
    if ($script:VerboseMode) {
        Write-Host "[CrunchHash] $Message" -ForegroundColor Cyan
    }
}

# Add compiled CRC32 class for performance
try {
    $typeExists = $false
    try {
        $null = [FastCRC32]
        $typeExists = $true
    } catch {
        $typeExists = $false
    }

    if (-not $typeExists) {
        Add-Type -TypeDefinition @"
using System;
using System.IO;

public class FastCRC32
{
    private static uint[] crcTable;

    static FastCRC32()
    {
        crcTable = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int j = 0; j < 8; j++)
            {
                if ((c & 1) != 0)
                    c = (c >> 1) ^ 0xEDB88320;
                else
                    c >>= 1;
            }
            crcTable[i] = c;
        }
    }

    public static uint ComputeHash(byte[] data)
    {
        uint crc = 0xFFFFFFFF;
        for (int i = 0; i < data.Length; i++)
        {
            byte index = (byte)(crc ^ data[i]);
            crc = (crc >> 8) ^ crcTable[index];
        }
        return crc ^ 0xFFFFFFFF;
    }

    public static uint ComputeHashStream(Stream stream, Action<int, double> progressCallback = null)
    {
        uint crc = 0xFFFFFFFF;
        byte[] buffer = new byte[65536];
        long total = stream.Length;
        long read = 0;
        int count;
        DateTime startTime = DateTime.Now;

        while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i < count; i++)
            {
                byte index = (byte)(crc ^ buffer[i]);
                crc = (crc >> 8) ^ crcTable[index];
            }
            read += count;

            if (progressCallback != null)
            {
                int percent = total > 0 ? (int)((100 * read) / total) : 100;
                double elapsed = (DateTime.Now - startTime).TotalSeconds;
                double speedMBs = elapsed > 0 ? (read / 1048576.0) / elapsed : 0;
                progressCallback(percent, speedMBs);
            }
        }
        return crc ^ 0xFFFFFFFF;
    }
}
"@ -ErrorAction Stop
    }
} catch {
    # Type already loaded or error loading, continue anyway
}

Write-VerboseOutput "Initializing CrunchHash v3.0..."
Write-VerboseOutput "Verbose Mode: $($script:VerboseMode)"
Write-VerboseOutput "Portable Mode: $($script:PortableMode)"

$exePath = $PSScriptRoot
Write-VerboseOutput "Working Directory: $exePath"

$logPath = [System.IO.Path]::Combine($exePath, "Hash_GUI_Log.txt")
$batchLogPath = [System.IO.Path]::Combine($exePath, "Batch_GUI_Log.txt")
$hashProgressFile = [System.IO.Path]::Combine($exePath, "hash_progress.tmp")
$hashResultFile   = [System.IO.Path]::Combine($exePath, "hash_result.tmp")
$hashErrorFile    = [System.IO.Path]::Combine($exePath, "hash_error.tmp")
$hashSpeedFile    = [System.IO.Path]::Combine($exePath, "hash_speed.tmp")
$configPath = [System.IO.Path]::Combine($exePath, "HashGUI_Config.json")
$hashCachePath = [System.IO.Path]::Combine($exePath, "HashCache.json")

# Script-scoped state for hash results
$script:generatedHash = $null
$script:fontOutput = New-Object System.Drawing.Font("Consolas", 12, [System.Drawing.FontStyle]::Bold)
$script:fontVerdict = New-Object System.Drawing.Font("Consolas", 14, [System.Drawing.FontStyle]::Bold)
$script:currentJobId = $null
$script:lastProgress = 0
$script:batchJobId = $null
$script:batchTempFile = [System.IO.Path]::Combine($exePath, "batch_results.tmp")
$script:batchProgressFile = [System.IO.Path]::Combine($exePath, "batch_progress.tmp")
$script:batchFileProgressFile = [System.IO.Path]::Combine($exePath, "batch_file_progress.tmp")
$script:batchCacheFile = [System.IO.Path]::Combine($exePath, "batch_cache.tmp")
$script:batchTotalFiles = 0
$script:batchCurrentFile = 0
$script:batchFileProgress = 0
$script:batchShouldPause = $false
$script:batchPauseFile = [System.IO.Path]::Combine($exePath, "batch_pause.tmp")
$script:batchLoadingJobId = $null
$script:batchLoadingTempFile = [System.IO.Path]::Combine($exePath, "batch_loading.tmp")
$script:batchLoadingShouldCancel = $false
$script:batchLoadingAddedFiles = $null
$script:verifyJobId = $null
$script:verifyTempFile = [System.IO.Path]::Combine($exePath, "verify_results.tmp")
$script:verifyProgressFile = [System.IO.Path]::Combine($exePath, "verify_progress.tmp")
$script:verifyShouldPause = $false
$script:verifyPauseFile = [System.IO.Path]::Combine($exePath, "verify_pause.tmp")
$script:verifyCurrentWidth = 0
$script:verifyTargetWidth = 0
$script:verifyShouldStop = $false
$script:verifyRunning = $false
$script:verifyLastDisplayedLength = 0
$script:verifyTotalFiles = 0
$script:verifyMatchCount = 0
$script:verifyMismatchCount = 0
$script:verifyMissingCount = 0
$script:recentFiles = @()
$script:hashCache = @{}
$script:notifyIcon = $null
$script:parallelThreadCount = 4
$script:dragDropBorderActive = $false
$script:networkPathTimeout = 5  # Default timeout in seconds for network path checks
$script:dupJobId = $null
$script:dupRunspace = $null
$script:dupHandle = $null
$script:dupShouldStop = $false
$script:dupShouldPause = $false
$script:dupStopTime = $null
$script:dupTempFile = [System.IO.Path]::Combine($exePath, "dup_results.tmp")
$script:dupProgressFile = [System.IO.Path]::Combine($exePath, "dup_progress.tmp")
$script:dupPauseFile = [System.IO.Path]::Combine($exePath, "dup_pause.tmp")
$script:dupSets = @{}
$script:dupLastReadLine = 0

function Clear-HashTempFiles {
    foreach ($f in @($hashProgressFile, $hashResultFile, $hashErrorFile, $hashSpeedFile)) {
        try { if (Test-Path $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } } catch { }
    }
}

function Test-FileLocked {
    param([string]$filePath)
    
    if (-not (Test-Path $filePath)) {
        return $false
    }
    
    try {
        $fileStream = [System.IO.File]::Open($filePath, 'Open', 'Read', 'None')
        $fileStream.Close()
        $fileStream.Dispose()
        return $false
    } catch [System.IO.IOException] {
        return $true
    } catch {
        return $false
    }
}

function Test-LargeFile {
    param([string]$filePath, [ref]$sizeGB)
    
    try {
        $fileInfo = Get-Item -LiteralPath $filePath -ErrorAction Stop
        $fileSizeGB = $fileInfo.Length / 1GB
        $sizeGB.Value = [math]::Round($fileSizeGB, 2)
        return ($fileSizeGB -gt 10)
    } catch {
        return $false
    }
}

function Load-HashCache {
    if ($script:PortableMode) { return }
    
    try {
        if (Test-Path $hashCachePath) {
            $cacheData = Get-Content -Path $hashCachePath -Raw | ConvertFrom-Json
            $script:hashCache = @{}
            foreach ($prop in $cacheData.PSObject.Properties) {
                $script:hashCache[$prop.Name] = $prop.Value
            }
        }
    } catch { 
        $script:hashCache = @{}
    }
}

function Save-HashCache {
    if ($script:PortableMode) { return }
    
    try {
        # Limit cache to 50000 most recent entries
        if ($script:hashCache.Count -gt 50000) {
            $sorted = $script:hashCache.GetEnumerator() | Sort-Object { $_.Value.Timestamp } -Descending | Select-Object -First 50000
            $script:hashCache = @{}
            foreach ($item in $sorted) {
                $script:hashCache[$item.Key] = $item.Value
            }
        }
        $script:hashCache | ConvertTo-Json | Out-File -FilePath $hashCachePath -Force -Encoding UTF8
    } catch { }
}

function Get-CachedHash {
    param(
        [string]$filePath,
        [string]$algorithm,
        [string]$format
    )
    
    try {
        $fileInfo = Get-Item -LiteralPath $filePath -ErrorAction Stop
        $cacheKey = "$filePath|$algorithm|$format"
        
        if ($script:hashCache.ContainsKey($cacheKey)) {
            $cached = $script:hashCache[$cacheKey]
            $cachedModified = [DateTime]::Parse($cached.Modified)
            
            # Check if file hasn't been modified since cache
            if ($fileInfo.LastWriteTime -eq $cachedModified -and $fileInfo.Length -eq $cached.Size) {
                return $cached.Hash
            }
        }
        return $null
    } catch {
        return $null
    }
}

function Set-CachedHash {
    param(
        [string]$filePath,
        [string]$algorithm,
        [string]$format,
        [string]$hash
    )
    
    try {
        $fileInfo = Get-Item -LiteralPath $filePath -ErrorAction Stop
        $cacheKey = "$filePath|$algorithm|$format"
        
        $script:hashCache[$cacheKey] = @{
            Hash = $hash
            Modified = $fileInfo.LastWriteTime.ToString("o")
            Size = $fileInfo.Length
            Timestamp = [DateTime]::Now.ToString("o")
        }
        
        Save-HashCache
    } catch { }
}

function Format-HashOutput {
    param($hashHex, [string]$format)
    
    switch ($format) {
        "lowercase" { return $hashHex }
        "uppercase" { return $hashHex.ToUpperInvariant() }
        "hex" { return "0x" + $hashHex }
        "base64" {
            # Convert hex string to byte array (compatible with .NET Framework 4.8)
            $bytes = New-Object byte[] ($hashHex.Length / 2)
            for ($i = 0; $i -lt $hashHex.Length; $i += 2) {
                $bytes[$i / 2] = [System.Convert]::ToByte($hashHex.Substring($i, 2), 16)
            }
            return [System.Convert]::ToBase64String($bytes)
        }
        default { return $hashHex }
    }
}

function Test-NetworkPath {
    param([string]$path)
    
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    
    # Check if UNC path or mapped network drive
    if ($path -match '^\\\\') {
        return $true
    }
    
    # Check if mapped network drive
    try {
        $drive = Split-Path -Path $path -Qualifier
        if ($drive) {
            $driveInfo = Get-PSDrive -Name $drive.TrimEnd(':') -ErrorAction SilentlyContinue
            if ($driveInfo -and $driveInfo.DisplayRoot) {
                return $true
            }
        }
    } catch { }
    
    return $false
}

function Test-NetworkPathAccessible {
    param(
        [string]$path,
        [int]$timeoutSeconds = $script:networkPathTimeout
    )
    
    # Use a background job with timeout to prevent hanging on unresponsive servers
    $job = Start-Job -ScriptBlock {
        param($pathToTest)
        try {
            if (Test-Path $pathToTest -ErrorAction Stop) {
                # Try to read file attributes to verify access
                $null = Get-Item -LiteralPath $pathToTest -ErrorAction Stop
                return $true
            }
            return $false
        } catch {CrunchHash
            return $false
        }
    } -ArgumentList $path
    
    # Wait for job with timeout
    $completed = Wait-Job -Job $job -Timeout $timeoutSeconds
    
    if ($completed) {
        # Job completed within timeout
        $result = Receive-Job -Job $job
        Remove-Job -Job $job -Force
        return $result
    } else {
        # Job timed out - server is unresponsive
        Stop-Job -Job $job
        Remove-Job -Job $job -Force
        return $false
    }
}

function Export-HashCheckFile {
    param(
        [string]$filePath,
        [string]$hash,
        [string]$algorithm
    )
    
    try {
        if ([string]::IsNullOrWhiteSpace($hash)) {
            return $null
        }
        
        # Strip any whitespace/newlines and ensure it's a clean string
        $cleanHash = ($hash -replace '[\r\n\s]+', '').Trim()
        
        if ([string]::IsNullOrWhiteSpace($cleanHash)) {
            return $null
        }
        
        $hashFilePath = "$filePath.$($algorithm.ToLower())"
        
        # HashCheck format: hash *filename (or hash  filename with two spaces)
        $fileName = [System.IO.Path]::GetFileName($filePath)
        $hashCheckContent = "$cleanHash *$fileName"
        
        # Use UTF8 encoding explicitly with no BOM
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($hashFilePath, $hashCheckContent, $utf8NoBom)
        
        return $hashFilePath
    } catch {
        return $null
    }
}

function Export-SFVFile {
    param(
        [string]$outputPath,
        [hashtable]$fileHashes
    )

    try {
        $sfvContent = "; Generated by CrunchHash v3.0 on $([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))`r`n"
        $sfvContent += "; Total files: $($fileHashes.Count)`r`n`r`n"

        # Get the directory where the .sfv file will be saved
        $sfvDirectory = [System.IO.Path]::GetDirectoryName($outputPath)

        foreach ($entry in $fileHashes.GetEnumerator()) {
            $filePath = $entry.Key
            $fileDirectory = [System.IO.Path]::GetDirectoryName($filePath)

            # Calculate relative path from .sfv location to file
            $relativePath = $null
            if ($fileDirectory -eq $sfvDirectory) {
                # File is in same directory as .sfv - use just filename
                $relativePath = [System.IO.Path]::GetFileName($filePath)
            } else {
                # File is in subdirectory - use relative path
                try {
                    $sfvUri = New-Object System.Uri("$sfvDirectory\")
                    $fileUri = New-Object System.Uri($filePath)
                    $relativeUri = $sfvUri.MakeRelativeUri($fileUri)
                    $relativePath = [System.Uri]::UnescapeDataString($relativeUri.ToString()).Replace('/', '\')
                } catch {
                    # Fallback to just filename if relative path calculation fails
                    $relativePath = [System.IO.Path]::GetFileName($filePath)
                }
            }

            $sfvContent += "$relativePath $($entry.Value)`r`n"
        }

        [System.IO.File]::WriteAllText($outputPath, $sfvContent)
        return $true
    } catch {
        return $false
    }
}

function Show-ToastNotification {
    param(
        [string]$title,
        [string]$message
    )
    
    try {
        # Use Windows 10+ toast notifications
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
        
        $template = @"
<toast>
    <visual>
        <binding template="ToastText02">
            <text id="1">$title</text>
            <text id="2">$message</text>
        </binding>
    </visual>
</toast>
"@
        
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml($template)
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("CrunchHash v3.0").Show($toast)
    } catch {
        # Fallback to balloon tip if toast fails
        if ($script:notifyIcon) {
            $script:notifyIcon.BalloonTipTitle = $title
            $script:notifyIcon.BalloonTipText = $message
            $script:notifyIcon.BalloonTipIcon = 'Info'
            $script:notifyIcon.ShowBalloonTip(5000)
        }
    }
}

function Initialize-TrayIcon {
    param($mainForm)
    
    if ($script:notifyIcon) {
        # Already initialized
        return
    }
    
    try {
        $script:notifyIcon = New-Object System.Windows.Forms.NotifyIcon
        
        # Try to load custom icon, fallback to system icon
        # Handle both script and compiled exe scenarios
        $iconPath = $null
        if ($PSScriptRoot) {
            $iconPath = Join-Path $PSScriptRoot "crunchhash.ico"
        } else {
            # For compiled exe, use the exe's directory
            $exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
            $iconPath = Join-Path (Split-Path -Parent $exePath) "crunchhash.ico"
        }
        
        if ($iconPath -and (Test-Path $iconPath)) {
            try {
                $script:notifyIcon.Icon = New-Object System.Drawing.Icon($iconPath)
            } catch {
                # Use embedded icon from form
                if ($mainForm.Icon) {
                    $script:notifyIcon.Icon = $mainForm.Icon
                } else {
                    $script:notifyIcon.Icon = [System.Drawing.SystemIcons]::Application
                }
            }
        } else {
            # Use embedded icon from form or system icon
            if ($mainForm.Icon) {
                $script:notifyIcon.Icon = $mainForm.Icon
            } else {
                $script:notifyIcon.Icon = [System.Drawing.SystemIcons]::Application
            }
        }
        
        $script:notifyIcon.Text = "CrunchHash v3.0"
        $script:notifyIcon.Visible = $false
        
        # Context menu for tray icon
        $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
        
        $restoreItem = New-Object System.Windows.Forms.ToolStripMenuItem
        $restoreItem.Text = "Restore"
        $restoreItem.Add_Click({
            $form.WindowState = 'Normal'
            $form.Activate()
            $script:notifyIcon.Visible = $false
        })
        
        $exitItem = New-Object System.Windows.Forms.ToolStripMenuItem
        $exitItem.Text = "Exit"
        $exitItem.Add_Click({
            $form.Close()
        })
        
        $contextMenu.Items.Add($restoreItem)
        $contextMenu.Items.Add($exitItem)
        $script:notifyIcon.ContextMenuStrip = $contextMenu
        
        # Double-click to restore
        $script:notifyIcon.Add_DoubleClick({
            $form.WindowState = 'Normal'
            $form.Activate()
            $script:notifyIcon.Visible = $false
        })
    } catch {
        # Silently fail
    }
}

function Save-Config {
    if ($script:PortableMode) { return }
    
    try {
        $config = @{
            algorithm = $comboAlgo.SelectedIndex
            darkMode = $checkDarkMode.Checked
            fontSize = [int]$numericFontSize.Value
            hashFormat = if ($radioFormatUpper.Checked) { "uppercase" } elseif ($radioFormatHex.Checked) { "hex" } elseif ($radioFormatBase64.Checked) { "base64" } else { "lowercase" }
            autoCopy = $checkAutoCopy.Checked
            recentFiles = $script:recentFiles
            parallelThreads = $script:parallelThreadCount
            networkPathTimeout = $script:networkPathTimeout
        }
        $config | ConvertTo-Json | Out-File -FilePath $configPath -Force -Encoding UTF8
    } catch { }
}

function Get-Config {
    if ($script:PortableMode) { return }
    
    try {
        if (Test-Path $configPath) {
            $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
            if ($config.algorithm -ge 0 -and $config.algorithm -lt $comboAlgo.Items.Count) { $comboAlgo.SelectedIndex = $config.algorithm }
            $checkDarkMode.Checked = $config.darkMode
            $numericFontSize.Value = $config.fontSize
            $checkAutoCopy.Checked = $config.autoCopy
            
            # Load parallel thread count
            if ($config.parallelThreads) {
                $script:parallelThreadCount = [int]$config.parallelThreads
                if ($numericParallelThreads) {
                    $numericParallelThreads.Value = $script:parallelThreadCount
                }
            }
            
            # Load network path timeout
            if ($config.networkPathTimeout) {
                $script:networkPathTimeout = [int]$config.networkPathTimeout
                if ($numericNetworkTimeout) {
                    $numericNetworkTimeout.Value = $script:networkPathTimeout
                }
            }
            
            # Set hash format
            switch ($config.hashFormat) {
                "uppercase" { $radioFormatUpper.Checked = $true }
                "hex" { $radioFormatHex.Checked = $true }
                "base64" { $radioFormatBase64.Checked = $true }
                default { $radioFormatLower.Checked = $true }
            }
            
            # Load recent files
            if ($config.recentFiles) {
                $script:recentFiles = @($config.recentFiles)
            }
        }
        
        # Load hash cache
        Load-HashCache
    } catch { }
}

function Add-RecentFile {
    param([string]$filePath)
    
    if ([string]::IsNullOrWhiteSpace($filePath) -or -not (Test-Path $filePath)) { return }
    
    # Remove if already exists
    $script:recentFiles = @($script:recentFiles | Where-Object { $_ -ne $filePath })
    
    # Add to beginning
    $script:recentFiles = @($filePath) + $script:recentFiles
    
    # Keep only last 100
    if ($script:recentFiles.Count -gt 100) {
        $script:recentFiles = $script:recentFiles[0..99]
    }
    
    # Update UI
    Update-RecentFilesList
}

function Update-RecentFilesList {
    if ($listBoxRecentFiles) {
        $listBoxRecentFiles.Items.Clear()
        $maxWidth = 0
        $index = 1
        foreach ($file in $script:recentFiles) {
            if (Test-Path $file) {
                $numberedFile = "$index. $file"
                [void]$listBoxRecentFiles.Items.Add($numberedFile)
                # Calculate width needed for horizontal scrolling
                $textWidth = [System.Windows.Forms.TextRenderer]::MeasureText($numberedFile, $listBoxRecentFiles.Font).Width
                if ($textWidth -gt $maxWidth) {
                    $maxWidth = $textWidth
                }
                $index++
            }
        }
        # Set horizontal extent to allow full scrolling with extra padding (more padding for larger fonts)
        $listBoxRecentFiles.HorizontalExtent = $maxWidth + 50
    }
}

function Add-LineNumbers {
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text) -or $Text -eq "No log entries." -or $Text -eq "No batch log entries." -or $Text -eq "Log cleared." -or $Text -eq "Batch log cleared.") {
        return $Text
    }

    $lines = $Text -split "`r`n|`n"

    # Remove trailing empty lines but keep one
    while ($lines.Count -gt 1 -and [string]::IsNullOrEmpty($lines[$lines.Count - 1]) -and [string]::IsNullOrEmpty($lines[$lines.Count - 2])) {
        $lines = $lines[0..($lines.Count - 2)]
    }

    $numberedLines = New-Object System.Collections.ArrayList
    $index = 1

    foreach ($line in $lines) {
        [void]$numberedLines.Add("$index. $line")
        $index++
    }

    return ($numberedLines -join "`r`n")
}

function Add-ColoredText {
    param(
        [System.Windows.Forms.RichTextBox]$RichTextBox,
        [string]$Text,
        [System.Drawing.Color]$Color = [System.Drawing.Color]::Black
    )

    $RichTextBox.SelectionStart = $RichTextBox.TextLength
    $RichTextBox.SelectionLength = 0
    $RichTextBox.SelectionColor = $Color
    $RichTextBox.AppendText($Text)
    $RichTextBox.SelectionColor = $RichTextBox.ForeColor
}

function Update-BatchFilesListExtent {
    if ($listBoxBatchFiles -and $listBoxBatchFiles.Items.Count -gt 0) {
        $maxWidth = 0
        foreach ($item in $listBoxBatchFiles.Items) {
            $textWidth = [System.Windows.Forms.TextRenderer]::MeasureText($item.ToString(), $listBoxBatchFiles.Font).Width
            if ($textWidth -gt $maxWidth) {
                $maxWidth = $textWidth
            }
        }
        # Set horizontal extent to allow full scrolling with extra padding
        $listBoxBatchFiles.HorizontalExtent = $maxWidth + 50
    }
}

function Start-BatchFileLoading {
    param(
        [string]$folderPath,
        [bool]$recursive
    )

    # Stop any existing loading job
    if ($script:batchLoadingJobId) {
        try {
            Stop-Job -Id $script:batchLoadingJobId -ErrorAction SilentlyContinue
            Remove-Job -Id $script:batchLoadingJobId -Force -ErrorAction SilentlyContinue
        } catch { }
        $script:batchLoadingJobId = $null
    }

    # Clean up temp file
    if (Test-Path $script:batchLoadingTempFile) {
        Remove-Item $script:batchLoadingTempFile -Force -ErrorAction SilentlyContinue
    }

    $script:batchLoadingShouldCancel = $false
    $script:batchLoadingAddedFiles = New-Object System.Collections.Generic.HashSet[string]

    # Start background job to enumerate files
    $job = Start-Job -ScriptBlock {
        param($folderPath, $recursive, $outputFile)

        try {
            $fileCount = 0
            $batchSize = 100
            $batchLines = New-Object System.Collections.ArrayList

            # Normalize path - ensure it ends with \ for drive roots
            if ($folderPath -match '^[A-Za-z]:$') {
                $folderPath = $folderPath + '\'
            }

            # Use streaming writer for better performance and reliability
            $writer = [System.IO.StreamWriter]::new($outputFile, $false, [System.Text.Encoding]::UTF8)

            try {
                # Use -Path instead of -LiteralPath for better drive root compatibility
                if ($recursive) {
                    $files = Get-ChildItem -Path $folderPath -File -Recurse -ErrorAction SilentlyContinue
                } else {
                    $files = Get-ChildItem -Path $folderPath -File -ErrorAction SilentlyContinue
                }

                # Process files as they come in (streaming)
                foreach ($file in $files) {
                    $fileCount++
                    [void]$batchLines.Add($file.FullName)

                    if ($batchLines.Count -ge $batchSize) {
                        # Write batch to file with progress info: fileCount|filePaths
                        $output = "$fileCount|" + ($batchLines -join "`n")
                        $writer.WriteLine($output)
                        $writer.WriteLine("===BATCH===")
                        $writer.Flush()
                        $batchLines.Clear()
                    }
                }

                # Write remaining files
                if ($batchLines.Count -gt 0) {
                    $output = "$fileCount|" + ($batchLines -join "`n")
                    $writer.WriteLine($output)
                    $writer.WriteLine("===BATCH===")
                    $writer.Flush()
                }

                # Write completion marker with final count
                $writer.WriteLine("===COMPLETE===|$fileCount")
                $writer.Flush()

            } finally {
                if ($writer) { $writer.Close(); $writer.Dispose() }
            }

        } catch {
            # Write error marker
            try {
                [System.IO.File]::AppendAllText($outputFile, "===ERROR===|$($_.Exception.Message)`n")
            } catch { }
        }
    } -ArgumentList $folderPath, $recursive, $script:batchLoadingTempFile

    $script:batchLoadingJobId = $job.Id

    # Disable add buttons during loading
    $buttonBatchAdd.Enabled = $false
    $labelBatchFooter.Text = "Loading files from folder..."
    $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange

    # Show and start spinner animation
    $script:batchLoadingSpinner.Visible = $true
    $script:batchLoadingSpinner.BringToFront()
    $script:spinnerTimer.Start()
}

function Start-HashJob {
    param($inputPath, $algoName, $keyBytes)

    Clear-HashTempFiles

    $job = Start-Job -ScriptBlock {
        param($inputPath, $algoName, $keyBytes, $progressFile, $resultFile, $errorFile, $speedFile)

        # Load FastCRC32 class in job scope
        try {
            $null = [FastCRC32]
        } catch {
            try {
                Add-Type -TypeDefinition @"
using System;
using System.IO;

public class FastCRC32
{
    private static uint[] crcTable;

    static FastCRC32()
    {
        crcTable = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int j = 0; j < 8; j++)
            {
                if ((c & 1) != 0)
                    c = (c >> 1) ^ 0xEDB88320;
                else
                    c >>= 1;
            }
            crcTable[i] = c;
        }
    }

    public static uint ComputeHashStream(Stream stream, Action<int, double> progressCallback)
    {
        uint crc = 0xFFFFFFFF;
        byte[] buffer = new byte[65536];
        long total = stream.Length;
        long read = 0;
        int count;
        DateTime startTime = DateTime.Now;
        
        while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i < count; i++)
            {
                byte index = (byte)(crc ^ buffer[i]);
                crc = (crc >> 8) ^ crcTable[index];
            }
            read += count;
            
            if (progressCallback != null)
            {
                int percent = total > 0 ? (int)((100 * read) / total) : 100;
                double elapsed = (DateTime.Now - startTime).TotalSeconds;
                double speedMBs = elapsed > 0 ? (read / 1048576.0) / elapsed : 0;
                progressCallback(percent, speedMBs);
            }
        }
        return crc ^ 0xFFFFFFFF;
    }
}
"@ -ErrorAction SilentlyContinue
            } catch {
                # Ignore Add-Type errors - CRC32 will still work
            }
        }

        try {
            if (-not (Test-Path $inputPath)) {
                [System.IO.File]::WriteAllText($errorFile, "File not found: $inputPath")
                return
            }

            # CRC32 special handling (using compiled C# class)
            if ($algoName -eq "CRC32") {
                $fs = [System.IO.File]::OpenRead($inputPath)
                try {
                    $callback = {
                        param($percent, $speedMBs)
                        try { 
                            [System.IO.File]::WriteAllText($progressFile, $percent.ToString())
                            [System.IO.File]::WriteAllText($speedFile, $speedMBs.ToString("F2"))
                        } catch { }
                    }
                    
                    $crc32 = [FastCRC32]::ComputeHashStream($fs, $callback)
                    $hash = $crc32.ToString("x8")
                    try { [System.IO.File]::WriteAllText($resultFile, $hash) } catch { }
                } finally {
                    if ($fs) { $fs.Close() }
                }
                return
            }

            # Standard hash algorithms
            switch ($algoName) {
                "SHA256" { $algo = [System.Security.Cryptography.SHA256]::Create() }
                "SHA1"   { $algo = [System.Security.Cryptography.SHA1]::Create() }
                "SHA512" { $algo = [System.Security.Cryptography.SHA512]::Create() }
                "MD5"    { $algo = [System.Security.Cryptography.MD5]::Create() }
                "SHA384" { $algo = [System.Security.Cryptography.SHA384]::Create() }
                "RIPEMD160" { $algo = [System.Security.Cryptography.RIPEMD160]::Create() }
                "HMACSHA256" { $algo = [System.Security.Cryptography.HMACSHA256]::new($keyBytes) }
                "HMACSHA512" { $algo = [System.Security.Cryptography.HMACSHA512]::new($keyBytes) }
                default { throw "Unsupported algorithm: $algoName" }
            }

            $fs = [System.IO.File]::OpenRead($inputPath)
            try {
                $chunkSize = 4 * 1024 * 1024
                $buffer = New-Object byte[] $chunkSize
                $outBuf = New-Object byte[] $chunkSize
                $empty = New-Object byte[] 0
                $total = $fs.Length
                $read = 0
                $startTime = [DateTime]::Now
                
                while (($count = $fs.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $null = $algo.TransformBlock($buffer, 0, $count, $outBuf, 0)
                    $read += $count
                    $percent = if ($total -gt 0) { [int]((100 * $read) / $total) } else { 100 }
                    
                    # Calculate speed
                    $elapsed = ([DateTime]::Now - $startTime).TotalSeconds
                    if ($elapsed -gt 0) {
                        $speedMBs = ($read / 1MB) / $elapsed
                        try { 
                            [System.IO.File]::WriteAllText($progressFile, $percent.ToString())
                            [System.IO.File]::WriteAllText($speedFile, $speedMBs.ToString("F2"))
                        } catch { }
                    }
                }
                $null = $algo.TransformFinalBlock($empty, 0, 0)
                $hashBytes = $algo.Hash
                $hash = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLowerInvariant()
                try { [System.IO.File]::WriteAllText($resultFile, $hash) } catch { }
            } finally {
                if ($fs) { $fs.Close() }
            }
        } catch {
            try { [System.IO.File]::WriteAllText($errorFile, $_.Exception.Message) } catch { }
        } finally {
            if ($algo) { $algo.Dispose() }
        }
    } -ArgumentList $inputPath, $algoName, $keyBytes, $hashProgressFile, $hashResultFile, $hashErrorFile, $hashSpeedFile
    
    $script:currentJobId = $job.Id
    return $job.Id
}
function Set-DarkMode {
    param([bool]$enabled)

    if ($enabled) {
        # PlanetArchives dark palette - BOLD version
        $bgColor      = [System.Drawing.Color]::FromArgb(10, 15, 35)     # very deep navy
        $tabColor     = [System.Drawing.Color]::FromArgb(18, 24, 45)     # deep tab color
        $headerColor  = [System.Drawing.Color]::FromArgb(45, 85, 150)    # RICH BLUE HEADER
        $panelColor   = [System.Drawing.Color]::FromArgb(25, 30, 50)     # deep panel
        $accentColor  = [System.Drawing.Color]::FromArgb(100, 160, 255)  # BRIGHT BLUE BUTTONS
        $fgColor      = [System.Drawing.Color]::FromArgb(240, 240, 245)  # nearly white text
        $outputFore   = [System.Drawing.Color]::FromArgb(150, 210, 255)  # bright cyan-blue output
        
        # persist theme colors for other code paths
        $script:DarkBgColor      = $bgColor
        $script:DarkTabColor     = $tabColor
        $script:DarkHeaderColor  = $headerColor
        $script:DarkPanelColor   = $panelColor
        $script:DarkAccentColor  = $accentColor
        $script:DarkForeColor    = $fgColor
        $script:DarkOutputFore   = $outputFore

        $form.BackColor = $bgColor
        $tabControl.BackColor = $tabColor
        $tabControl.ForeColor = $fgColor

        # Header / title label to act like a colored titlebar
        if ($labelHeader) {
            $labelHeader.BackColor = $headerColor
            $labelHeader.ForeColor = $fgColor
            $labelHeader.Padding = New-Object System.Windows.Forms.Padding(6)
        }

        foreach ($tab in $tabControl.TabPages) {
            $tab.BackColor = $tabColor
            $tab.ForeColor = $fgColor
            foreach ($ctrl in $tab.Controls) {
                switch ($ctrl.GetType().Name) {
                    "TextBox" {
                        $ctrl.BackColor = $panelColor
                        $ctrl.ForeColor = $fgColor
                        $ctrl.BorderStyle = 'FixedSingle'
                    }
                    "RichTextBox" {
                        $ctrl.BackColor = $panelColor
                        $ctrl.ForeColor = $fgColor
                        $ctrl.BorderStyle = 'FixedSingle'
                    }
                    "Label" {
                        $ctrl.BackColor = $tabColor
                        $ctrl.ForeColor = $fgColor
                    }
                    "Button" {
                        # Skip Pause buttons - they have custom colors (yellow/green)
                        if ($ctrl -ne $buttonDupPause -and $ctrl -ne $buttonBatchPause -and $ctrl -ne $buttonVerifyPause) {
                            $ctrl.BackColor = $accentColor
                            $ctrl.ForeColor = [System.Drawing.Color]::White
                            $ctrl.FlatStyle = 'Standard'
                        }
                    }
                    "CheckBox" { $ctrl.BackColor = $tabColor; $ctrl.ForeColor = $fgColor }
                    "RadioButton" { $ctrl.BackColor = $tabColor; $ctrl.ForeColor = $fgColor }
                    "ComboBox" { $ctrl.BackColor = $panelColor; $ctrl.ForeColor = $fgColor }
                    "ListBox" { $ctrl.BackColor = $panelColor; $ctrl.ForeColor = $fgColor }
                    "NumericUpDown" { $ctrl.BackColor = $panelColor; $ctrl.ForeColor = $fgColor }
                    "Panel" { $ctrl.BackColor = $panelColor }
                }
            }
        }

        # Make main output stand out
        if ($textBoxResult) {
            $textBoxResult.BackColor = $panelColor
            $textBoxResult.ForeColor = $outputFore
            $textBoxResult.Font = $script:fontOutput
        }
        if ($textBoxLogViewer) { $textBoxLogViewer.BackColor = $panelColor; $textBoxLogViewer.ForeColor = $outputFore }
        if ($textBoxBatchResults) { $textBoxBatchResults.BackColor = $panelColor; $textBoxBatchResults.ForeColor = $outputFore }
        if ($textBoxBatchLogViewer) { $textBoxBatchLogViewer.BackColor = $panelColor; $textBoxBatchLogViewer.ForeColor = $outputFore }
        if ($textBoxVerifyInput) { $textBoxVerifyInput.BackColor = $panelColor; $textBoxVerifyInput.ForeColor = $outputFore }
        if ($textBoxVerifyResults) { $textBoxVerifyResults.BackColor = $panelColor; $textBoxVerifyResults.ForeColor = $outputFore }
        if ($textBoxDupResults) { $textBoxDupResults.BackColor = $panelColor; $textBoxDupResults.ForeColor = $outputFore }
        if ($listBoxRecentFiles) { $listBoxRecentFiles.BackColor = $panelColor; $listBoxRecentFiles.ForeColor = $outputFore }

        $labelFooter.BackColor = $bgColor
        $labelFooter.ForeColor = $fgColor
        $labelBatchFooter.BackColor = $bgColor
        $labelBatchFooter.ForeColor = $fgColor
        } else {
        # restore light mode defaults
        # clear theme vars
        $script:DarkBgColor = $null
        $script:DarkTabColor = $null
        $script:DarkPanelColor = $null
        $script:DarkOutputFore = $null

        $form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
        $tabControl.BackColor = [System.Drawing.Color]::White
        $tabControl.ForeColor = [System.Drawing.Color]::Black
        if ($labelHeader) {
            $labelHeader.BackColor = [System.Drawing.Color]::Transparent
            $labelHeader.ForeColor = [System.Drawing.Color]::Black
            $labelHeader.Padding = [System.Windows.Forms.Padding]::Empty
        }

        foreach ($tab in $tabControl.TabPages) {
            $tab.BackColor = [System.Drawing.Color]::White
            $tab.ForeColor = [System.Drawing.Color]::Black
            foreach ($ctrl in $tab.Controls) {
                switch ($ctrl.GetType().Name) {
                    "TextBox" {
                        $ctrl.BackColor = [System.Drawing.Color]::White
                        $ctrl.ForeColor = [System.Drawing.Color]::Black
                        $ctrl.BorderStyle = 'Fixed3D'
                    }
                    "RichTextBox" {
                        $ctrl.BackColor = [System.Drawing.Color]::White
                        $ctrl.ForeColor = [System.Drawing.Color]::Black
                        $ctrl.BorderStyle = 'Fixed3D'
                    }
                    "Label" {
                        $ctrl.BackColor = [System.Drawing.Color]::White
                        $ctrl.ForeColor = [System.Drawing.Color]::Black
                    }
                    "Button" {
                        # Skip Pause buttons - they have custom colors (yellow/green)
                        if ($ctrl -ne $buttonDupPause -and $ctrl -ne $buttonBatchPause -and $ctrl -ne $buttonVerifyPause) {
                            $ctrl.BackColor = [System.Drawing.Color]::FromArgb(0,122,204)
                            $ctrl.ForeColor = [System.Drawing.Color]::White
                        }
                    }
                    "CheckBox" { $ctrl.BackColor = [System.Drawing.Color]::White; $ctrl.ForeColor = [System.Drawing.Color]::Black }
                    "RadioButton" { $ctrl.BackColor = [System.Drawing.Color]::White; $ctrl.ForeColor = [System.Drawing.Color]::Black }
                    "ComboBox" { $ctrl.BackColor = [System.Drawing.Color]::White; $ctrl.ForeColor = [System.Drawing.Color]::Black }
                    "ListBox" { $ctrl.BackColor = [System.Drawing.Color]::White; $ctrl.ForeColor = [System.Drawing.Color]::Black }
                    "NumericUpDown" { $ctrl.BackColor = [System.Drawing.Color]::White; $ctrl.ForeColor = [System.Drawing.Color]::Black }
                    "Panel" { $ctrl.BackColor = [System.Drawing.Color]::LightGray }
                }
            }
        }

        if ($textBoxResult) {
            $textBoxResult.BackColor = [System.Drawing.Color]::White
            $textBoxResult.ForeColor = [System.Drawing.Color]::Black
            $textBoxResult.Font = $script:fontOutput
        }
        if ($textBoxLogViewer) { $textBoxLogViewer.BackColor = [System.Drawing.Color]::White; $textBoxLogViewer.ForeColor = [System.Drawing.Color]::Black }
        if ($textBoxBatchLogViewer) { $textBoxBatchLogViewer.BackColor = [System.Drawing.Color]::White; $textBoxBatchLogViewer.ForeColor = [System.Drawing.Color]::Black }

        $labelFooter.BackColor = [System.Drawing.Color]::White
        $labelFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray
        $labelBatchFooter.BackColor = [System.Drawing.Color]::White
        $labelBatchFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray
    }
}

# Create main form
$form = New-Object System.Windows.Forms.Form
if ($script:PortableMode) {
    $form.Text = "CrunchHash v3.0  [WARNING: Portable Mode - No config/cache will be saved]"
} else {
    $form.Text = "CrunchHash v3.0"
}
$form.Size = New-Object System.Drawing.Size(600, 700)
$form.StartPosition = "CenterScreen"

# Detect Windows high contrast mode and apply color scheme
$applyHighContrast = [System.Windows.Forms.SystemInformation]::HighContrast
if ($applyHighContrast) {
    $form.BackColor = [System.Drawing.Color]::Black
    $form.ForeColor = [System.Drawing.Color]::White
    $form.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    foreach ($tab in $tabControl.TabPages) {
        $tab.BackColor = [System.Drawing.Color]::Black
        $tab.ForeColor = [System.Drawing.Color]::White
        foreach ($ctrl in $tab.Controls) {
            switch ($ctrl.GetType().Name) {
                "TextBox" {
                    $ctrl.BackColor = [System.Drawing.Color]::Black
                    $ctrl.ForeColor = [System.Drawing.Color]::Yellow
                }
                "Button" {
                    $ctrl.BackColor = [System.Drawing.Color]::Yellow
                    $ctrl.ForeColor = [System.Drawing.Color]::Black
                }
                "Label" {
                    $ctrl.ForeColor = [System.Drawing.Color]::White
                }
                "CheckBox" {
                    $ctrl.ForeColor = [System.Drawing.Color]::White
                }
                "RadioButton" {
                    $ctrl.ForeColor = [System.Drawing.Color]::White
                }
                "ComboBox" {
                    $ctrl.BackColor = [System.Drawing.Color]::Black
                    $ctrl.ForeColor = [System.Drawing.Color]::Yellow
                }
            }
        }
    }
}
else {
    $form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $form.ForeColor = [System.Drawing.Color]::Black
    $form.Font = New-Object System.Drawing.Font("Segoe UI", 10)
}
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.KeyPreview = $true

# Create tooltip component
$tooltip = New-Object System.Windows.Forms.ToolTip
$tooltip.AutoPopDelay = 5000
$tooltip.InitialDelay = 500
$tooltip.ReshowDelay = 100


# Tab control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Size = New-Object System.Drawing.Size(580, 650)

# Auto-refresh Log Viewer when tab is selected
$tabControl.Add_SelectedIndexChanged({
    if ($tabControl.SelectedTab -eq $tabLogViewer) {
        if ((Test-Path $logPath) -and ((Get-Item $logPath).Length -gt 0)) {
            $textBoxLogViewer.Text = Get-Content $logPath -Raw
        } else {
            $textBoxLogViewer.Text = "No log entries."
        }
    }
})

$tabMain = New-Object System.Windows.Forms.TabPage
$tabMain.Text = "Main"

$tabAbout = New-Object System.Windows.Forms.TabPage
$tabAbout.Text = "About"

$tabLogViewer = New-Object System.Windows.Forms.TabPage
$tabLogViewer.Text = "Log Viewer"

$tabSettings = New-Object System.Windows.Forms.TabPage
$tabSettings.Text = "Settings"

$tabBatch = New-Object System.Windows.Forms.TabPage
$tabBatch.Text = "Batch"

$tabBatchLogViewer = New-Object System.Windows.Forms.TabPage
$tabBatchLogViewer.Text = "Batch Log Viewer"

$tabRecentFiles = New-Object System.Windows.Forms.TabPage
$tabRecentFiles.Text = "Recent Files"

$tabVerify = New-Object System.Windows.Forms.TabPage
$tabVerify.Text = "Verify"

$tabDuplicateFinder = New-Object System.Windows.Forms.TabPage
$tabDuplicateFinder.Text = "Duplicate Finder"

$tabControl.TabPages.AddRange(@($tabMain, $tabLogViewer, $tabBatch, $tabBatchLogViewer, $tabRecentFiles, $tabVerify, $tabDuplicateFinder, $tabSettings, $tabAbout))
$form.Controls.Add($tabControl)

# Main Tab Controls
$labelHeader = New-Object System.Windows.Forms.Label
$labelHeader.Text = "CrunchHash v3.0"
$labelHeader.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$labelHeader.Location = New-Object System.Drawing.Point(20, 10)
$labelHeader.Size = New-Object System.Drawing.Size(540, 30)
$labelHeader.TextAlign = "MiddleCenter"

$radioString = New-Object System.Windows.Forms.RadioButton
$radioString.Text = "String Mode"
$radioString.Location = New-Object System.Drawing.Point(20, 50)
$radioString.Checked = $true
$radioString.AutoSize = $true

$radioFile = New-Object System.Windows.Forms.RadioButton
$radioFile.Text = "File Mode"
$radioFile.Location = New-Object System.Drawing.Point(150, 50)
$radioFile.AutoSize = $true

$labelInput = New-Object System.Windows.Forms.Label
$labelInput.Text = "Enter string:"
$labelInput.Location = New-Object System.Drawing.Point(20, 80)
$labelInput.Size = New-Object System.Drawing.Size(150, 20)

$textBoxInput = New-Object System.Windows.Forms.TextBox
$textBoxInput.Location = New-Object System.Drawing.Point(20, 105)
$textBoxInput.Size = New-Object System.Drawing.Size(500, 20)
$textBoxInput.AllowDrop = $true

$buttonBrowse = New-Object System.Windows.Forms.Button
$buttonBrowse.Text = "Browse..."
$buttonBrowse.Location = New-Object System.Drawing.Point(440, 130)
$buttonBrowse.Size = New-Object System.Drawing.Size(80, 25)
$buttonBrowse.Visible = $false
$buttonBrowse.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonBrowse.ForeColor = [System.Drawing.Color]::White

$labelAlgo = New-Object System.Windows.Forms.Label
$labelAlgo.Text = "Algorithm:"
$labelAlgo.Location = New-Object System.Drawing.Point(20, 160)
$labelAlgo.Size = New-Object System.Drawing.Size(150, 20)

$comboAlgo = New-Object System.Windows.Forms.ComboBox
$comboAlgo.Location = New-Object System.Drawing.Point(20, 185)
$comboAlgo.Size = New-Object System.Drawing.Size(200, 20)
$comboAlgo.Items.AddRange(@("SHA256", "SHA1", "SHA512", "MD5", "SHA384", "RIPEMD160", "CRC32", "HMACSHA256", "HMACSHA512"))
$comboAlgo.SelectedIndex = 0

$labelKey = New-Object System.Windows.Forms.Label
$labelKey.Text = "HMAC Key:"
$labelKey.Location = New-Object System.Drawing.Point(20, 215)
$labelKey.Size = New-Object System.Drawing.Size(150, 20)
$labelKey.Visible = $true

$textBoxKey = New-Object System.Windows.Forms.TextBox
$textBoxKey.Location = New-Object System.Drawing.Point(20, 240)
$textBoxKey.Size = New-Object System.Drawing.Size(500, 20)
$textBoxKey.UseSystemPasswordChar = $true
$textBoxKey.Visible = $true
$textBoxKey.Enabled = $false
$textBoxKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$textBoxKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)

$labelCompare = New-Object System.Windows.Forms.Label
$labelCompare.Text = "Compare with hash:"
$labelCompare.Location = New-Object System.Drawing.Point(20, 270)
$labelCompare.Size = New-Object System.Drawing.Size(150, 20)

$textBoxCompare = New-Object System.Windows.Forms.TextBox
$textBoxCompare.Location = New-Object System.Drawing.Point(20, 295)
$textBoxCompare.Size = New-Object System.Drawing.Size(500, 20)

$checkLog = New-Object System.Windows.Forms.CheckBox
$checkLog.Text = "Log to file"
$checkLog.Location = New-Object System.Drawing.Point(20, 325)
$checkLog.AutoSize = $true

$buttonGenerate = New-Object System.Windows.Forms.Button
$buttonGenerate.Text = "Generate Hash"
$buttonGenerate.Location = New-Object System.Drawing.Point(20, 355)
$buttonGenerate.Size = New-Object System.Drawing.Size(120, 30)
$buttonGenerate.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonGenerate.ForeColor = [System.Drawing.Color]::White

$buttonCompare = New-Object System.Windows.Forms.Button
$buttonCompare.Text = "Compare"
$buttonCompare.Location = New-Object System.Drawing.Point(150, 355)
$buttonCompare.Size = New-Object System.Drawing.Size(100, 30)
$buttonCompare.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonCompare.ForeColor = [System.Drawing.Color]::White

$buttonCopy = New-Object System.Windows.Forms.Button
$buttonCopy.Text = "Copy"
$buttonCopy.Location = New-Object System.Drawing.Point(260, 355)
$buttonCopy.Size = New-Object System.Drawing.Size(100, 30)
$buttonCopy.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonCopy.ForeColor = [System.Drawing.Color]::White

$buttonClear = New-Object System.Windows.Forms.Button
$buttonClear.Text = "Clear"
$buttonClear.Location = New-Object System.Drawing.Point(370, 355)
$buttonClear.Size = New-Object System.Drawing.Size(110, 30)
$buttonClear.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonClear.ForeColor = [System.Drawing.Color]::White

$buttonStop = New-Object System.Windows.Forms.Button
$buttonStop.Text = "Stop"
$buttonStop.Location = New-Object System.Drawing.Point(490, 355)
$buttonStop.Size = New-Object System.Drawing.Size(70, 30)
$buttonStop.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonStop.ForeColor = [System.Drawing.Color]::White
$buttonStop.Enabled = $false

$textBoxResult = New-Object System.Windows.Forms.RichTextBox
$textBoxResult.Location = New-Object System.Drawing.Point(20, 400)
$textBoxResult.Size = New-Object System.Drawing.Size(540, 180)
$textBoxResult.ReadOnly = $true
$textBoxResult.BackColor = [System.Drawing.Color]::White
$textBoxResult.Font = $script:fontOutput
$textBoxResult.ScrollBars = "Both"
$textBoxResult.WordWrap = $false

$panelProgressBackground = New-Object System.Windows.Forms.Panel
$panelProgressBackground.Location = New-Object System.Drawing.Point(20, 590)
$panelProgressBackground.Size = New-Object System.Drawing.Size(540, 10)
$panelProgressBackground.BackColor = [System.Drawing.Color]::LightGray
$panelProgressBackground.BorderStyle = 'FixedSingle'

$panelProgressFill = New-Object System.Windows.Forms.Panel
$panelProgressFill.Location = New-Object System.Drawing.Point(0, 0)
$panelProgressFill.Size = New-Object System.Drawing.Size(0, 10)
$panelProgressFill.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$panelProgressBackground.Controls.Add($panelProgressFill)

$labelFooter = New-Object System.Windows.Forms.Label
$labelFooter.Text = "Ready"
$labelFooter.Location = New-Object System.Drawing.Point(20, 605)
$labelFooter.Size = New-Object System.Drawing.Size(540, 20)
$labelFooter.TextAlign = "MiddleRight"
$labelFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray
$labelFooter.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# About Tab
$labelAbout = New-Object System.Windows.Forms.Label
$labelAbout.Text = @"
CrunchHash v3.0

A professional hashing interface for cryptographic operations.

Core Features:
- String/File mode selection with drag-and-drop support and visual feedback
- 9 hash algorithms: SHA256, SHA1, SHA512, MD5, SHA384, RIPEMD160, CRC32, HMACSHA256, HMACSHA512
- Fast CRC32 implementation using compiled C# for 10-20x speedup
- HMAC key support for keyed hash algorithms (HMACSHA256, HMACSHA512)
- Real-time progress tracking with speed indicator (MB/s)
- Hash comparison with visual verdict (MATCH/MISMATCH)
- File details display: size, modified date, full path
- File locking detection - warns if files are in use by other processes
- Large file warnings - alerts for files >10GB with confirmation dialog
- Hash result caching - skips re-hashing unchanged files (based on path + modified time)
- Network path support - UNC paths and mapped drives with connection verification
- Network path timeouts - 5-second timeout prevents hanging on unresponsive servers
- Portable mode - run with -Portable flag to disable config/cache persistence

Hash Output Formats:
- lowercase (default)
- UPPERCASE
- Hex with 0x prefix
- Base64 encoded

Export Formats:
- TXT/CSV - Structured batch results export
- HashCheck - Individual .sha256/.md5/etc files alongside originals
- SFV - Simple File Verification format for CRC32
- Verify Log - Compatible format for Verify tab import

Batch Operations:
- Hash multiple files with real-time result streaming
- Configurable parallel processing (1-8 threads) for faster operations
- Independent algorithm selector per tab
- Results appear instantly as each file completes
- Horizontal scrolling in file list for long paths
- Export batch results to multiple formats including Verify Log
- Full file paths in results for traceability
- Stop/resume with preservation of completed hashes
- Pre-flight checks for locked, large, and network files
- Network path timeout checks prevent batch delays
- [CACHED] markers indicate files loaded from cache

Hash Verification:
- Verify multiple files against hash list with real-time results
- Import batch logs directly via 'Import Batch Log' button
- Supports hash<TAB>filename or hash<SPACE>filename format
- Base directory support for relative paths
- Independent algorithm selector
- Real-time progress with file-by-file result streaming
- Detailed results: MATCH/MISMATCH/MISSING/ERROR
- Results appear immediately as each file is verified

Recent Files:
- Quick access to previously hashed files (last 50)
- Multi-selection support (Ctrl+Click, Shift+Click)
- Horizontal scrolling with dynamic extent calculation
- Font size aware scrolling (adjusts for 8-24pt fonts)
- Single file: Quick hash in Main tab
- Multiple files: Batch processing
- Dual-button system with conditional enable/disable

Duplicate Finder:
- Recursively scan directories for duplicate files based on hash
- Real-time progress tracking with file count and hash statistics
- Detailed results showing all copies of duplicate files with full paths
- Group duplicates by hash with file size and count information
- Export duplicate results to text file for analysis
- Right-click context menu for copying results
- Stop button to cancel long-running scans
- Background processing prevents UI freezing

User Interface:
- Dark mode theme with PlanetArchives color palette
- Adjustable output font size (8-24pt)
- Automatic copy to clipboard option
- Settings persistence across sessions
- 8 organized tabs for different operations
- Keyboard shortcuts (Ctrl+Enter to hash, Ctrl+C to copy)
- System tray minimization during long operations
- Toast notifications for background operation completion
- Visual drag-drop feedback with color highlights
- Horizontal scrolling in batch file lists and recent files
- Smart button locking - export buttons disabled during active operations

Logging:
- Comprehensive logging with format tracking
- Separate logs for single and batch operations
- Auto-refresh after clearing logs
- Open logs in Notepad for external editing

Technical Details:
* PowerShell 5.1+ with .NET Framework 4.8
* Windows Forms GUI (System.Windows.Forms, System.Drawing)
* Asynchronous file hashing with background jobs
* Parallel batch processing support (configurable thread count)
* Temp file communication for progress tracking
* 250ms timer polling for smooth UI updates
* JSON config persistence (HashGUI_Config.json)
* Hash cache with automatic size limiting (max 50,000 entries)
* Windows 10+ toast notification support
* Real-time result streaming for batch and verify operations

Keyboard Shortcuts:
* Ctrl+Enter - Generate hash (from any tab)
* Ctrl+C - Copy selected text to clipboard

Command Line:
* -Portable - Run in portable mode (no config/cache files created)

Author: Dustin W. Deen
GitHub: https://github.com/thestickybullgod/CrunchHash

Enhanced with assistance from GitHub Copilot (December 2025)
"@
$labelAbout.Location = New-Object System.Drawing.Point(20, 20)
$labelAbout.Size = New-Object System.Drawing.Size(520, 3000)
$labelAbout.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$labelAbout.TextAlign = "TopLeft"
$labelAbout.BackColor = [System.Drawing.Color]::Transparent
$labelAbout.AutoSize = $true
$labelAbout.MaximumSize = New-Object System.Drawing.Size(520, 0)

# Create panel with scroll for About tab
$panelAbout = New-Object System.Windows.Forms.Panel
$panelAbout.Location = New-Object System.Drawing.Point(0, 0)
$panelAbout.Size = New-Object System.Drawing.Size(560, 600)
$panelAbout.AutoScroll = $true
$panelAbout.Controls.Add($labelAbout)

# Log Viewer Tab
$textBoxLogViewer = New-Object System.Windows.Forms.TextBox
$textBoxLogViewer.Location = New-Object System.Drawing.Point(20, 20)
$textBoxLogViewer.Size = New-Object System.Drawing.Size(540, 400)
$textBoxLogViewer.Multiline = $true
$textBoxLogViewer.ReadOnly = $true
$textBoxLogViewer.ScrollBars = "Both"
$textBoxLogViewer.WordWrap = $false
$textBoxLogViewer.Font = New-Object System.Drawing.Font("Consolas", 10)
if ((Test-Path $logPath) -and ((Get-Item $logPath).Length -gt 0)) { $textBoxLogViewer.Text = Add-LineNumbers (Get-Content $logPath -Raw) } else { $textBoxLogViewer.Text = "No log entries." }

$buttonRefreshLog = New-Object System.Windows.Forms.Button
$buttonRefreshLog.Text = "Refresh"
$buttonRefreshLog.Location = New-Object System.Drawing.Point(20, 430)
$buttonRefreshLog.Size = New-Object System.Drawing.Size(100, 30)
$buttonRefreshLog.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonRefreshLog.ForeColor = [System.Drawing.Color]::White

$buttonClearLog = New-Object System.Windows.Forms.Button
$buttonClearLog.Text = "Clear Log"
$buttonClearLog.Location = New-Object System.Drawing.Point(130, 430)
$buttonClearLog.Size = New-Object System.Drawing.Size(100, 30)
$buttonClearLog.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonClearLog.ForeColor = [System.Drawing.Color]::White

$buttonOpenLog = New-Object System.Windows.Forms.Button
$buttonOpenLog.Text = "Open in Notepad"
$buttonOpenLog.Location = New-Object System.Drawing.Point(240, 430)
$buttonOpenLog.Size = New-Object System.Drawing.Size(120, 30)
$buttonOpenLog.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonOpenLog.ForeColor = [System.Drawing.Color]::White

# Settings Tab
$timerClipboardDetect = New-Object System.Windows.Forms.Timer
$timerClipboardDetect.Interval = 1000  # 1 second
$timerClipboardDetect.Add_Tick({
    if ($checkClipboardDetect.Checked -and $tabControl.SelectedTab -eq $tabMain) {
        try {
            $clip = [Windows.Forms.Clipboard]::GetText()
            # Accept hex (32, 40, 64 chars), base64 (44+ chars), or common hash formats
            if ($clip -match '^[a-fA-F0-9]{32}$' -or $clip -match '^[a-fA-F0-9]{40}$' -or $clip -match '^[a-fA-F0-9]{64}$' -or $clip -match '^[A-Za-z0-9+/=]{44,}$') {
                if ($textBoxCompare.Text -ne $clip) {
                    $textBoxCompare.Text = $clip
                }
            }
        } catch {}
    }
})
$timerClipboardDetect.Start()
$checkAutoCopy = New-Object System.Windows.Forms.CheckBox
$checkAutoCopy.Text = "Auto-copy generated hash"
$checkAutoCopy.Location = New-Object System.Drawing.Point(20, 20)
$checkAutoCopy.Size = New-Object System.Drawing.Size(220, 20)
$checkAutoCopy.Checked = $true

$checkClipboardDetect = New-Object System.Windows.Forms.CheckBox
$checkClipboardDetect.Text = "Clipboard hash detect"
$checkClipboardDetect.Location = New-Object System.Drawing.Point(250, 20)
$checkClipboardDetect.Size = New-Object System.Drawing.Size(180, 20)
$checkClipboardDetect.Checked = $false
$tooltip.SetToolTip($checkClipboardDetect, "Automatically populate the comparison field when a valid hash is detected in the clipboard.")

$checkDarkMode = New-Object System.Windows.Forms.CheckBox
$checkDarkMode.Text = "Dark Mode"
$checkDarkMode.Location = New-Object System.Drawing.Point(20, 50)
$checkDarkMode.Size = New-Object System.Drawing.Size(200, 20)
$checkDarkMode.Checked = $false

$labelFontSize = New-Object System.Windows.Forms.Label
$labelFontSize.Text = "Output font size:"
$labelFontSize.Location = New-Object System.Drawing.Point(20, 80)
$labelFontSize.Size = New-Object System.Drawing.Size(150, 20)

$numericFontSize = New-Object System.Windows.Forms.NumericUpDown
$numericFontSize.Location = New-Object System.Drawing.Point(180, 78)
$numericFontSize.Size = New-Object System.Drawing.Size(60, 20)
$numericFontSize.Minimum = 8
$numericFontSize.Maximum = 24
$numericFontSize.Value = 12

# Hash Format Options
$labelHashFormat = New-Object System.Windows.Forms.Label
$labelHashFormat.Text = "Hash Output Format:"
$labelHashFormat.Location = New-Object System.Drawing.Point(20, 110)
$labelHashFormat.Size = New-Object System.Drawing.Size(200, 20)

$radioFormatLower = New-Object System.Windows.Forms.RadioButton
$radioFormatLower.Text = "Lowercase (default)"
$radioFormatLower.Location = New-Object System.Drawing.Point(40, 135)
$radioFormatLower.AutoSize = $true
$radioFormatLower.Checked = $true

$radioFormatUpper = New-Object System.Windows.Forms.RadioButton
$radioFormatUpper.Text = "UPPERCASE"
$radioFormatUpper.Location = New-Object System.Drawing.Point(40, 160)
$radioFormatUpper.AutoSize = $true

$radioFormatHex = New-Object System.Windows.Forms.RadioButton
$radioFormatHex.Text = "Hex with 0x prefix"
$radioFormatHex.Location = New-Object System.Drawing.Point(40, 185)
$radioFormatHex.AutoSize = $true

$radioFormatBase64 = New-Object System.Windows.Forms.RadioButton
$radioFormatBase64.Text = "Base64 encoded"
$radioFormatBase64.Location = New-Object System.Drawing.Point(40, 210)
$radioFormatBase64.AutoSize = $true

# Parallel Processing
$labelParallelThreads = New-Object System.Windows.Forms.Label
$labelParallelThreads.Text = "Parallel batch threads (1-8):"
$labelParallelThreads.Location = New-Object System.Drawing.Point(20, 245)
$labelParallelThreads.Size = New-Object System.Drawing.Size(200, 20)

$numericParallelThreads = New-Object System.Windows.Forms.NumericUpDown
$numericParallelThreads.Location = New-Object System.Drawing.Point(220, 243)
$numericParallelThreads.Size = New-Object System.Drawing.Size(60, 20)
$numericParallelThreads.Minimum = 1
$numericParallelThreads.Maximum = 8
$numericParallelThreads.Value = 4

$checkMinimizeToTray = New-Object System.Windows.Forms.CheckBox
$checkMinimizeToTray.Text = "Show system tray icon when minimized"
$checkMinimizeToTray.Location = New-Object System.Drawing.Point(20, 275)
$checkMinimizeToTray.Size = New-Object System.Drawing.Size(400, 20)
$checkMinimizeToTray.Checked = $true

$checkToastNotifications = New-Object System.Windows.Forms.CheckBox
$checkToastNotifications.Text = "Show toast notifications when operations complete"
$checkToastNotifications.Location = New-Object System.Drawing.Point(20, 305)
$checkToastNotifications.Size = New-Object System.Drawing.Size(400, 20)
$checkToastNotifications.Checked = $true

$labelNetworkTimeout = New-Object System.Windows.Forms.Label
$labelNetworkTimeout.Text = "Network path timeout (seconds):"
$labelNetworkTimeout.Location = New-Object System.Drawing.Point(20, 335)
$labelNetworkTimeout.Size = New-Object System.Drawing.Size(200, 20)

$numericNetworkTimeout = New-Object System.Windows.Forms.NumericUpDown
$numericNetworkTimeout.Location = New-Object System.Drawing.Point(220, 333)
$numericNetworkTimeout.Size = New-Object System.Drawing.Size(60, 20)
$numericNetworkTimeout.Minimum = 1
$numericNetworkTimeout.Maximum = 30
$numericNetworkTimeout.Value = 5

$labelPortableMode = New-Object System.Windows.Forms.Label
$labelPortableMode.Text = if ($script:PortableMode) { "WARNING: Portable Mode Enabled (config/cache disabled)" } else { "Portable Mode: Disabled (use -Portable flag)" }
$labelPortableMode.Location = New-Object System.Drawing.Point(20, 365)
$labelPortableMode.Size = New-Object System.Drawing.Size(500, 20)
$labelPortableMode.ForeColor = if ($script:PortableMode) { [System.Drawing.Color]::Orange } else { [System.Drawing.Color]::Gray }

$buttonClearCache = New-Object System.Windows.Forms.Button
$buttonClearCache.Text = "Clear Hash Cache"
$buttonClearCache.Location = New-Object System.Drawing.Point(20, 400)
$buttonClearCache.Size = New-Object System.Drawing.Size(150, 30)
$buttonClearCache.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
$buttonClearCache.ForeColor = [System.Drawing.Color]::White

$buttonVerboseShell = New-Object System.Windows.Forms.Button
$buttonVerboseShell.Text = "Launch Verbose Shell"
$buttonVerboseShell.Location = New-Object System.Drawing.Point(180, 400)
$buttonVerboseShell.Size = New-Object System.Drawing.Size(150, 30)
$buttonVerboseShell.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonVerboseShell.ForeColor = [System.Drawing.Color]::White

# Add controls to Settings Tab
$tabSettings.Controls.Add($checkAutoCopy)
$tabSettings.Controls.Add($checkClipboardDetect)
$tabSettings.Controls.Add($checkDarkMode)
$tabSettings.Controls.Add($labelFontSize)
$tabSettings.Controls.Add($numericFontSize)
$tabSettings.Controls.Add($labelHashFormat)
$tabSettings.Controls.Add($radioFormatLower)
$tabSettings.Controls.Add($radioFormatUpper)
$tabSettings.Controls.Add($radioFormatHex)
$tabSettings.Controls.Add($radioFormatBase64)
$tabSettings.Controls.Add($labelParallelThreads)
$tabSettings.Controls.Add($numericParallelThreads)
$tabSettings.Controls.Add($checkMinimizeToTray)
$tabSettings.Controls.Add($checkToastNotifications)
$tabSettings.Controls.Add($labelNetworkTimeout)
$tabSettings.Controls.Add($numericNetworkTimeout)
$tabSettings.Controls.Add($labelPortableMode)
$tabSettings.Controls.Add($buttonClearCache)
$tabSettings.Controls.Add($buttonVerboseShell)

# Batch Tab Controls
$labelBatchInfo = New-Object System.Windows.Forms.Label
$labelBatchInfo.Text = "Select files to hash:"
$labelBatchInfo.Location = New-Object System.Drawing.Point(20, 10)
$labelBatchInfo.Size = New-Object System.Drawing.Size(150, 20)

$labelBatchAlgo = New-Object System.Windows.Forms.Label
$labelBatchAlgo.Text = "Algorithm:"
$labelBatchAlgo.Location = New-Object System.Drawing.Point(300, 10)
$labelBatchAlgo.Size = New-Object System.Drawing.Size(80, 20)

$comboBatchAlgo = New-Object System.Windows.Forms.ComboBox
$comboBatchAlgo.Location = New-Object System.Drawing.Point(380, 8)
$comboBatchAlgo.Size = New-Object System.Drawing.Size(180, 20)
$comboBatchAlgo.Items.AddRange(@("SHA256", "SHA1", "SHA512", "MD5", "SHA384", "RIPEMD160", "CRC32", "HMACSHA256", "HMACSHA512"))
$comboBatchAlgo.SelectedIndex = 0

$listBoxBatchFiles = New-Object System.Windows.Forms.ListBox
$listBoxBatchFiles.Location = New-Object System.Drawing.Point(20, 35)
$listBoxBatchFiles.Size = New-Object System.Drawing.Size(540, 120)
$listBoxBatchFiles.AllowDrop = $true
$listBoxBatchFiles.SelectionMode = "MultiSimple"
$listBoxBatchFiles.HorizontalScrollbar = $true

$checkBatchRecursive = New-Object System.Windows.Forms.CheckBox
$checkBatchRecursive.Text = "Recursive"
$checkBatchRecursive.Location = New-Object System.Drawing.Point(20, 162)
$checkBatchRecursive.Size = New-Object System.Drawing.Size(100, 20)
$checkBatchRecursive.Checked = $false
$checkBatchRecursive.ForeColor = [System.Drawing.Color]::White

$labelBatchKey = New-Object System.Windows.Forms.Label
$labelBatchKey.Text = "HMAC Key:"
$labelBatchKey.Location = New-Object System.Drawing.Point(130, 162)
$labelBatchKey.Size = New-Object System.Drawing.Size(80, 20)
$labelBatchKey.Visible = $true

$textBoxBatchKey = New-Object System.Windows.Forms.TextBox
$textBoxBatchKey.Location = New-Object System.Drawing.Point(210, 160)
$textBoxBatchKey.Size = New-Object System.Drawing.Size(350, 20)
$textBoxBatchKey.UseSystemPasswordChar = $true
$textBoxBatchKey.Visible = $true
$textBoxBatchKey.Enabled = $false
$textBoxBatchKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$textBoxBatchKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)

$buttonBatchAdd = New-Object System.Windows.Forms.Button
$buttonBatchAdd.Text = "Browse"
$buttonBatchAdd.Location = New-Object System.Drawing.Point(20, 188)
$buttonBatchAdd.Size = New-Object System.Drawing.Size(100, 30)
$buttonBatchAdd.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonBatchAdd.ForeColor = [System.Drawing.Color]::White

$buttonBatchRemove = New-Object System.Windows.Forms.Button
$buttonBatchRemove.Text = "Remove Selected"
$buttonBatchRemove.Location = New-Object System.Drawing.Point(130, 188)
$buttonBatchRemove.Size = New-Object System.Drawing.Size(120, 30)
$buttonBatchRemove.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonBatchRemove.ForeColor = [System.Drawing.Color]::White

$buttonBatchHash = New-Object System.Windows.Forms.Button
$buttonBatchHash.Text = "Hash All"
$buttonBatchHash.Location = New-Object System.Drawing.Point(260, 188)
$buttonBatchHash.Size = New-Object System.Drawing.Size(100, 30)
$buttonBatchHash.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$buttonBatchHash.ForeColor = [System.Drawing.Color]::White

$buttonBatchClear = New-Object System.Windows.Forms.Button
$buttonBatchClear.Text = "Clear All"
$buttonBatchClear.Location = New-Object System.Drawing.Point(370, 188)
$buttonBatchClear.Size = New-Object System.Drawing.Size(100, 30)
$buttonBatchClear.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonBatchClear.ForeColor = [System.Drawing.Color]::White

$buttonBatchStop = New-Object System.Windows.Forms.Button
$buttonBatchStop.Text = "Stop"
$buttonBatchStop.Location = New-Object System.Drawing.Point(470, 188)
$buttonBatchStop.Size = New-Object System.Drawing.Size(90, 30)
$buttonBatchStop.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonBatchStop.ForeColor = [System.Drawing.Color]::White
$buttonBatchStop.Enabled = $false
$buttonBatchStop.Visible = $false

$buttonBatchPause = New-Object System.Windows.Forms.Button
$buttonBatchPause.Text = "Pause"
$buttonBatchPause.Location = New-Object System.Drawing.Point(370, 188)
$buttonBatchPause.Size = New-Object System.Drawing.Size(90, 30)
$buttonBatchPause.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
$buttonBatchPause.ForeColor = [System.Drawing.Color]::Black
$buttonBatchPause.Enabled = $false
$buttonBatchPause.Visible = $false

$textBoxBatchResults = New-Object System.Windows.Forms.RichTextBox
$textBoxBatchResults.Location = New-Object System.Drawing.Point(20, 228)
$textBoxBatchResults.Size = New-Object System.Drawing.Size(540, 255)
$textBoxBatchResults.ReadOnly = $true
$textBoxBatchResults.ScrollBars = "Both"
$textBoxBatchResults.Font = New-Object System.Drawing.Font("Consolas", 9)
$textBoxBatchResults.WordWrap = $false
$textBoxBatchResults.DetectUrls = $false

# Create context menu for Batch results
$contextMenuBatchResults = New-Object System.Windows.Forms.ContextMenuStrip
$menuItemBatchCopy = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemBatchCopy.Text = "Copy"
$menuItemBatchCopy.Add_Click({
    if ($textBoxBatchResults.SelectionLength -gt 0) {
        [System.Windows.Forms.Clipboard]::SetText($textBoxBatchResults.SelectedText)
    } elseif ($textBoxBatchResults.Text.Length -gt 0) {
        [System.Windows.Forms.Clipboard]::SetText($textBoxBatchResults.Text)
    }
})
[void]$contextMenuBatchResults.Items.Add($menuItemBatchCopy)

# Only show context menu when paused, stopped, or completed
$textBoxBatchResults.Add_MouseUp({
    param($sender, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) {
        # Enable context menu only when not running or when paused
        if (-not $script:batchJobId -or $script:batchShouldPause) {
            $contextMenuBatchResults.Show($textBoxBatchResults, $e.Location)
        }
    }
})

# Block user interaction during batch operation - keep cursor as arrow and prevent selection
$textBoxBatchResults.Add_MouseMove({
    param($sender, $e)
    if ($script:batchJobId -and -not $script:batchShouldPause) {
        $textBoxBatchResults.Cursor = [System.Windows.Forms.Cursors]::Default
        # Continuously clear selection during mouse movement
        if ($textBoxBatchResults.SelectionLength -gt 0) {
            $textBoxBatchResults.SelectionLength = 0
        }
    }
})

$textBoxBatchResults.Add_MouseDown({
    param($sender, $e)
    if ($script:batchJobId -and -not $script:batchShouldPause) {
        # Prevent mouse down from initiating selection
        $textBoxBatchResults.SelectionLength = 0
    }
})

$textBoxBatchResults.Add_KeyDown({
    param($sender, $e)
    if ($script:batchJobId -and -not $script:batchShouldPause) {
        # Block keyboard-based selection (Ctrl+A, Shift+arrows, etc.)
        if ($e.Control -or $e.Shift) {
            $e.SuppressKeyPress = $true
            $e.Handled = $true
        }
    }
})

$textBoxBatchResults.Add_SelectionChanged({
    if ($script:batchJobId -and -not $script:batchShouldPause) {
        # Clear any selection made during batch operation
        $textBoxBatchResults.SelectionLength = 0
    }
})

# File Progress Bar (for individual file hashing)
$labelBatchFileProgress = New-Object System.Windows.Forms.Label
$labelBatchFileProgress.Text = "File Progress:"
$labelBatchFileProgress.Location = New-Object System.Drawing.Point(20, 490)
$labelBatchFileProgress.Size = New-Object System.Drawing.Size(80, 15)
$labelBatchFileProgress.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$labelBatchFileProgress.ForeColor = [System.Drawing.Color]::DarkSlateGray

$labelBatchFilePercent = New-Object System.Windows.Forms.Label
$labelBatchFilePercent.Text = "0%"
$labelBatchFilePercent.Location = New-Object System.Drawing.Point(400, 490)
$labelBatchFilePercent.Size = New-Object System.Drawing.Size(160, 15)
$labelBatchFilePercent.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$labelBatchFilePercent.ForeColor = [System.Drawing.Color]::DarkSlateGray
$labelBatchFilePercent.TextAlign = "MiddleRight"

$panelBatchFileProgressBackground = New-Object System.Windows.Forms.Panel
$panelBatchFileProgressBackground.Location = New-Object System.Drawing.Point(20, 508)
$panelBatchFileProgressBackground.Size = New-Object System.Drawing.Size(540, 10)
$panelBatchFileProgressBackground.BackColor = [System.Drawing.Color]::LightGray
$panelBatchFileProgressBackground.BorderStyle = 'FixedSingle'

$panelBatchFileProgressFill = New-Object System.Windows.Forms.Panel
$panelBatchFileProgressFill.Location = New-Object System.Drawing.Point(0, 0)
$panelBatchFileProgressFill.Size = New-Object System.Drawing.Size(0, 10)
$panelBatchFileProgressFill.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$panelBatchFileProgressBackground.Controls.Add($panelBatchFileProgressFill)

# Batch Progress Bar (for overall batch completion)
$labelBatchOverallProgress = New-Object System.Windows.Forms.Label
$labelBatchOverallProgress.Text = "Batch Progress:"
$labelBatchOverallProgress.Location = New-Object System.Drawing.Point(20, 525)
$labelBatchOverallProgress.Size = New-Object System.Drawing.Size(90, 15)
$labelBatchOverallProgress.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$labelBatchOverallProgress.ForeColor = [System.Drawing.Color]::DarkSlateGray

$labelBatchOverallPercent = New-Object System.Windows.Forms.Label
$labelBatchOverallPercent.Text = "0%"
$labelBatchOverallPercent.Location = New-Object System.Drawing.Point(510, 525)
$labelBatchOverallPercent.Size = New-Object System.Drawing.Size(50, 15)
$labelBatchOverallPercent.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$labelBatchOverallPercent.ForeColor = [System.Drawing.Color]::DarkSlateGray
$labelBatchOverallPercent.TextAlign = "MiddleRight"

$panelBatchProgressBackground = New-Object System.Windows.Forms.Panel
$panelBatchProgressBackground.Location = New-Object System.Drawing.Point(20, 543)
$panelBatchProgressBackground.Size = New-Object System.Drawing.Size(540, 10)
$panelBatchProgressBackground.BackColor = [System.Drawing.Color]::LightGray
$panelBatchProgressBackground.BorderStyle = 'FixedSingle'

$panelBatchProgressFill = New-Object System.Windows.Forms.Panel
$panelBatchProgressFill.Location = New-Object System.Drawing.Point(0, 0)
$panelBatchProgressFill.Size = New-Object System.Drawing.Size(0, 10)
$panelBatchProgressFill.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$panelBatchProgressBackground.Controls.Add($panelBatchProgressFill)

$buttonBatchCopyResults = New-Object System.Windows.Forms.Button
$buttonBatchCopyResults.Text = "Copy Results"
$buttonBatchCopyResults.Location = New-Object System.Drawing.Point(20, 560)
$buttonBatchCopyResults.Size = New-Object System.Drawing.Size(100, 30)
$buttonBatchCopyResults.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonBatchCopyResults.ForeColor = [System.Drawing.Color]::White

$buttonBatchExport = New-Object System.Windows.Forms.Button
$buttonBatchExport.Text = "Export TXT/CSV..."
$buttonBatchExport.Location = New-Object System.Drawing.Point(130, 560)
$buttonBatchExport.Size = New-Object System.Drawing.Size(130, 30)
$buttonBatchExport.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$buttonBatchExport.ForeColor = [System.Drawing.Color]::White

$buttonExportHashCheck = New-Object System.Windows.Forms.Button
$buttonExportHashCheck.Text = "HashCheck"
$buttonExportHashCheck.Location = New-Object System.Drawing.Point(270, 560)
$buttonExportHashCheck.Size = New-Object System.Drawing.Size(80, 30)
$buttonExportHashCheck.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$buttonExportHashCheck.ForeColor = [System.Drawing.Color]::White

$buttonExportSFV = New-Object System.Windows.Forms.Button
$buttonExportSFV.Text = "SFV"
$buttonExportSFV.Location = New-Object System.Drawing.Point(360, 560)
$buttonExportSFV.Size = New-Object System.Drawing.Size(60, 30)
$buttonExportSFV.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$buttonExportSFV.ForeColor = [System.Drawing.Color]::White

$buttonExportVerifyLog = New-Object System.Windows.Forms.Button
$buttonExportVerifyLog.Text = "Verify Log"
$buttonExportVerifyLog.Location = New-Object System.Drawing.Point(430, 560)
$buttonExportVerifyLog.Size = New-Object System.Drawing.Size(80, 30)
$buttonExportVerifyLog.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$buttonExportVerifyLog.ForeColor = [System.Drawing.Color]::White

$checkBatchLog = New-Object System.Windows.Forms.CheckBox
$checkBatchLog.Text = "Log to file"
$checkBatchLog.Location = New-Object System.Drawing.Point(20, 597)
$checkBatchLog.AutoSize = $true

$labelBatchFooter = New-Object System.Windows.Forms.Label
$labelBatchFooter.Text = "Ready"
$labelBatchFooter.Location = New-Object System.Drawing.Point(120, 597)
$labelBatchFooter.Size = New-Object System.Drawing.Size(440, 20)
$labelBatchFooter.TextAlign = "MiddleLeft"
$labelBatchFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray
$labelBatchFooter.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Loading spinner for folder enumeration
$script:batchLoadingSpinner = New-Object System.Windows.Forms.PictureBox
$script:batchLoadingSpinner.Location = New-Object System.Drawing.Point(535, 595)
$script:batchLoadingSpinner.Size = New-Object System.Drawing.Size(24, 24)
$script:batchLoadingSpinner.Visible = $false
$script:batchLoadingSpinner.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::CenterImage
$script:spinnerRotation = 0

# Timer for spinner animation
$script:spinnerTimer = New-Object System.Windows.Forms.Timer
$script:spinnerTimer.Interval = 50  # 50ms = 20 FPS
$script:spinnerTimer.Add_Tick({
    if ($script:batchLoadingSpinner.Visible) {
        $script:spinnerRotation = ($script:spinnerRotation + 30) % 360

        # Create bitmap for spinner
        $bmp = New-Object System.Drawing.Bitmap(24, 24)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

        # Translate to center and rotate
        $g.TranslateTransform(12, 12)
        $g.RotateTransform($script:spinnerRotation)

        # Draw spinning arc (green color)
        $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::LimeGreen, 3)
        $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
        $g.DrawArc($pen, -8, -8, 16, 16, 0, 270)

        $pen.Dispose()
        $g.Dispose()

        $script:batchLoadingSpinner.Image = $bmp
    }
})

$tabBatch.Controls.Add($labelBatchInfo)
$tabBatch.Controls.Add($labelBatchAlgo)
$tabBatch.Controls.Add($comboBatchAlgo)
$tabBatch.Controls.Add($listBoxBatchFiles)
$tabBatch.Controls.Add($checkBatchRecursive)
$tabBatch.Controls.Add($labelBatchKey)
$tabBatch.Controls.Add($textBoxBatchKey)
$tabBatch.Controls.Add($buttonBatchAdd)
$tabBatch.Controls.Add($buttonBatchRemove)
$tabBatch.Controls.Add($buttonBatchHash)
$tabBatch.Controls.Add($buttonBatchClear)
$tabBatch.Controls.Add($buttonBatchStop)
$tabBatch.Controls.Add($buttonBatchPause)
$tabBatch.Controls.Add($buttonBatchCopyResults)
$tabBatch.Controls.Add($buttonBatchExport)
$tabBatch.Controls.Add($buttonExportHashCheck)
$tabBatch.Controls.Add($buttonExportSFV)
$tabBatch.Controls.Add($buttonExportVerifyLog)
$tabBatch.Controls.Add($checkBatchLog)
$tabBatch.Controls.Add($textBoxBatchResults)
$tabBatch.Controls.Add($labelBatchFileProgress)
$tabBatch.Controls.Add($labelBatchFilePercent)
$tabBatch.Controls.Add($panelBatchFileProgressBackground)
$tabBatch.Controls.Add($labelBatchOverallProgress)
$tabBatch.Controls.Add($labelBatchOverallPercent)
$tabBatch.Controls.Add($panelBatchProgressBackground)
$tabBatch.Controls.Add($labelBatchFooter)
$tabBatch.Controls.Add($script:batchLoadingSpinner)

# Batch Log Viewer Tab
$textBoxBatchLogViewer = New-Object System.Windows.Forms.TextBox
$textBoxBatchLogViewer.Location = New-Object System.Drawing.Point(20, 20)
$textBoxBatchLogViewer.Size = New-Object System.Drawing.Size(540, 400)
$textBoxBatchLogViewer.Multiline = $true
$textBoxBatchLogViewer.ReadOnly = $true
$textBoxBatchLogViewer.ScrollBars = "Both"
$textBoxBatchLogViewer.WordWrap = $false
$textBoxBatchLogViewer.Font = New-Object System.Drawing.Font("Consolas", 10)
if ((Test-Path $batchLogPath) -and ((Get-Item $batchLogPath).Length -gt 0)) { $textBoxBatchLogViewer.Text = Add-LineNumbers (Get-Content $batchLogPath -Raw) } else { $textBoxBatchLogViewer.Text = "No batch log entries." }

$buttonRefreshBatchLog = New-Object System.Windows.Forms.Button
$buttonRefreshBatchLog.Text = "Refresh"
$buttonRefreshBatchLog.Location = New-Object System.Drawing.Point(20, 430)
$buttonRefreshBatchLog.Size = New-Object System.Drawing.Size(100, 30)
$buttonRefreshBatchLog.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonRefreshBatchLog.ForeColor = [System.Drawing.Color]::White

$buttonClearBatchLog = New-Object System.Windows.Forms.Button
$buttonClearBatchLog.Text = "Clear Log"
$buttonClearBatchLog.Location = New-Object System.Drawing.Point(130, 430)
$buttonClearBatchLog.Size = New-Object System.Drawing.Size(100, 30)
$buttonClearBatchLog.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonClearBatchLog.ForeColor = [System.Drawing.Color]::White

$buttonOpenBatchLog = New-Object System.Windows.Forms.Button
$buttonOpenBatchLog.Text = "Open in Notepad"
$buttonOpenBatchLog.Location = New-Object System.Drawing.Point(240, 430)
$buttonOpenBatchLog.Size = New-Object System.Drawing.Size(120, 30)
$buttonOpenBatchLog.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonOpenBatchLog.ForeColor = [System.Drawing.Color]::White

$tabBatchLogViewer.Controls.Add($textBoxBatchLogViewer)
$tabBatchLogViewer.Controls.Add($buttonRefreshBatchLog)
$tabBatchLogViewer.Controls.Add($buttonClearBatchLog)
$tabBatchLogViewer.Controls.Add($buttonOpenBatchLog)

# Recent Files Tab
$labelRecentInfo = New-Object System.Windows.Forms.Label
$labelRecentInfo.Text = "Recently hashed files (most recent first):"
$labelRecentInfo.Location = New-Object System.Drawing.Point(20, 10)
$labelRecentInfo.Size = New-Object System.Drawing.Size(540, 20)

$listBoxRecentFiles = New-Object System.Windows.Forms.ListBox
$listBoxRecentFiles.Location = New-Object System.Drawing.Point(20, 35)
$listBoxRecentFiles.Size = New-Object System.Drawing.Size(540, 400)
$listBoxRecentFiles.Font = New-Object System.Drawing.Font("Consolas", 9)
$listBoxRecentFiles.SelectionMode = "MultiSimple"
$listBoxRecentFiles.HorizontalScrollbar = $true
$listBoxRecentFiles.ScrollAlwaysVisible = $true

$buttonRecentHash = New-Object System.Windows.Forms.Button
$buttonRecentHash.Text = "Re-Hash Selected"
$buttonRecentHash.Location = New-Object System.Drawing.Point(20, 445)
$buttonRecentHash.Size = New-Object System.Drawing.Size(120, 30)
$buttonRecentHash.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonRecentHash.ForeColor = [System.Drawing.Color]::White
$buttonRecentHash.Enabled = $false

$buttonRecentBatch = New-Object System.Windows.Forms.Button
$buttonRecentBatch.Text = "Re-Hash Selected (Batch)"
$buttonRecentBatch.Location = New-Object System.Drawing.Point(150, 445)
$buttonRecentBatch.Size = New-Object System.Drawing.Size(170, 30)
$buttonRecentBatch.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonRecentBatch.ForeColor = [System.Drawing.Color]::White
$buttonRecentBatch.Enabled = $false

$buttonRecentClear = New-Object System.Windows.Forms.Button
$buttonRecentClear.Text = "Clear List"
$buttonRecentClear.Location = New-Object System.Drawing.Point(330, 445)
$buttonRecentClear.Size = New-Object System.Drawing.Size(100, 30)
$buttonRecentClear.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonRecentClear.ForeColor = [System.Drawing.Color]::White

$buttonRecentRefresh = New-Object System.Windows.Forms.Button
$buttonRecentRefresh.Text = "Refresh"
$buttonRecentRefresh.Location = New-Object System.Drawing.Point(440, 445)
$buttonRecentRefresh.Size = New-Object System.Drawing.Size(100, 30)
$buttonRecentRefresh.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonRecentRefresh.ForeColor = [System.Drawing.Color]::White

$tabRecentFiles.Controls.Add($labelRecentInfo)
$tabRecentFiles.Controls.Add($listBoxRecentFiles)
$tabRecentFiles.Controls.Add($buttonRecentHash)
$tabRecentFiles.Controls.Add($buttonRecentBatch)
$tabRecentFiles.Controls.Add($buttonRecentClear)
$tabRecentFiles.Controls.Add($buttonRecentRefresh)

# Verify Tab
$labelVerifyInfo = New-Object System.Windows.Forms.Label
$labelVerifyInfo.Text = "Paste hash list (format: hash<tab>filename or hash<space>filename):"
$labelVerifyInfo.Location = New-Object System.Drawing.Point(20, 10)
$labelVerifyInfo.Size = New-Object System.Drawing.Size(540, 20)

$textBoxVerifyInput = New-Object System.Windows.Forms.TextBox
$textBoxVerifyInput.Location = New-Object System.Drawing.Point(20, 35)
$textBoxVerifyInput.Size = New-Object System.Drawing.Size(540, 150)
$textBoxVerifyInput.Multiline = $true
$textBoxVerifyInput.ScrollBars = "Both"
$textBoxVerifyInput.Font = New-Object System.Drawing.Font("Consolas", 9)
$textBoxVerifyInput.WordWrap = $false
$textBoxVerifyInput.AcceptsTab = $true

$labelVerifyAlgo = New-Object System.Windows.Forms.Label
$labelVerifyAlgo.Text = "Algorithm:"
$labelVerifyAlgo.Location = New-Object System.Drawing.Point(20, 195)
$labelVerifyAlgo.Size = New-Object System.Drawing.Size(80, 20)

$comboVerifyAlgo = New-Object System.Windows.Forms.ComboBox
$comboVerifyAlgo.Location = New-Object System.Drawing.Point(100, 193)
$comboVerifyAlgo.Size = New-Object System.Drawing.Size(180, 20)
$comboVerifyAlgo.Items.AddRange(@("SHA256", "SHA1", "SHA512", "MD5", "SHA384", "RIPEMD160", "CRC32", "HMACSHA256", "HMACSHA512"))
$comboVerifyAlgo.SelectedIndex = 0
$tooltip.SetToolTip($comboVerifyAlgo, "Select the hash algorithm used to generate the hashes in your list. This must match the algorithm that was originally used to create the hashes. For HMAC algorithms, you'll need to provide the key.")

$labelVerifyKey = New-Object System.Windows.Forms.Label
$labelVerifyKey.Text = "HMAC Key:"
$labelVerifyKey.Location = New-Object System.Drawing.Point(20, 225)
$labelVerifyKey.Size = New-Object System.Drawing.Size(80, 20)
$labelVerifyKey.Visible = $true

$textBoxVerifyKey = New-Object System.Windows.Forms.TextBox
$textBoxVerifyKey.Location = New-Object System.Drawing.Point(100, 223)
$textBoxVerifyKey.Size = New-Object System.Drawing.Size(460, 20)
$textBoxVerifyKey.UseSystemPasswordChar = $true
$textBoxVerifyKey.Visible = $true
$textBoxVerifyKey.Enabled = $false
$textBoxVerifyKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$textBoxVerifyKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)

$labelVerifyBasePath = New-Object System.Windows.Forms.Label
$labelVerifyBasePath.Text = "Base directory (optional):"
$labelVerifyBasePath.Location = New-Object System.Drawing.Point(20, 253)
$labelVerifyBasePath.Size = New-Object System.Drawing.Size(180, 20)

$textBoxVerifyBasePath = New-Object System.Windows.Forms.TextBox
$textBoxVerifyBasePath.Location = New-Object System.Drawing.Point(20, 278)
$textBoxVerifyBasePath.Size = New-Object System.Drawing.Size(460, 20)

$buttonVerifyBrowse = New-Object System.Windows.Forms.Button
$buttonVerifyBrowse.Text = "..."
$buttonVerifyBrowse.Location = New-Object System.Drawing.Point(490, 276)
$buttonVerifyBrowse.Size = New-Object System.Drawing.Size(70, 25)
$buttonVerifyBrowse.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonVerifyBrowse.ForeColor = [System.Drawing.Color]::White

$buttonVerify = New-Object System.Windows.Forms.Button
$buttonVerify.Text = "Verify All"
$buttonVerify.Location = New-Object System.Drawing.Point(20, 313)
$buttonVerify.Size = New-Object System.Drawing.Size(100, 30)
$buttonVerify.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$buttonVerify.ForeColor = [System.Drawing.Color]::White

$buttonVerifyClear = New-Object System.Windows.Forms.Button
$buttonVerifyClear.Text = "Clear"
$buttonVerifyClear.Location = New-Object System.Drawing.Point(130, 313)
$buttonVerifyClear.Size = New-Object System.Drawing.Size(80, 30)
$buttonVerifyClear.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonVerifyClear.ForeColor = [System.Drawing.Color]::White

$buttonImportBatchLog = New-Object System.Windows.Forms.Button
$buttonImportBatchLog.Text = "Import Batch Log..."
$buttonImportBatchLog.Location = New-Object System.Drawing.Point(220, 313)
$buttonImportBatchLog.Size = New-Object System.Drawing.Size(140, 30)
$buttonImportBatchLog.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonImportBatchLog.ForeColor = [System.Drawing.Color]::White

# Add dropdown for verify format selection (right of Import Batch Log)
$comboVerifyFormat = New-Object System.Windows.Forms.ComboBox
$comboVerifyFormat.Location = New-Object System.Drawing.Point(370, 313)
$comboVerifyFormat.Size = New-Object System.Drawing.Size(130, 30)
$comboVerifyFormat.DropDownStyle = 'DropDownList'
$comboVerifyFormat.Items.AddRange(@("lowercase", "uppercase", "hex", "base64"))
$comboVerifyFormat.SelectedIndex = 0

$textBoxVerifyResults = New-Object System.Windows.Forms.RichTextBox
$textBoxVerifyResults.Location = New-Object System.Drawing.Point(20, 353)
$textBoxVerifyResults.Size = New-Object System.Drawing.Size(540, 185)
$textBoxVerifyResults.ReadOnly = $true
$textBoxVerifyResults.ScrollBars = "Both"
$textBoxVerifyResults.Font = New-Object System.Drawing.Font("Consolas", 9)
$textBoxVerifyResults.WordWrap = $false
$textBoxVerifyResults.DetectUrls = $false

# Create context menu for Verify results
$contextMenuVerifyResults = New-Object System.Windows.Forms.ContextMenuStrip
$menuItemVerifyCopy = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemVerifyCopy.Text = "Copy"
$menuItemVerifyCopy.Add_Click({
    if ($textBoxVerifyResults.SelectionLength -gt 0) {
        [System.Windows.Forms.Clipboard]::SetText($textBoxVerifyResults.SelectedText)
    } elseif ($textBoxVerifyResults.Text.Length -gt 0) {
        [System.Windows.Forms.Clipboard]::SetText($textBoxVerifyResults.Text)
    }
})
[void]$contextMenuVerifyResults.Items.Add($menuItemVerifyCopy)

# Only show context menu when paused, stopped, or completed
$textBoxVerifyResults.Add_MouseUp({
    param($sender, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) {
        # Enable context menu only when not running or when paused
        if (-not $script:verifyRunning -or $script:verifyShouldPause) {
            $contextMenuVerifyResults.Show($textBoxVerifyResults, $e.Location)
        }
    }
})

# Block user interaction during verification - keep cursor as arrow and prevent selection
$textBoxVerifyResults.Add_MouseMove({
    param($sender, $e)
    if ($script:verifyRunning -and -not $script:verifyShouldPause) {
        $textBoxVerifyResults.Cursor = [System.Windows.Forms.Cursors]::Default
        # Continuously clear selection during mouse movement
        if ($textBoxVerifyResults.SelectionLength -gt 0) {
            $textBoxVerifyResults.SelectionLength = 0
        }
    }
})

$textBoxVerifyResults.Add_MouseDown({
    param($sender, $e)
    if ($script:verifyRunning -and -not $script:verifyShouldPause) {
        # Prevent mouse down from initiating selection
        $textBoxVerifyResults.SelectionLength = 0
    }
})

$textBoxVerifyResults.Add_KeyDown({
    param($sender, $e)
    if ($script:verifyRunning -and -not $script:verifyShouldPause) {
        # Block keyboard-based selection (Ctrl+A, Shift+arrows, etc.)
        if ($e.Control -or $e.Shift) {
            $e.SuppressKeyPress = $true
            $e.Handled = $true
        }
    }
})

$textBoxVerifyResults.Add_SelectionChanged({
    if ($script:verifyRunning -and -not $script:verifyShouldPause) {
        # Clear any selection made during verification
        $textBoxVerifyResults.SelectionLength = 0
    }
})

$labelVerifyProgressLabel = New-Object System.Windows.Forms.Label
$labelVerifyProgressLabel.Text = "Progress:"
$labelVerifyProgressLabel.Location = New-Object System.Drawing.Point(20, 542)
$labelVerifyProgressLabel.Size = New-Object System.Drawing.Size(60, 15)
$labelVerifyProgressLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)

$panelVerifyProgressBackground = New-Object System.Windows.Forms.Panel
$panelVerifyProgressBackground.Location = New-Object System.Drawing.Point(20, 560)
$panelVerifyProgressBackground.Size = New-Object System.Drawing.Size(540, 18)
$panelVerifyProgressBackground.BackColor = [System.Drawing.Color]::DarkGray
$panelVerifyProgressBackground.BorderStyle = 'FixedSingle'
$panelVerifyProgressBackground.Visible = $true

$panelVerifyProgressFill = New-Object System.Windows.Forms.Panel
$panelVerifyProgressFill.Location = New-Object System.Drawing.Point(0, 0)
$panelVerifyProgressFill.Size = New-Object System.Drawing.Size(0, 18)
$panelVerifyProgressFill.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$panelVerifyProgressFill.Visible = $true
$panelVerifyProgressFill.Anchor = 'Top,Left'
$panelVerifyProgressBackground.Controls.Add($panelVerifyProgressFill)

$buttonVerifyStop = New-Object System.Windows.Forms.Button
$buttonVerifyStop.Text = "Stop"
$buttonVerifyStop.Location = New-Object System.Drawing.Point(20, 583)
$buttonVerifyStop.Size = New-Object System.Drawing.Size(80, 25)
$buttonVerifyStop.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
$buttonVerifyStop.ForeColor = [System.Drawing.Color]::White
$buttonVerifyStop.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$buttonVerifyStop.Enabled = $false

$buttonVerifyPause = New-Object System.Windows.Forms.Button
$buttonVerifyPause.Text = "Pause"
$buttonVerifyPause.Location = New-Object System.Drawing.Point(110, 583)
$buttonVerifyPause.Size = New-Object System.Drawing.Size(80, 25)
$buttonVerifyPause.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
$buttonVerifyPause.ForeColor = [System.Drawing.Color]::Black
$buttonVerifyPause.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$buttonVerifyPause.Enabled = $false

$labelVerifyFooter = New-Object System.Windows.Forms.Label
$labelVerifyFooter.Text = "Ready"
$labelVerifyFooter.Location = New-Object System.Drawing.Point(200, 583)
$labelVerifyFooter.Size = New-Object System.Drawing.Size(360, 20)
$labelVerifyFooter.TextAlign = "MiddleRight"
$labelVerifyFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray
$labelVerifyFooter.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$tabVerify.Controls.Add($labelVerifyInfo)
$tabVerify.Controls.Add($textBoxVerifyInput)
$tabVerify.Controls.Add($labelVerifyAlgo)
$tabVerify.Controls.Add($comboVerifyAlgo)
$tabVerify.Controls.Add($labelVerifyKey)
$tabVerify.Controls.Add($textBoxVerifyKey)
$tabVerify.Controls.Add($labelVerifyBasePath)
$tabVerify.Controls.Add($textBoxVerifyBasePath)
$tabVerify.Controls.Add($buttonVerifyBrowse)
$tabVerify.Controls.Add($buttonVerify)
$tabVerify.Controls.Add($buttonVerifyClear)
$tabVerify.Controls.Add($buttonImportBatchLog)
$tabVerify.Controls.Add($comboVerifyFormat)
$tooltip.SetToolTip($comboVerifyFormat, "Select the hash format to use for verification. This must match the format of the hashes in your imported list (lowercase, uppercase, hex, or base64).")
$tabVerify.Controls.Add($textBoxVerifyResults)
$tabVerify.Controls.Add($labelVerifyProgressLabel)
$tabVerify.Controls.Add($panelVerifyProgressBackground)
$tabVerify.Controls.Add($buttonVerifyStop)
$tabVerify.Controls.Add($buttonVerifyPause)
$tabVerify.Controls.Add($labelVerifyFooter)
$labelVerifyProgressLabel.BringToFront()
$panelVerifyProgressBackground.BringToFront()
$buttonVerifyStop.BringToFront()
$labelVerifyFooter.BringToFront()

# Duplicate Finder Tab Controls
$labelDupInfo = New-Object System.Windows.Forms.Label
$labelDupInfo.Text = "Select directories to search for duplicate files:"
$labelDupInfo.Location = New-Object System.Drawing.Point(20, 10)
$labelDupInfo.Size = New-Object System.Drawing.Size(300, 20)

$listBoxDupPaths = New-Object System.Windows.Forms.ListBox
$listBoxDupPaths.Location = New-Object System.Drawing.Point(20, 35)
$listBoxDupPaths.Size = New-Object System.Drawing.Size(430, 60)
$listBoxDupPaths.SelectionMode = 'MultiExtended'
$listBoxDupPaths.HorizontalScrollbar = $true

$buttonDupAddFolder = New-Object System.Windows.Forms.Button
$buttonDupAddFolder.Text = "Add Folder"
$buttonDupAddFolder.Location = New-Object System.Drawing.Point(460, 35)
$buttonDupAddFolder.Size = New-Object System.Drawing.Size(100, 25)
$buttonDupAddFolder.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonDupAddFolder.ForeColor = [System.Drawing.Color]::White

$buttonDupRemoveFolder = New-Object System.Windows.Forms.Button
$buttonDupRemoveFolder.Text = "Remove"
$buttonDupRemoveFolder.Location = New-Object System.Drawing.Point(460, 65)
$buttonDupRemoveFolder.Size = New-Object System.Drawing.Size(100, 25)
$buttonDupRemoveFolder.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
$buttonDupRemoveFolder.ForeColor = [System.Drawing.Color]::White

$checkDupRecursive = New-Object System.Windows.Forms.CheckBox
$checkDupRecursive.Text = "Search subdirectories (Recursive)"
$checkDupRecursive.Location = New-Object System.Drawing.Point(20, 107)
$checkDupRecursive.AutoSize = $true
$checkDupRecursive.Checked = $true

$labelDupAlgo = New-Object System.Windows.Forms.Label
$labelDupAlgo.Text = "Algorithm:"
$labelDupAlgo.Location = New-Object System.Drawing.Point(340, 109)
$labelDupAlgo.Size = New-Object System.Drawing.Size(70, 20)

$comboDupAlgo = New-Object System.Windows.Forms.ComboBox
$comboDupAlgo.Location = New-Object System.Drawing.Point(410, 107)
$comboDupAlgo.Size = New-Object System.Drawing.Size(100, 20)
$comboDupAlgo.Items.AddRange(@("MD5", "SHA1", "SHA256", "SHA384", "SHA512", "RIPEMD160", "CRC32"))
$comboDupAlgo.SelectedIndex = 0
$comboDupAlgo.DropDownStyle = 'DropDownList'

$labelDupExtensions = New-Object System.Windows.Forms.Label
$labelDupExtensions.Text = "Extensions:"
$labelDupExtensions.Location = New-Object System.Drawing.Point(20, 140)
$labelDupExtensions.Size = New-Object System.Drawing.Size(65, 20)

$textBoxDupExtensions = New-Object System.Windows.Forms.TextBox
$textBoxDupExtensions.Location = New-Object System.Drawing.Point(90, 138)
$textBoxDupExtensions.Size = New-Object System.Drawing.Size(300, 20)
$textBoxDupExtensions.ForeColor = [System.Drawing.Color]::Gray
$textBoxDupExtensions.Text = "*.jpg,*.png (optional)"

# Clear placeholder on focus
$textBoxDupExtensions.Add_GotFocus({
    if ($textBoxDupExtensions.Text -eq "*.jpg,*.png (optional)" -and $textBoxDupExtensions.ForeColor -eq [System.Drawing.Color]::Gray) {
        $textBoxDupExtensions.Text = ""
        $textBoxDupExtensions.ForeColor = [System.Drawing.Color]::Black
    }
})

# Restore placeholder if empty
$textBoxDupExtensions.Add_LostFocus({
    if ($textBoxDupExtensions.Text.Trim() -eq "") {
        $textBoxDupExtensions.Text = "*.jpg,*.png (optional)"
        $textBoxDupExtensions.ForeColor = [System.Drawing.Color]::Gray
    }
})

$buttonDupFind = New-Object System.Windows.Forms.Button
$buttonDupFind.Text = "Go"
$buttonDupFind.Location = New-Object System.Drawing.Point(400, 135)
$buttonDupFind.Size = New-Object System.Drawing.Size(50, 26)
$buttonDupFind.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$buttonDupFind.ForeColor = [System.Drawing.Color]::White
$buttonDupFind.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

$buttonDupPause = New-Object System.Windows.Forms.Button
$buttonDupPause.Text = "Pause"
$buttonDupPause.Location = New-Object System.Drawing.Point(240, 560)
$buttonDupPause.Size = New-Object System.Drawing.Size(80, 30)
$buttonDupPause.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
$buttonDupPause.ForeColor = [System.Drawing.Color]::Black
$buttonDupPause.Enabled = $false

$buttonDupStop = New-Object System.Windows.Forms.Button
$buttonDupStop.Text = "Stop"
$buttonDupStop.Location = New-Object System.Drawing.Point(340, 560)
$buttonDupStop.Size = New-Object System.Drawing.Size(80, 30)
$buttonDupStop.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
$buttonDupStop.ForeColor = [System.Drawing.Color]::White
$buttonDupStop.Enabled = $false

$labelDupResults = New-Object System.Windows.Forms.Label
$labelDupResults.Text = "Duplicate Files Found:"
$labelDupResults.Location = New-Object System.Drawing.Point(20, 173)
$labelDupResults.Size = New-Object System.Drawing.Size(200, 20)

$textBoxDupResults = New-Object System.Windows.Forms.RichTextBox
$textBoxDupResults.Location = New-Object System.Drawing.Point(20, 198)
$textBoxDupResults.Size = New-Object System.Drawing.Size(540, 315)
$textBoxDupResults.ReadOnly = $true
$textBoxDupResults.ScrollBars = "Both"
$textBoxDupResults.Font = New-Object System.Drawing.Font("Consolas", 9)
$textBoxDupResults.WordWrap = $false
$textBoxDupResults.DetectUrls = $false

# Create context menu for duplicate results
$contextMenuDupResults = New-Object System.Windows.Forms.ContextMenuStrip
$menuItemCopyDup = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemCopyDup.Text = "Copy"
$menuItemCopyDup.Add_Click({
    if ($textBoxDupResults.SelectedText.Length -gt 0) {
        [System.Windows.Forms.Clipboard]::SetText($textBoxDupResults.SelectedText)
    }
})
$contextMenuDupResults.Items.Add($menuItemCopyDup)
$textBoxDupResults.ContextMenuStrip = $contextMenuDupResults

# Block user interaction during scan - keep cursor as arrow and prevent selection
$textBoxDupResults.Add_MouseMove({
    param($sender, $e)
    if ($script:dupScanRunning -and -not $script:dupShouldPause) {
        $textBoxDupResults.Cursor = [System.Windows.Forms.Cursors]::Default
        # Continuously clear selection during mouse movement
        if ($textBoxDupResults.SelectionLength -gt 0) {
            $textBoxDupResults.SelectionLength = 0
        }
    }
})

$textBoxDupResults.Add_MouseDown({
    param($sender, $e)
    if ($script:dupScanRunning -and -not $script:dupShouldPause) {
        # Prevent mouse down from initiating selection
        $textBoxDupResults.SelectionLength = 0
    }
})

$textBoxDupResults.Add_KeyDown({
    param($sender, $e)
    if ($script:dupScanRunning -and -not $script:dupShouldPause) {
        # Block keyboard-based selection (Ctrl+A, Shift+arrows, etc.)
        if ($e.Control -or $e.Shift) {
            $e.SuppressKeyPress = $true
            $e.Handled = $true
        }
    }
})

$textBoxDupResults.Add_SelectionChanged({
    if ($script:dupScanRunning -and -not $script:dupShouldPause) {
        # Clear any selection made during scan
        $textBoxDupResults.SelectionLength = 0
    }
})

# Block context menu during scan
$contextMenuDupResults.Add_Opening({
    param($sender, $e)
    if ($script:dupScanRunning -and -not $script:dupShouldPause) {
        $e.Cancel = $true
    }
})

$labelDupProgressLabel = New-Object System.Windows.Forms.Label
$labelDupProgressLabel.Text = "Progress:"
$labelDupProgressLabel.Location = New-Object System.Drawing.Point(20, 518)
$labelDupProgressLabel.Size = New-Object System.Drawing.Size(60, 15)
$labelDupProgressLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)

$labelDupProgressPercent = New-Object System.Windows.Forms.Label
$labelDupProgressPercent.Text = "0%"
$labelDupProgressPercent.Location = New-Object System.Drawing.Point(510, 518)
$labelDupProgressPercent.Size = New-Object System.Drawing.Size(50, 15)
$labelDupProgressPercent.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$labelDupProgressPercent.TextAlign = "MiddleRight"

$panelDupProgressBackground = New-Object System.Windows.Forms.Panel
$panelDupProgressBackground.Location = New-Object System.Drawing.Point(20, 536)
$panelDupProgressBackground.Size = New-Object System.Drawing.Size(540, 18)
$panelDupProgressBackground.BackColor = [System.Drawing.Color]::LightGray
$panelDupProgressBackground.BorderStyle = 'FixedSingle'

# Enumeration phase progress (gray/blue - shows behind green hashing progress)
$panelDupEnumFill = New-Object System.Windows.Forms.Panel
$panelDupEnumFill.Location = New-Object System.Drawing.Point(0, 0)
$panelDupEnumFill.Size = New-Object System.Drawing.Size(0, 18)
$panelDupEnumFill.BackColor = [System.Drawing.Color]::FromArgb(100, 149, 237)  # Cornflower blue
$panelDupProgressBackground.Controls.Add($panelDupEnumFill)

# Hashing phase progress (green - shows on top)
$panelDupProgressFill = New-Object System.Windows.Forms.Panel
$panelDupProgressFill.Location = New-Object System.Drawing.Point(0, 0)
$panelDupProgressFill.Size = New-Object System.Drawing.Size(0, 18)
$panelDupProgressFill.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$panelDupProgressBackground.Controls.Add($panelDupProgressFill)

$buttonDupExport = New-Object System.Windows.Forms.Button
$buttonDupExport.Text = "Export Results"
$buttonDupExport.Location = New-Object System.Drawing.Point(20, 560)
$buttonDupExport.Size = New-Object System.Drawing.Size(110, 30)
$buttonDupExport.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonDupExport.ForeColor = [System.Drawing.Color]::White

$buttonDupClear = New-Object System.Windows.Forms.Button
$buttonDupClear.Text = "Clear"
$buttonDupClear.Location = New-Object System.Drawing.Point(140, 560)
$buttonDupClear.Size = New-Object System.Drawing.Size(80, 30)
$buttonDupClear.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonDupClear.ForeColor = [System.Drawing.Color]::White

$labelDupFooter = New-Object System.Windows.Forms.Label
$labelDupFooter.Text = "Ready"
$labelDupFooter.Location = New-Object System.Drawing.Point(20, 595)
$labelDupFooter.Size = New-Object System.Drawing.Size(540, 20)
$labelDupFooter.TextAlign = "MiddleLeft"
$labelDupFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray
$labelDupFooter.Font = New-Object System.Drawing.Font("Segoe UI", 9)


$tabDuplicateFinder.Controls.Add($labelDupInfo)
$tabDuplicateFinder.Controls.Add($listBoxDupPaths)
$tabDuplicateFinder.Controls.Add($buttonDupAddFolder)
$tabDuplicateFinder.Controls.Add($buttonDupRemoveFolder)
$tabDuplicateFinder.Controls.Add($checkDupRecursive)
$tabDuplicateFinder.Controls.Add($labelDupExtensions)
$tabDuplicateFinder.Controls.Add($textBoxDupExtensions)
$tabDuplicateFinder.Controls.Add($labelDupAlgo)
$tabDuplicateFinder.Controls.Add($comboDupAlgo)
$tabDuplicateFinder.Controls.Add($buttonDupFind)
$tabDuplicateFinder.Controls.Add($buttonDupPause)
$tabDuplicateFinder.Controls.Add($buttonDupStop)
$tabDuplicateFinder.Controls.Add($labelDupResults)
$tabDuplicateFinder.Controls.Add($textBoxDupResults)
$tabDuplicateFinder.Controls.Add($labelDupProgressLabel)
$tabDuplicateFinder.Controls.Add($labelDupProgressPercent)
$tabDuplicateFinder.Controls.Add($panelDupProgressBackground)
$tabDuplicateFinder.Controls.Add($buttonDupExport)
$tabDuplicateFinder.Controls.Add($buttonDupClear)
$tabDuplicateFinder.Controls.Add($labelDupFooter)

# Add controls to Main Tab
$tabMain.Controls.Add($labelHeader)
$tabMain.Controls.Add($radioString)
$tabMain.Controls.Add($radioFile)
$tabMain.Controls.Add($labelInput)
$tabMain.Controls.Add($textBoxInput)
$tabMain.Controls.Add($buttonBrowse)
$tabMain.Controls.Add($labelAlgo)
$tabMain.Controls.Add($comboAlgo)
$tabMain.Controls.Add($labelKey)
$tabMain.Controls.Add($textBoxKey)
$tabMain.Controls.Add($labelCompare)
$tabMain.Controls.Add($textBoxCompare)
$tabMain.Controls.Add($checkLog)
$tabMain.Controls.Add($buttonGenerate)
$tabMain.Controls.Add($buttonCompare)
$tabMain.Controls.Add($buttonCopy)
$tabMain.Controls.Add($buttonClear)
$tabMain.Controls.Add($buttonStop)
$tabMain.Controls.Add($textBoxResult)
$tabMain.Controls.Add($panelProgressBackground)
$tabMain.Controls.Add($labelFooter)

$tabAbout.Controls.Add($panelAbout)

$tabLogViewer.Controls.Add($textBoxLogViewer)
$tabLogViewer.Controls.Add($buttonRefreshLog)
$tabLogViewer.Controls.Add($buttonClearLog)
$tabLogViewer.Controls.Add($buttonOpenLog)

# Event Handlers
$radioString.Add_CheckedChanged({
    $labelInput.Text = "Enter string:"
    $textBoxInput.Text = ""
    $buttonBrowse.Visible = $false
})

$radioFile.Add_CheckedChanged({
    $labelInput.Text = "Select file path:"
    $textBoxInput.Text = ""
    $buttonBrowse.Visible = $true
})

# Drag-and-drop support for File Mode with visual feedback
$textBoxInput.Add_DragEnter({
    if ($radioFile.Checked -and $_.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $_.Effect = [System.Windows.Forms.DragDropEffects]::Copy
        $textBoxInput.BackColor = [System.Drawing.Color]::LightGreen
        $script:dragDropBorderActive = $true
    } else {
        $_.Effect = [System.Windows.Forms.DragDropEffects]::None
    }
})

$textBoxInput.Add_DragOver({
    if ($radioFile.Checked -and $_.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $_.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    } else {
        $_.Effect = [System.Windows.Forms.DragDropEffects]::None
    }
})

$textBoxInput.Add_DragLeave({
    if ($script:dragDropBorderActive) {
        if ($checkDarkMode.Checked -and $script:DarkPanelColor) {
            $textBoxInput.BackColor = $script:DarkPanelColor
        } else {
            $textBoxInput.BackColor = [System.Drawing.Color]::White
        }
        $script:dragDropBorderActive = $false
    }
})

$textBoxInput.Add_DragDrop({
    $files = $_.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
    if ($files -and $files.Count -gt 0) {
        $textBoxInput.Text = $files[0]
        
        # Check if network path
        if (Test-NetworkPath -path $files[0]) {
            $labelFooter.Text = "Checking network path..."
            $labelFooter.ForeColor = [System.Drawing.Color]::Orange
            [System.Windows.Forms.Application]::DoEvents()
            
            if (Test-NetworkPathAccessible -path $files[0]) {
                $labelFooter.Text = "Network path: Connected"
                $labelFooter.ForeColor = [System.Drawing.Color]::Green
            } else {
                $labelFooter.Text = "Network path: Not accessible or timed out"
                $labelFooter.ForeColor = [System.Drawing.Color]::Red
            }
        }
    }
    
    # Reset background color
    if ($checkDarkMode.Checked -and $script:DarkPanelColor) {
        $textBoxInput.BackColor = $script:DarkPanelColor
    } else {
        $textBoxInput.BackColor = [System.Drawing.Color]::White
    }
    $script:dragDropBorderActive = $false
})

$comboAlgo.Add_SelectedIndexChanged({
    $selected = $comboAlgo.SelectedItem
    if ($selected -like "HMAC*") {
        $labelKey.Visible = $true
        $textBoxKey.Visible = $true
        $textBoxKey.Enabled = $true
        $textBoxKey.BackColor = [System.Drawing.Color]::White
        $textBoxKey.ForeColor = [System.Drawing.Color]::Black
    } else {
        $labelKey.Visible = $true
        $textBoxKey.Visible = $true
        $textBoxKey.Enabled = $false
        $textBoxKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
        $textBoxKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
    }
})

$comboBatchAlgo.Add_SelectedIndexChanged({
    $selected = $comboBatchAlgo.SelectedItem
    if ($selected -like "HMAC*") {
        $labelBatchKey.Visible = $true
        $textBoxBatchKey.Visible = $true
        $textBoxBatchKey.Enabled = $true
        $textBoxBatchKey.BackColor = [System.Drawing.Color]::White
        $textBoxBatchKey.ForeColor = [System.Drawing.Color]::Black
    } else {
        $labelBatchKey.Visible = $true
        $textBoxBatchKey.Visible = $true
        $textBoxBatchKey.Enabled = $false
        $textBoxBatchKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
        $textBoxBatchKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
    }
})

$buttonBrowse.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    if ($dialog.ShowDialog() -eq "OK") { $textBoxInput.Text = $dialog.FileName }
})

$buttonCopy.Add_Click({
    if (![string]::IsNullOrWhiteSpace($script:generatedHash)) {
        [System.Windows.Forms.Clipboard]::SetText($script:generatedHash)
        [System.Windows.Forms.MessageBox]::Show("Hash copied to clipboard.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } else {
        [System.Windows.Forms.MessageBox]::Show("No hash to copy.", "Clipboard", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
})

$buttonClear.Add_Click({
    $textBoxResult.Clear()
    if ($checkDarkMode.Checked -and $script:DarkPanelColor) {
        $textBoxResult.BackColor = $script:DarkPanelColor
    } else {
        $textBoxResult.BackColor = [System.Drawing.Color]::White
    }
    $textBoxCompare.Clear()
    $textBoxInput.Clear()
    $labelFooter.Text = "Ready"
    $script:generatedHash = $null
    $panelProgressFill.Width = 0
})

$buttonStop.Add_Click({
    if ($script:currentJobId) {
        try {
            Stop-Job -Id $script:currentJobId -ErrorAction SilentlyContinue
            Remove-Job -Id $script:currentJobId -ErrorAction SilentlyContinue
            Clear-HashTempFiles
            $uiTimer.Stop()
            $script:currentJobId = $null
            $textBoxResult.Text = "Operation cancelled."
            $textBoxResult.BackColor = [System.Drawing.Color]::LightYellow
            $textBoxResult.ForeColor = [System.Drawing.Color]::Black
            $labelFooter.Text = "Cancelled"
            $panelProgressFill.Width = 0
            $buttonStop.Enabled = $false
            $buttonGenerate.Enabled = $true
        } catch { }
    }
})

$buttonRefreshLog.Add_Click({
    if ((Test-Path $logPath) -and ((Get-Item $logPath).Length -gt 0)) { $textBoxLogViewer.Text = Add-LineNumbers (Get-Content $logPath -Raw) } else { $textBoxLogViewer.Text = "No log entries." }
})

$buttonClearLog.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show("Clear log file?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
        if (Test-Path $logPath) { Clear-Content -Path $logPath }
        $textBoxLogViewer.Text = "Log cleared."
        [System.Windows.Forms.MessageBox]::Show("Log cleared.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$buttonOpenLog.Add_Click({
    if (Test-Path $logPath) { Start-Process "notepad.exe" $logPath } else { [System.Windows.Forms.MessageBox]::Show("No log file found.", "View Log", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) }
})

$buttonRefreshBatchLog.Add_Click({
    if ((Test-Path $batchLogPath) -and ((Get-Item $batchLogPath).Length -gt 0)) { $textBoxBatchLogViewer.Text = Add-LineNumbers (Get-Content $batchLogPath -Raw) } else { $textBoxBatchLogViewer.Text = "No batch log entries." }
})

$buttonClearBatchLog.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show("Clear batch log file?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
        if (Test-Path $batchLogPath) { Clear-Content -Path $batchLogPath }
        $textBoxBatchLogViewer.Text = "Batch log cleared."
        [System.Windows.Forms.MessageBox]::Show("Batch log cleared.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$buttonOpenBatchLog.Add_Click({
    if (Test-Path $batchLogPath) { Start-Process "notepad.exe" $batchLogPath } else { [System.Windows.Forms.MessageBox]::Show("No batch log file found.", "View Log", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) }
})

$buttonClearCache.Add_Click({
    if ($script:PortableMode) {
        [System.Windows.Forms.MessageBox]::Show("Cache is disabled in Portable Mode.", "Cache Disabled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    
    $cacheCount = 0
    if ($script:hashCache) {
        $cacheCount = $script:hashCache.Count
    }
    
    if ($cacheCount -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Cache is already empty.", "Clear Cache", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    
    $confirm = [System.Windows.Forms.MessageBox]::Show("Clear all $cacheCount cached hash(es)?`n`nThis will remove all stored hashes and force re-computation on next use.", "Confirm Clear Cache", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
        $script:hashCache = @{}
        if (Test-Path $hashCachePath) {
            Remove-Item $hashCachePath -Force -ErrorAction SilentlyContinue
        }
        [System.Windows.Forms.MessageBox]::Show("Cache cleared successfully.`n`n$cacheCount hash(es) removed.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$buttonVerboseShell.Add_Click({
    # Check if running as EXE (compiled script) by checking if we have a valid script path
    # If $PSCommandPath is available, we're running as a .ps1 script
    $isCompiledExe = $true

    if ($PSCommandPath -or $MyInvocation.MyCommand.Path -or $PSScriptRoot) {
        $isCompiledExe = $false
    }

    if ($isCompiledExe) {
        # Running as EXE - just show informative message
        [System.Windows.Forms.MessageBox]::Show("Verbose console output is only available when running the .ps1 script directly.`n`nTo enable verbose mode, run CrunchHash_v3.0.ps1 in PowerShell and click this button.", "Verbose Mode Not Available", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }

    # Running as .ps1 script - get the script path
    $scriptPath = $PSCommandPath
    if (-not $scriptPath) {
        # Try alternative methods
        if ($MyInvocation.MyCommand.Path) {
            $scriptPath = $MyInvocation.MyCommand.Path
        } elseif ($PSScriptRoot) {
            $scriptPath = Join-Path $PSScriptRoot "CrunchHash_v3.0.ps1"
        }
    }

    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
        [System.Windows.Forms.MessageBox]::Show("Could not determine script path.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    # Build arguments for new instance with verbose mode
    $psArgs = "-ExecutionPolicy Bypass -NoExit -Command `"Write-Host 'CrunchHash Verbose Mode' -ForegroundColor Green; Write-Host 'Console output will appear here during operations' -ForegroundColor Yellow; Write-Host ''; & '$scriptPath' -Verbose"
    if ($script:PortableMode) {
        $psArgs += " -Portable"
    }
    $psArgs += "`""

    try {
        # Launch new instance
        Start-Process powershell.exe -ArgumentList $psArgs
        # Close current window
        $form.Close()
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to launch verbose shell: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$buttonRecentHash.Add_Click({
    if ($listBoxRecentFiles.SelectedItems.Count -ne 1) {
        return
    }
    
    $selectedFile = $listBoxRecentFiles.SelectedItems[0].ToString()
    # Strip number prefix (e.g., "1. C:\file.txt" -> "C:\file.txt")
    $selectedFile = $selectedFile -replace '^\d+\.\s+', ''
    if (Test-Path $selectedFile) {
        $radioFile.Checked = $true
        $textBoxInput.Text = $selectedFile
        $tabControl.SelectedTab = $tabMain
        $buttonGenerate.PerformClick()
    } else {
        [System.Windows.Forms.MessageBox]::Show("File no longer exists.", "Missing File", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
})

$buttonRecentBatch.Add_Click({
    if ($listBoxRecentFiles.SelectedItems.Count -eq 0) {
        return
    }
    
    # Check if all selected files exist
    $validFiles = @()
    $missingFiles = @()
    foreach ($item in $listBoxRecentFiles.SelectedItems) {
        $filePath = $item.ToString()
        # Strip number prefix (e.g., "1. C:\file.txt" -> "C:\file.txt")
        $filePath = $filePath -replace '^\d+\.\s+', ''
        if (Test-Path $filePath) {
            $validFiles += $filePath
        } else {
            $missingFiles += $filePath
        }
    }
    
    if ($missingFiles.Count -gt 0) {
        $msg = "The following files no longer exist:`n`n" + ($missingFiles -join "`n")
        [System.Windows.Forms.MessageBox]::Show($msg, "Missing Files", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    
    if ($validFiles.Count -eq 0) {
        return
    }
    
    # Add files to Batch tab
    $listBoxBatchFiles.Items.Clear()
    foreach ($file in $validFiles) {
        [void]$listBoxBatchFiles.Items.Add($file)
    }
    Update-BatchFilesListExtent
    $tabControl.SelectedTab = $tabBatch
    [System.Windows.Forms.MessageBox]::Show("$($validFiles.Count) file(s) added to Batch tab.`n`nClick 'Hash All' to process.", "Ready", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

# Update button states based on selection
$listBoxRecentFiles.Add_SelectedIndexChanged({
    $selectedCount = $listBoxRecentFiles.SelectedItems.Count

    if ($selectedCount -eq 0) {
        $buttonRecentHash.Enabled = $false
        $buttonRecentHash.ForeColor = [System.Drawing.Color]::Black
        $buttonRecentBatch.Enabled = $false
        $buttonRecentBatch.ForeColor = [System.Drawing.Color]::Black
    } elseif ($selectedCount -eq 1) {
        $buttonRecentHash.Enabled = $true
        $buttonRecentHash.ForeColor = [System.Drawing.Color]::White
        $buttonRecentBatch.Enabled = $false
        $buttonRecentBatch.ForeColor = [System.Drawing.Color]::Black
    } else {
        $buttonRecentHash.Enabled = $false
        $buttonRecentHash.ForeColor = [System.Drawing.Color]::Black
        $buttonRecentBatch.Enabled = $true
        $buttonRecentBatch.ForeColor = [System.Drawing.Color]::White
    }
})

$buttonRecentClear.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show("Clear recent files list?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
        $script:recentFiles = @()
        Update-RecentFilesList
        Save-Config

        # Manually reset button states since clearing doesn't always trigger SelectedIndexChanged
        $buttonRecentHash.Enabled = $false
        $buttonRecentHash.ForeColor = [System.Drawing.Color]::Black
        $buttonRecentBatch.Enabled = $false
        $buttonRecentBatch.ForeColor = [System.Drawing.Color]::Black
    }
})

$buttonRecentRefresh.Add_Click({
    Update-RecentFilesList
    if ($script:recentFiles.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No recent files. Hash a file first to see it in the list.", "Recent Files", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$comboVerifyAlgo.Add_SelectedIndexChanged({
    $selected = $comboVerifyAlgo.SelectedItem
    if ($selected -like "HMAC*") {
        $labelVerifyKey.Visible = $true
        $textBoxVerifyKey.Visible = $true
        $textBoxVerifyKey.Enabled = $true
        $textBoxVerifyKey.BackColor = [System.Drawing.Color]::White
        $textBoxVerifyKey.ForeColor = [System.Drawing.Color]::Black
    } else {
        $labelVerifyKey.Visible = $true
        $textBoxVerifyKey.Visible = $true
        $textBoxVerifyKey.Enabled = $false
        $textBoxVerifyKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
        $textBoxVerifyKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
    }
})

$buttonVerifyBrowse.Add_Click({
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDialog.Description = "Select base directory for files"
    if ($folderDialog.ShowDialog() -eq "OK") {
        $textBoxVerifyBasePath.Text = $folderDialog.SelectedPath
    }
})

$buttonVerifyClear.Add_Click({
    $textBoxVerifyInput.Clear()
    $textBoxVerifyResults.Clear()
    $textBoxVerifyBasePath.Clear()
    $panelVerifyProgressFill.Width = 0
    $script:verifyCurrentWidth = 0
    $script:verifyTargetWidth = 0
    $labelVerifyFooter.Text = "Ready"
})

$buttonImportBatchLog.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Log Files (*.txt;*.log)|*.txt;*.log|All Files (*.*)|*.*"
    $dialog.Title = "Select Batch Log File to Import"

    if ($dialog.ShowDialog() -eq "OK") {
        try {
            # Use StreamReader for memory-efficient reading of large files
            $streamReader = New-Object System.IO.StreamReader($dialog.FileName)
            $importedBuffer = New-Object System.Text.StringBuilder
            $lineCount = 0
            $importCount = 0

            # Pre-compile regex patterns for better performance
            $pattern1 = [regex]::new('^\s*(.+?):\s+((?:0x)?[a-fA-F0-9]{8,}|[A-Za-z0-9+/=]{16,})\s*$')
            $pattern2 = [regex]::new('^\s*((?:0x)?[a-fA-F0-9]{8,}|[A-Za-z0-9+/=]{16,})\t(.+?)\s*$')
            $pattern3 = [regex]::new('^\s*((?:0x)?[a-fA-F0-9]{8,}|[A-Za-z0-9+/=]{16,})\s+(.+?)\s*$')

            try {
                while ($null -ne ($line = $streamReader.ReadLine())) {
                    $lineCount++

                    # Skip empty lines
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }

                    # Try each pattern - use -match for faster initial check
                    if ($line -match ':\s+(?:0x)?[a-fA-F0-9]') {
                        $m = $pattern1.Match($line)
                        if ($m.Success) {
                            $filename = $m.Groups[1].Value.Trim()
                            $hash = $m.Groups[2].Value.Trim()
                            [void]$importedBuffer.AppendLine("$hash`t$filename")
                            $importCount++
                            continue
                        }
                    }
                    if ($line -match '\t') {
                        $m = $pattern2.Match($line)
                        if ($m.Success) {
                            $hash = $m.Groups[1].Value.Trim()
                            $filename = $m.Groups[2].Value.Trim()
                            [void]$importedBuffer.AppendLine("$hash`t$filename")
                            $importCount++
                            continue
                        }
                    }
                    $m = $pattern3.Match($line)
                    if ($m.Success) {
                        $hash = $m.Groups[1].Value.Trim()
                        $filename = $m.Groups[2].Value.Trim()
                        [void]$importedBuffer.AppendLine("$hash`t$filename")
                        $importCount++
                    }

                    # Keep UI responsive for very large files
                    if (($lineCount % 1000) -eq 0) {
                        [System.Windows.Forms.Application]::DoEvents()
                    }
                }
            } finally {
                $streamReader.Close()
            }

            if ($importCount -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("No valid hash entries found in the log file.`n`nExpected formats: filename: hash, hash<tab>filename, or hash filename (all four formats supported)", "Import Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }

            $textBoxVerifyInput.Text = $importedBuffer.ToString().TrimEnd()
            [System.Windows.Forms.MessageBox]::Show(("Successfully imported {0} hash entries from batch log.`n`nClick 'Verify All' to verify hashes." -f $importCount), "Import Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error importing batch log: $($_.Exception.Message)", "Import Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$buttonVerifyPause.Add_Click({
    if ($script:verifyShouldPause) {
        # Resume
        $script:verifyShouldPause = $false
        $buttonVerifyPause.Text = "Pause"
        $buttonVerifyPause.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
        $textBoxVerifyResults.ScrollBars = "None"  # Hide scrollbars when resuming
        # Delete pause file to signal resume
        if (Test-Path $script:verifyPauseFile) {
            Remove-Item $script:verifyPauseFile -Force -ErrorAction SilentlyContinue
        }
    } else {
        # Pause
        $script:verifyShouldPause = $true
        $buttonVerifyPause.Text = "Resume"
        $buttonVerifyPause.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
        $textBoxVerifyResults.ScrollBars = "Both"  # Show scrollbars when paused
        # Create pause file to signal pause
        try {
            [System.IO.File]::WriteAllText($script:verifyPauseFile, "PAUSE")
        } catch { }
    }
})

$buttonVerifyStop.Add_Click({
    if ($script:verifyJobId) {
        try {
            Stop-Job -Id $script:verifyJobId -ErrorAction SilentlyContinue
            Remove-Job -Id $script:verifyJobId -ErrorAction SilentlyContinue

            # Preserve completed results
            $completedResults = ""
            if (Test-Path $script:verifyTempFile) {
                try {
                    $completedResults = [System.IO.File]::ReadAllText($script:verifyTempFile)
                } catch { }
            }

            # Cleanup temp files
            if (Test-Path $script:verifyPauseFile) {
                Remove-Item $script:verifyPauseFile -Force -ErrorAction SilentlyContinue
            }

            $script:verifyJobId = $null
            $script:verifyRunning = $false
            $textBoxVerifyResults.ScrollBars = "Both"
            $buttonVerify.Enabled = $true
            $buttonVerifyStop.Enabled = $false
            $buttonVerifyPause.Enabled = $false
            $buttonVerifyPause.Text = "Pause"
            $buttonVerifyPause.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)

            # Re-enable other hash operations
            $buttonGenerate.Enabled = $true
            $buttonDupFind.Enabled = $true
            $buttonBatchHash.Enabled = $true

            $panelVerifyProgressFill.Width = 0
            $labelVerifyFooter.Text = "Verification stopped by user"
            if ($checkDarkMode.Checked -and $script:DarkForeColor) { $labelVerifyFooter.ForeColor = $script:DarkForeColor } else { $labelVerifyFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray }
        } catch {
            $labelVerifyFooter.Text = "Error stopping verification: $($_.Exception.Message)"
        }
    }
    $script:verifyShouldStop = $true
    $buttonVerifyStop.Enabled = $false
})

$buttonVerify.Add_Click({
    if ([string]::IsNullOrWhiteSpace($textBoxVerifyInput.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please paste a hash list first.", "Verify", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Check if verification job is already running
    if ($script:verifyJobId) {
        [System.Windows.Forms.MessageBox]::Show("Verification already in progress.", "Busy", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $textBoxVerifyResults.Clear()
    $textBoxVerifyResults.ScrollBars = "None"  # Hide scrollbars during verification
    $script:verifyRunning = $true
    $panelVerifyProgressFill.Width = 0
    $script:verifyCurrentWidth = 0
    $script:verifyTargetWidth = 0
    $script:verifyShouldStop = $false
    $script:verifyShouldPause = $false
    $script:verifyLastDisplayedLength = 0
    $script:verifyMatchCount = 0
    $script:verifyMismatchCount = 0
    $script:verifyMissingCount = 0
    $buttonVerifyStop.Enabled = $true
    $buttonVerifyPause.Enabled = $true
    $buttonVerify.Enabled = $false
    $labelVerifyFooter.Text = "Starting verification..."

    # Disable other hash operations to prevent conflicts
    $buttonGenerate.Enabled = $false
    $buttonDupFind.Enabled = $false
    $buttonBatchHash.Enabled = $false

    # Start UI timer for smooth progress animation
    if (-not $uiTimer.Enabled) {
        $uiTimer.Start()
    }

    # Parse input lines
    $lines = $textBoxVerifyInput.Text -split "`r?`n" | Where-Object { $_ -match '\S' }
    $basePath = $textBoxVerifyBasePath.Text.Trim()
    $algoName = $comboVerifyAlgo.SelectedItem
    $keyBytes = $null
    if ($algoName -like "HMAC*") { $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($textBoxVerifyKey.Text) }
    $selectedVerifyFormat = $comboVerifyFormat.SelectedItem

    # Clear previous temp files
    if (Test-Path $script:verifyTempFile) {
        Remove-Item $script:verifyTempFile -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $script:verifyProgressFile) {
        Remove-Item $script:verifyProgressFile -Force -ErrorAction SilentlyContinue
    }

    try {
        # Start parallel verification job
        $job = Start-Job -ScriptBlock {
            param($lines, $basePath, $algoName, $keyBytes, $format, $tempFile, $progressFile, $pauseFile, $threadCount)

            # Helper function to check for pause
            function Wait-IfPaused {
                param($progressFile, $pauseFile, $completedCount, $totalFiles)
                while (Test-Path $pauseFile) {
                    $percent = if ($totalFiles -gt 0) { [int](($completedCount * 100) / $totalFiles) } else { 0 }
                    try {
                        [System.IO.File]::WriteAllText($progressFile, "$completedCount|$percent|$totalFiles|PAUSED")
                    } catch { }
                    Start-Sleep -Milliseconds 500
                }
                return $true
            }

            # Load FastCRC32 class
            try {
                $null = [FastCRC32]
            } catch {
                try {
                    Add-Type -TypeDefinition @"
using System;
using System.IO;

public class FastCRC32
{
    private static uint[] crcTable;

    static FastCRC32()
    {
        crcTable = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int j = 0; j < 8; j++)
            {
                if ((c & 1) != 0)
                    c = (c >> 1) ^ 0xEDB88320;
                else
                    c >>= 1;
            }
            crcTable[i] = c;
        }
    }

    public static uint ComputeHashStream(Stream stream)
    {
        uint crc = 0xFFFFFFFF;
        byte[] buffer = new byte[65536];
        int count;

        while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i < count; i++)
            {
                byte index = (byte)(crc ^ buffer[i]);
                crc = (crc >> 8) ^ crcTable[index];
            }
        }
        return crc ^ 0xFFFFFFFF;
    }
}
"@ -ErrorAction Stop
                } catch { }
            }

            function Format-HashOutputLocal {
                param($hashHex, [string]$format)
                switch ($format) {
                    "lowercase" { return $hashHex }
                    "uppercase" { return $hashHex.ToUpperInvariant() }
                    "hex" { return "0x" + $hashHex }
                    "base64" {
                        $bytes = New-Object byte[] ($hashHex.Length / 2)
                        for ($i = 0; $i -lt $hashHex.Length; $i += 2) {
                            $bytes[$i / 2] = [System.Convert]::ToByte($hashHex.Substring($i, 2), 16)
                        }
                        return [System.Convert]::ToBase64String($bytes)
                    }
                    default { return $hashHex }
                }
            }

            # Create runspace pool for parallel processing
            $runspacePool = [runspacefactory]::CreateRunspacePool(1, $threadCount)
            $runspacePool.Open()

            $scriptBlock = {
                param($line, $basePath, $algoName, $keyBytes, $format, $fileIndex, $totalFiles)

                $result = @{
                    Index = $fileIndex
                    Line = $line
                    Status = $null
                    Filename = $null
                    ExpectedHash = $null
                    ComputedHash = $null
                    Error = $null
                }

                try {
                    # Parse line: hash and filename separated by tab or space
                    if ($line -match '^([a-fA-F0-9]+|0x[a-fA-F0-9]+|[A-Za-z0-9+/]+=*)\s+(.*)$') {
                        $expectedHash = $matches[1].Trim()
                        $filename = $matches[2].Trim()
                        $result.Filename = $filename
                        $result.ExpectedHash = $expectedHash

                        if ([string]::IsNullOrWhiteSpace($filename)) {
                            $result.Status = "INVALID"
                            return $result
                        }

                        # Construct full path
                        $fullPath = if ([string]::IsNullOrWhiteSpace($basePath)) { $filename } else { Join-Path $basePath $filename }

                        if (-not (Test-Path $fullPath -ErrorAction SilentlyContinue)) {
                            $result.Status = "MISSING"
                            return $result
                        }

                        # Compute hash
                        if ($algoName -eq "CRC32") {
                            $fs = [System.IO.File]::OpenRead($fullPath)
                            try {
                                $crc32 = [FastCRC32]::ComputeHashStream($fs)
                                $computedHash = $crc32.ToString("x8")
                                $hashBytes = [BitConverter]::GetBytes([Convert]::ToUInt32($computedHash, 16))
                            } finally { $fs.Close() }
                        } else {
                            switch ($algoName) {
                                "SHA256" { $algo = [System.Security.Cryptography.SHA256]::Create() }
                                "SHA1"   { $algo = [System.Security.Cryptography.SHA1]::Create() }
                                "SHA512" { $algo = [System.Security.Cryptography.SHA512]::Create() }
                                "MD5"    { $algo = [System.Security.Cryptography.MD5]::Create() }
                                "SHA384" { $algo = [System.Security.Cryptography.SHA384]::Create() }
                                "RIPEMD160" { $algo = [System.Security.Cryptography.RIPEMD160]::Create() }
                                "HMACSHA256" { $algo = [System.Security.Cryptography.HMACSHA256]::new($keyBytes) }
                                "HMACSHA512" { $algo = [System.Security.Cryptography.HMACSHA512]::new($keyBytes) }
                                default { throw "Unsupported algorithm" }
                            }
                            $fs = [System.IO.File]::OpenRead($fullPath)
                            try {
                                $hashBytes = $algo.ComputeHash($fs)
                                $computedHash = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLowerInvariant()
                            } finally { $fs.Close(); if ($algo) { $algo.Dispose() } }
                        }

                        # Format and compare
                        if ($format -eq "base64") {
                            try {
                                $expectedBytes = [Convert]::FromBase64String($expectedHash)
                                $isMatch = ($expectedBytes.Length -eq $hashBytes.Length)
                                if ($isMatch) {
                                    for ($i = 0; $i -lt $expectedBytes.Length; $i++) {
                                        if ($expectedBytes[$i] -ne $hashBytes[$i]) { $isMatch = $false; break }
                                    }
                                }
                                $result.ComputedHash = [Convert]::ToBase64String($hashBytes)
                                $result.Status = if ($isMatch) { "MATCH" } else { "MISMATCH" }
                            } catch {
                                $result.Status = "ERROR"
                                $result.Error = "Invalid base64 expected hash"
                            }
                        } else {
                            function Format-HashOutputLocal {
                                param($hashHex, [string]$format)
                                switch ($format) {
                                    "lowercase" { return $hashHex }
                                    "uppercase" { return $hashHex.ToUpperInvariant() }
                                    "hex" { return "0x" + $hashHex }
                                    default { return $hashHex }
                                }
                            }
                            $formattedComputed = Format-HashOutputLocal $computedHash $format
                            $formattedExpected = Format-HashOutputLocal ($expectedHash -replace '^0x', '') $format
                            $result.ComputedHash = $formattedComputed
                            $result.Status = if ($formattedComputed -eq $formattedExpected) { "MATCH" } else { "MISMATCH" }
                        }
                    } else {
                        $result.Status = "INVALID"
                    }
                } catch {
                    $result.Status = "ERROR"
                    $result.Error = $_.Exception.Message
                }

                return $result
            }

            # Process all lines in parallel
            $runspaces = @()
            $writer = [System.IO.StreamWriter]::new($tempFile, $false, [System.Text.Encoding]::UTF8)
            $completedCount = 0
            $totalLines = $lines.Count

            for ($i = 0; $i -lt $lines.Count; $i++) {
                $ps = [powershell]::Create().AddScript($scriptBlock).AddArgument($lines[$i]).AddArgument($basePath).AddArgument($algoName).AddArgument($keyBytes).AddArgument($format).AddArgument($i).AddArgument($totalLines)
                $ps.RunspacePool = $runspacePool
                $runspaces += @{ PowerShell = $ps; Handle = $ps.BeginInvoke(); Index = $i }
            }

            # Wait for results and write them in order
            $results = @{}
            $nextIndexToWrite = 0

            while ($runspaces.Count -gt 0) {
                # Check for pause
                Wait-IfPaused -progressFile $progressFile -pauseFile $pauseFile -completedCount $completedCount -totalFiles $totalLines

                foreach ($runspace in $runspaces.ToArray()) {
                    if ($runspace.Handle.IsCompleted) {
                        $result = $runspace.PowerShell.EndInvoke($runspace.Handle)
                        $runspace.PowerShell.Dispose()
                        $runspaces = $runspaces | Where-Object { $_.Index -ne $runspace.Index }

                        # Store result
                        $results[$runspace.Index] = $result

                        # Write results that are ready in order
                        while ($results.ContainsKey($nextIndexToWrite)) {
                            $r = $results[$nextIndexToWrite]
                            $resultLine = ""

                            switch ($r.Status) {
                                "MATCH" { $resultLine = "MATCH: $($r.Filename)" }
                                "MISMATCH" { $resultLine = "MISMATCH: $($r.Filename) (expected: $($r.ExpectedHash), got: $($r.ComputedHash))" }
                                "MISSING" { $resultLine = "MISSING: $($r.Filename)" }
                                "INVALID" { $resultLine = "INVALID LINE: $($r.Line)" }
                                "ERROR" { $resultLine = "ERROR: $($r.Filename) - $($r.Error)" }
                            }

                            if ($resultLine) {
                                $writer.WriteLine("$($r.Status)|$resultLine")
                                $writer.Flush()
                            }

                            $results.Remove($nextIndexToWrite)
                            $nextIndexToWrite++
                            $completedCount++

                            # Update progress
                            $percent = if ($totalLines -gt 0) { [int](($completedCount * 100) / $totalLines) } else { 0 }
                            try {
                                [System.IO.File]::WriteAllText($progressFile, "$completedCount|$percent|$totalLines")
                            } catch { }
                        }
                    }
                }

                Start-Sleep -Milliseconds 50
            }

            $writer.Close()
            $runspacePool.Close()
            $runspacePool.Dispose()

            # Write completion marker
            try {
                [System.IO.File]::WriteAllText($progressFile, "$completedCount|100|$totalLines|COMPLETE")
            } catch { }

        } -ArgumentList $lines, $basePath, $algoName, $keyBytes, $selectedVerifyFormat, $script:verifyTempFile, $script:verifyProgressFile, $script:verifyPauseFile, $script:parallelThreadCount

        $script:verifyJobId = $job.Id
        $script:verifyTotalFiles = $lines.Count

        # Force UI update
        $labelVerifyFooter.Text = "Verification job started - processing $($lines.Count) file(s)..."
        $labelVerifyFooter.ForeColor = [System.Drawing.Color]::DarkOrange
        [System.Windows.Forms.Application]::DoEvents()

    } catch {
        $textBoxVerifyResults.Text = "Error: $($_.Exception.Message)"
        $buttonVerify.Enabled = $true
        $buttonVerifyStop.Enabled = $false
        $buttonVerifyPause.Enabled = $false
        $buttonGenerate.Enabled = $true
        $buttonDupFind.Enabled = $true
        $buttonBatchHash.Enabled = $true
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Verification Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        $script:verifyRunning = $false
    }
})

# Duplicate Finder Event Handlers
$buttonDupAddFolder.Add_Click({
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select directory to search for duplicates"
    $folderBrowser.ShowNewFolderButton = $false

    $dialogResult = $folderBrowser.ShowDialog()
    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        # Add to list if not already there
        if ($listBoxDupPaths.Items -notcontains $folderBrowser.SelectedPath) {
            [void]$listBoxDupPaths.Items.Add($folderBrowser.SelectedPath)
        }
    }
    $folderBrowser.Dispose()
})

$buttonDupRemoveFolder.Add_Click({
    # Remove selected items
    $selectedIndices = @($listBoxDupPaths.SelectedIndices)
    # Remove in reverse order to maintain correct indices
    for ($i = $selectedIndices.Count - 1; $i -ge 0; $i--) {
        $listBoxDupPaths.Items.RemoveAt($selectedIndices[$i])
    }
})

$buttonDupClear.Add_Click({
    # Clean up any running job
    if ($script:dupJobId) {
        # Signal job to stop
        try {
            "STOP" | Out-File -FilePath "$($script:dupProgressFile).stop" -Force -ErrorAction SilentlyContinue
        } catch { }

        try {
            if ($script:dupRunspace) {
                $script:dupRunspace.Stop()
                $script:dupRunspace.Dispose()
                $script:dupRunspace = $null
            }
        } catch { }
        $script:dupJobId = $null
        $script:dupHandle = $null
    }

    # Clean up temp files with retry (wait for timer to release files)
    Start-Sleep -Milliseconds 300
    $tempFiles = @($script:dupTempFile, $script:dupProgressFile, "$($script:dupProgressFile).stop", $script:dupPauseFile)
    foreach ($file in $tempFiles) {
        if ($file -and (Test-Path $file)) {
            $retries = 3
            $deleted = $false
            while ($retries -gt 0 -and -not $deleted) {
                try {
                    Remove-Item $file -Force -ErrorAction Stop
                    $deleted = $true
                } catch {
                    $retries--
                    if ($retries -gt 0) {
                        Start-Sleep -Milliseconds 100
                    }
                }
            }
        }
    }

    # Reset UI
    $textBoxDupResults.Text = ""
    $labelDupFooter.Text = "Ready"
    $labelDupProgressPercent.Text = "0%"
    $panelDupProgressFill.Width = 0
    $buttonDupFind.Enabled = $true
    $buttonDupPause.Enabled = $false
    $buttonDupStop.Enabled = $false
    $buttonDupAddFolder.Enabled = $true
    $buttonDupRemoveFolder.Enabled = $true
    $buttonDupExport.Enabled = $true

    # Reset tracking variables
    $script:dupSets = @{}
    $script:dupLastReadLine = 0
    $script:dupShouldStop = $false
    $script:dupStopTime = $null
})

$buttonDupPause.Add_Click({
    if ($script:dupShouldPause) {
        # Resume
        $script:dupShouldPause = $false
        $buttonDupPause.Text = "Pause"
        $buttonDupPause.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
        $textBoxDupResults.ScrollBars = "None"  # Hide scrollbars when resuming
        # Delete pause file to signal resume
        if (Test-Path $script:dupPauseFile) {
            Remove-Item $script:dupPauseFile -Force -ErrorAction SilentlyContinue
        }
    } else {
        # Pause
        $script:dupShouldPause = $true
        $buttonDupPause.Text = "Resume"
        $buttonDupPause.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
        $textBoxDupResults.ScrollBars = "Both"  # Show scrollbars when paused
        # Create pause file to signal pause
        try {
            "PAUSE" | Out-File -FilePath $script:dupPauseFile -Force -ErrorAction SilentlyContinue
        } catch { }
    }
})

$buttonDupStop.Add_Click({
    # Immediately stop and clean up - no waiting
    if ($script:dupJobId) {
        # Signal job to stop
        try {
            "STOP" | Out-File -FilePath "$($script:dupProgressFile).stop" -Force -ErrorAction SilentlyContinue
        } catch { }

        try {
            # Force stop the runspace immediately
            if ($script:dupRunspace) {
                $script:dupRunspace.Stop()
                $script:dupRunspace.Dispose()
                $script:dupRunspace = $null
            }
        } catch { }

        # Reset job ID FIRST so timer stops trying to read files
        $script:dupJobId = $null
        $script:dupHandle = $null

        # Show summary if any duplicates were found
        $finalDupCount = $script:dupSets.Count
        $finalTotalDups = 0
        foreach ($set in $script:dupSets.Values) {
            $finalTotalDups += $set.Files.Count
        }

        if ($finalDupCount -gt 0) {
            $summary = "========== SUMMARY (STOPPED) ==========`r`n"
            $summary += "Duplicate sets found: $finalDupCount`r`n"
            $summary += "Total duplicate files: $finalTotalDups`r`n"
            $summary += "========================================`r`n`r`n"
            $textBoxDupResults.Text = $summary + $textBoxDupResults.Text
        }

        # Cleanup temp files with retry (wait for timer to release files)
        Start-Sleep -Milliseconds 300
        $tempFiles = @($script:dupTempFile, $script:dupProgressFile, "$($script:dupProgressFile).stop", $script:dupPauseFile)
        foreach ($file in $tempFiles) {
            if ($file -and (Test-Path $file)) {
                $retries = 3
                $deleted = $false
                while ($retries -gt 0 -and -not $deleted) {
                    try {
                        Remove-Item $file -Force -ErrorAction Stop
                        $deleted = $true
                    } catch {
                        $retries--
                        if ($retries -gt 0) {
                            Start-Sleep -Milliseconds 100
                        }
                    }
                }
            }
        }

        # Reset other state
        $script:dupSets = @{}
        $script:dupLastReadLine = 0
        $script:dupShouldStop = $false
        $script:dupStopTime = $null

        # Re-enable UI
        $buttonDupFind.Enabled = $true
        $buttonDupPause.Enabled = $false
        $buttonDupStop.Enabled = $false
        $buttonDupAddFolder.Enabled = $true
        $buttonDupRemoveFolder.Enabled = $true
        $buttonDupExport.Enabled = $true
        $script:dupScanRunning = $false  # Re-enable user interaction
        $textBoxDupResults.ScrollBars = "Both"  # Restore scrollbars after scan

        # Re-enable other hash operations
        $buttonGenerate.Enabled = $true
        $buttonBatchHash.Enabled = $true
        $buttonVerify.Enabled = $true

        $panelDupProgressFill.Width = 0  # Reset green bar
        $panelDupEnumFill.Width = 0  # Reset blue bar
        $labelDupProgressPercent.Text = "0%"
        $labelDupFooter.Text = "Stopped by user"
    }
})

$buttonDupExport.Add_Click({
    if (-not $textBoxDupResults.Text) {
        [System.Windows.Forms.MessageBox]::Show("No results to export. Please run a duplicate search first.", "No Results", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
    $saveDialog.DefaultExt = "txt"
    $saveDialog.FileName = "duplicate_files_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $saveDialog.Title = "Export Duplicate Files Results"

    if ($saveDialog.ShowDialog() -eq "OK") {
        try {
            [System.IO.File]::WriteAllText($saveDialog.FileName, $textBoxDupResults.Text, [System.Text.Encoding]::UTF8)
            $labelDupFooter.Text = "Results exported to: $(Split-Path $saveDialog.FileName -Leaf)"
            [System.Windows.Forms.MessageBox]::Show("Results successfully exported to:`n$($saveDialog.FileName)", "Export Successful", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to export results:`n$($_.Exception.Message)", "Export Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$buttonDupFind.Add_Click({
    if ($listBoxDupPaths.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please add at least one directory first.", "No Directories Selected", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Validate all paths exist
    $invalidPaths = @()
    foreach ($path in $listBoxDupPaths.Items) {
        if (-not (Test-Path $path)) {
            $invalidPaths += $path
        }
    }
    if ($invalidPaths.Count -gt 0) {
        $msg = "The following director$(if($invalidPaths.Count -eq 1){'y does'}else{'ies do'}) not exist:`n`n" + ($invalidPaths -join "`n")
        [System.Windows.Forms.MessageBox]::Show($msg, "Invalid Directory", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    $script:dupShouldStop = $false
    $script:dupShouldPause = $false
    $script:dupStopTime = $null
    $script:dupSets = @{}
    $script:dupLastReadLine = 0
    $buttonDupFind.Enabled = $false
    $buttonDupPause.Enabled = $true
    $buttonDupPause.Text = "Pause"
    $buttonDupPause.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
    $buttonDupStop.Enabled = $true
    $buttonDupAddFolder.Enabled = $false
    $buttonDupRemoveFolder.Enabled = $false
    $buttonDupExport.Enabled = $false
    $textBoxDupResults.Text = ""

    # Disable other hash operations to prevent conflicts
    $buttonGenerate.Enabled = $false
    $buttonBatchHash.Enabled = $false
    $buttonVerify.Enabled = $false

    # Lock textbox during scan - keep enabled to preserve colors, but block all interaction
    $script:dupScanRunning = $true
    $textBoxDupResults.ScrollBars = "None"  # Hide scrollbars to prevent dragging during scan

    $labelDupFooter.Text = "Scanning directories..."
    $labelDupProgressPercent.Text = "0%"
    $panelDupProgressFill.Width = 0

    $searchPaths = @($listBoxDupPaths.Items)
    $recursive = $checkDupRecursive.Checked
    $algorithm = $comboDupAlgo.SelectedItem

    # Get extensions, ignore if it's the placeholder text
    $extensions = $textBoxDupExtensions.Text.Trim()
    if ($extensions -eq "*.jpg,*.png (optional)" -or $textBoxDupExtensions.ForeColor -eq [System.Drawing.Color]::Gray) {
        $extensions = ""
    }

    # Clean up old temp files
    if (Test-Path $script:dupTempFile) {
        Remove-Item -LiteralPath $script:dupTempFile -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $script:dupProgressFile) {
        Remove-Item -LiteralPath $script:dupProgressFile -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path "$($script:dupProgressFile).stop") {
        Remove-Item -LiteralPath "$($script:dupProgressFile).stop" -Force -ErrorAction SilentlyContinue
    }

    # Start runspace to find duplicates
    $script:dupRunspace = [powershell]::Create()

    [void]$script:dupRunspace.AddScript({
        param($paths, $isRecursive, $algo, $tempFile, $progressFile, $extensionFilter, $stopFile, $hashCachePath, $pauseFile)

        # Helper function to check for pause
        function Wait-IfPaused {
            param($progressFile, $pauseFile)
            while (Test-Path $pauseFile) {
                # Write paused status
                "0|0|PHASE:PAUSED|Paused" | Out-File -FilePath $progressFile -Force -Encoding UTF8
                Start-Sleep -Milliseconds 500
                # Check if stop was requested during pause
                if (Test-Path $stopFile) {
                    return $false
                }
            }
            return $true
        }

        try {
            # Write initial progress immediately to signal start
            "0|0|PHASE:SCANNING|Starting..." | Out-File -FilePath $progressFile -Force -Encoding UTF8

            # Build size groups directly while enumerating (more efficient)
            $sizeGroups = @{}
            $totalEnumerated = 0
            $lastUpdateCount = 0

            foreach ($path in $paths) {
                $currentPath = $path
                # Write scanning progress at start of each path
                "0|0|PHASE:SCANNING|$currentPath" | Out-File -FilePath $progressFile -Force -Encoding UTF8

                $fileEnum = if ($isRecursive) {
                    Get-ChildItem -LiteralPath $path -File -Recurse -ErrorAction SilentlyContinue
                } else {
                    Get-ChildItem -LiteralPath $path -File -ErrorAction SilentlyContinue
                }

                foreach ($file in $fileEnum) {
                    # Check for pause every 50 files
                    if ($totalEnumerated % 50 -eq 0) {
                        if (-not (Wait-IfPaused $progressFile $pauseFile)) {
                            return
                        }
                    }

                    # Apply extension filter if provided
                    if ($extensionFilter) {
                        $extArray = $extensionFilter -split ',' | ForEach-Object { $_.Trim() -replace '^\*\.', '.' -replace '^\*', '' }
                        $ext = $file.Extension.ToLower()
                        $matchesFilter = $false
                        foreach ($filterExt in $extArray) {
                            if ($ext -like "*$filterExt") {
                                $matchesFilter = $true
                                break
                            }
                        }
                        if (-not $matchesFilter) { continue }
                    }

                    # Group by size as we enumerate
                    $size = $file.Length
                    if (-not $sizeGroups.ContainsKey($size)) {
                        $sizeGroups[$size] = @()
                    }
                    $sizeGroups[$size] += $file

                    $totalEnumerated++

                    # SCANNING phase: update file count every 50 files (no percentage - we don't know total yet)
                    if ($totalEnumerated - $lastUpdateCount -ge 50 -or $totalEnumerated -eq 1) {
                        "0|$totalEnumerated|PHASE:SCANNING|$currentPath" | Out-File -FilePath $progressFile -Force -Encoding UTF8
                        $lastUpdateCount = $totalEnumerated
                    }
                }
            }

            # Write final scanning count
            "0|$totalEnumerated|PHASE:SCANNING|Complete" | Out-File -FilePath $progressFile -Force -Encoding UTF8

            # FILTERING phase: 0-100% as we filter size groups
            "0|$totalEnumerated|PHASE:FILTERING" | Out-File -FilePath $progressFile -Force -Encoding UTF8

            # Only keep groups with potential duplicates (size appears more than once)
            $filesToHash = @()
            $groupIndex = 0
            $totalGroups = $sizeGroups.Keys.Count
            foreach ($size in $sizeGroups.Keys) {
                $groupIndex++
                if ($sizeGroups[$size].Count -gt 1) {
                    $filesToHash += $sizeGroups[$size]
                }
                # Update filtering progress
                if ($groupIndex % 100 -eq 0 -or $groupIndex -eq $totalGroups) {
                    $filterPercent = [int](($groupIndex / $totalGroups) * 100)
                    "$filterPercent|$totalEnumerated|PHASE:FILTERING" | Out-File -FilePath $progressFile -Force -Encoding UTF8
                }
            }

            # GROUPING phase complete
            "100|$totalEnumerated|PHASE:GROUPING" | Out-File -FilePath $progressFile -Force -Encoding UTF8

            $totalFiles = $filesToHash.Count
            if ($totalFiles -eq 0) {
                "0|0|COMPLETE" | Out-File -FilePath $progressFile -Force -Encoding UTF8
                return
            }

            # Load hash cache if available
            $hashCache = @{}
            if ($hashCachePath -and (Test-Path $hashCachePath)) {
                try {
                    $cacheData = Get-Content -LiteralPath $hashCachePath -Raw -Encoding UTF8 | ConvertFrom-Json
                    foreach ($entry in $cacheData.PSObject.Properties) {
                        $hashCache[$entry.Name] = $entry.Value
                    }
                } catch {
                    # Cache load failed, continue without cache
                }
            }

            # Write initial progress so UI knows hashing phase started
            "0|$totalFiles|PHASE:HASHING" | Out-File -FilePath $progressFile -Force -Encoding UTF8

            $hashTable = @{}
            $sizeTable = @{}
            $cachedFiles = @{}  # Track which files were cached
            $processed = 0
            $stopped = $false
            $duplicateSetNumber = 0
            $lastCacheSave = 0  # Track when we last saved cache

            # Process files sequentially with cache support
            foreach ($file in $filesToHash) {
                try {
                    # Check for pause
                    if (-not (Wait-IfPaused $progressFile $pauseFile)) {
                        $stopped = $true
                        break
                    }

                    # Check if stop requested
                    if (Test-Path $stopFile) {
                        $stopped = $true
                        break
                    }

                    # Try to get from cache first
                    $hash = $null
                    $wasCached = $false
                    $cacheKey = "$($file.FullName)|$($file.LastWriteTime.Ticks)|$algo"
                    if ($hashCache.ContainsKey($cacheKey)) {
                        $hash = $hashCache[$cacheKey].Hash
                        $wasCached = $true
                    } else {
                        # Calculate hash
                        if ($algo -eq "CRC32") {
                            $hashObj = Get-FileHash -LiteralPath $file.FullName -Algorithm MD5 -ErrorAction Stop
                            $hash = $hashObj.Hash
                        } else {
                            $hashObj = Get-FileHash -LiteralPath $file.FullName -Algorithm $algo -ErrorAction Stop
                            $hash = $hashObj.Hash
                        }
                        # Add to cache with timestamp
                        $hashCache[$cacheKey] = @{
                            Hash = $hash
                            Timestamp = [DateTime]::Now.ToString("o")
                        }
                    }

                    # Track if this file was cached
                    $cachedFiles[$file.FullName] = $wasCached

                    # Group by hash
                    if (-not $hashTable.ContainsKey($hash)) {
                        $hashTable[$hash] = @()
                        $sizeTable[$hash] = $file.Length
                    }
                    $hashTable[$hash] += $file.FullName

                    # Check if this creates/updates a duplicate set
                    if ($hashTable[$hash].Count -eq 2) {
                        $duplicateSetNumber++
                        # Build cached files array for this hash
                        $cachedForThisHash = @()
                        foreach ($f in $hashTable[$hash]) {
                            if ($cachedFiles[$f]) {
                                $cachedForThisHash += $f
                            }
                        }
                        $dupEntry = @{
                            Hash = $hash
                            Files = $hashTable[$hash]
                            SetNumber = $duplicateSetNumber
                            Size = $sizeTable[$hash]
                            CachedFiles = $cachedForThisHash
                        }
                        "DUPLICATE|" + ($dupEntry | ConvertTo-Json -Compress) | Add-Content -Path $tempFile -Encoding UTF8
                    } elseif ($hashTable[$hash].Count -gt 2) {
                        $setNum = 0
                        foreach ($entry in $hashTable.GetEnumerator()) {
                            if ($entry.Value.Count -gt 1) {
                                $setNum++
                                if ($entry.Key -eq $hash) { break }
                            }
                        }
                        # Build cached files array for this hash
                        $cachedForThisHash = @()
                        foreach ($f in $hashTable[$hash]) {
                            if ($cachedFiles[$f]) {
                                $cachedForThisHash += $f
                            }
                        }
                        $dupEntry = @{
                            Hash = $hash
                            Files = $hashTable[$hash]
                            SetNumber = $setNum
                            Size = $sizeTable[$hash]
                            CachedFiles = $cachedForThisHash
                        }
                        "UPDATE|" + ($dupEntry | ConvertTo-Json -Compress) | Add-Content -Path $tempFile -Encoding UTF8
                    }

                    $processed++
                    $hashPercent = [int](($processed / $totalFiles) * 100)
                    "$hashPercent|$totalFiles|PHASE:HASHING" | Out-File -FilePath $progressFile -Force -Encoding UTF8

                    # Save cache incrementally every 100 files (skip limiting for better responsiveness)
                    if ($hashCachePath -and (($processed - $lastCacheSave) -ge 100)) {
                        try {
                            $hashCache | ConvertTo-Json | Out-File -FilePath $hashCachePath -Force -Encoding UTF8
                            $lastCacheSave = $processed
                        } catch {
                            # Cache save failed, continue
                        }
                    }

                } catch {
                    # Skip files that can't be hashed
                    $processed++
                }
            }

            # Write completion marker
            if ($stopped) {
                "$processed|$totalFiles|STOPPED" | Out-File -FilePath $progressFile -Force -Encoding UTF8
            } else {
                "$processed|$totalFiles|COMPLETE" | Out-File -FilePath $progressFile -Force -Encoding UTF8
            }

            # Save updated cache back to disk (skip expensive sorting at completion for responsiveness)
            if ($hashCachePath -and $hashCache.Count -gt 0) {
                try {
                    $hashCache | ConvertTo-Json | Out-File -FilePath $hashCachePath -Force -Encoding UTF8
                } catch {
                    # Cache save failed, continue
                }
            }
        } catch {
            # Job-level error - write error to progress file
            "0|0|ERROR" | Out-File -FilePath $progressFile -Force -Encoding UTF8
        }
    })

    [void]$script:dupRunspace.AddArgument($searchPaths)
    [void]$script:dupRunspace.AddArgument($recursive)
    [void]$script:dupRunspace.AddArgument($algorithm)
    [void]$script:dupRunspace.AddArgument($script:dupTempFile)
    [void]$script:dupRunspace.AddArgument($script:dupProgressFile)
    [void]$script:dupRunspace.AddArgument($extensions)
    [void]$script:dupRunspace.AddArgument("$($script:dupProgressFile).stop")
    [void]$script:dupRunspace.AddArgument($hashCachePath)
    [void]$script:dupRunspace.AddArgument($script:dupPauseFile)

    $script:dupHandle = $script:dupRunspace.BeginInvoke()
    $script:dupJobId = [guid]::NewGuid().ToString()
    $labelDupFooter.Text = "Duplicate finder started..."
})

$numericFontSize.Add_ValueChanged({
    $script:fontOutput = New-Object System.Drawing.Font("Consolas", $numericFontSize.Value, [System.Drawing.FontStyle]::Bold)
    $script:fontVerdict = New-Object System.Drawing.Font("Consolas", ($numericFontSize.Value + 2), [System.Drawing.FontStyle]::Bold)
    $textBoxResult.Font = $script:fontOutput
    $textBoxLogViewer.Font = New-Object System.Drawing.Font("Consolas", $numericFontSize.Value)
    $textBoxBatchResults.Font = New-Object System.Drawing.Font("Consolas", $numericFontSize.Value)
    $textBoxBatchLogViewer.Font = New-Object System.Drawing.Font("Consolas", $numericFontSize.Value)
    $listBoxRecentFiles.Font = New-Object System.Drawing.Font("Consolas", $numericFontSize.Value)
    $textBoxVerifyInput.Font = New-Object System.Drawing.Font("Consolas", $numericFontSize.Value)
    $textBoxVerifyResults.Font = New-Object System.Drawing.Font("Consolas", $numericFontSize.Value)
    $textBoxDupResults.Font = New-Object System.Drawing.Font("Consolas", $numericFontSize.Value)
    # Recalculate horizontal extent for Recent Files list with new font size
    Update-RecentFilesList
})

$checkDarkMode.Add_CheckedChanged({
    Set-DarkMode -enabled $checkDarkMode.Checked
    
    # Reapply HMAC field colors after dark mode change
    # Check current algorithm selections to set correct colors
    $selectedMain = $comboAlgo.SelectedItem
    if ($selectedMain -like "HMAC*") {
        $textBoxKey.BackColor = [System.Drawing.Color]::White
        $textBoxKey.ForeColor = [System.Drawing.Color]::Black
    } else {
        $textBoxKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
        $textBoxKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
    }
    
    $selectedBatch = $comboBatchAlgo.SelectedItem
    if ($selectedBatch -like "HMAC*") {
        $textBoxBatchKey.BackColor = [System.Drawing.Color]::White
        $textBoxBatchKey.ForeColor = [System.Drawing.Color]::Black
    } else {
        $textBoxBatchKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
        $textBoxBatchKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
    }
    
    $selectedVerify = $comboVerifyAlgo.SelectedItem
    if ($selectedVerify -like "HMAC*") {
        $textBoxVerifyKey.BackColor = [System.Drawing.Color]::White
        $textBoxVerifyKey.ForeColor = [System.Drawing.Color]::Black
    } else {
        $textBoxVerifyKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
        $textBoxVerifyKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
    }
    
    # Reapply red color only to Clear Cache button
    $buttonClearCache.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)

    # Refresh Batch results with theme-appropriate colors for [CACHED] entries
    if ($textBoxBatchResults.Text.Length -gt 0 -and $textBoxBatchResults.Text -match '\[CACHED\]') {
        $currentText = $textBoxBatchResults.Text
        $savedScrollBars = $textBoxBatchResults.ScrollBars
        $textBoxBatchResults.Clear()
        $lines = $currentText -split "`r`n|`n"
        foreach ($line in $lines) {
            if ($line -match '\[CACHED\]') {
                $cachedColor = if ($checkDarkMode.Checked) { [System.Drawing.Color]::MediumOrchid } else { [System.Drawing.Color]::Blue }
                Add-ColoredText -RichTextBox $textBoxBatchResults -Text ($line + "`r`n") -Color $cachedColor
            } else {
                $textBoxBatchResults.AppendText($line + "`r`n")
            }
        }
        $textBoxBatchResults.ScrollBars = $savedScrollBars
    }

    # Refresh Verify results with colors (GREEN for MATCH, RED for MISMATCH/ERROR)
    if ($textBoxVerifyResults.Text.Length -gt 0 -and ($textBoxVerifyResults.Text -match 'MATCH:|MISMATCH:|ERROR:')) {
        $currentText = $textBoxVerifyResults.Text
        $savedScrollBars = $textBoxVerifyResults.ScrollBars
        $textBoxVerifyResults.Clear()
        $lines = $currentText -split "`r`n|`n"
        foreach ($line in $lines) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                $lineColor = if ($checkDarkMode.Checked) { $script:DarkOutputFore } else { [System.Drawing.Color]::Black }

                if ($line -match '^MATCH:') {
                    $lineColor = [System.Drawing.Color]::Green
                } elseif ($line -match '^MISMATCH:' -or $line -match '^ERROR:') {
                    $lineColor = [System.Drawing.Color]::Red
                }

                Add-ColoredText -RichTextBox $textBoxVerifyResults -Text ($line + "`r`n") -Color $lineColor
            }
        }
        $textBoxVerifyResults.ScrollBars = $savedScrollBars
    }

    # Force immediate visual refresh of all controls
    $form.Refresh()
})

# Keyboard shortcuts
$form.Add_KeyDown({
    param($src, $e)
    # Ctrl+Enter to generate hash
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $buttonGenerate.PerformClick()
        $e.Handled = $true
    }
})

# Batch Mode - Drag and drop with visual feedback
$listBoxBatchFiles.Add_DragEnter({
    if ($_.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $_.Effect = [System.Windows.Forms.DragDropEffects]::Copy
        $listBoxBatchFiles.BackColor = [System.Drawing.Color]::LightGreen
    } else {
        $_.Effect = [System.Windows.Forms.DragDropEffects]::None
    }
})

$listBoxBatchFiles.Add_DragOver({
    if ($_.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $_.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    } else {
        $_.Effect = [System.Windows.Forms.DragDropEffects]::None
    }
})

$listBoxBatchFiles.Add_DragLeave({
    if ($checkDarkMode.Checked -and $script:DarkPanelColor) {
        $listBoxBatchFiles.BackColor = $script:DarkPanelColor
    } else {
        $listBoxBatchFiles.BackColor = [System.Drawing.Color]::White
    }
})

$listBoxBatchFiles.Add_DragDrop({
    $files = $_.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
    if ($files) {
        $networkFiles = 0
        foreach ($file in $files) {
            if ((Test-Path $file) -and -not (Get-Item $file).PSIsContainer) {
                if ($listBoxBatchFiles.Items -notcontains $file) {
                    [void]$listBoxBatchFiles.Items.Add($file)
                    if (Test-NetworkPath -path $file) {
                        $networkFiles++
                    }
                }
            }
        }
        if ($networkFiles -gt 0) {
            $labelBatchFooter.Text = "Added $networkFiles network file(s)"
            $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange
        }
        Update-BatchFilesListExtent
    }
    
    # Reset background color
    if ($checkDarkMode.Checked -and $script:DarkPanelColor) {
        $listBoxBatchFiles.BackColor = $script:DarkPanelColor
    } else {
        $listBoxBatchFiles.BackColor = [System.Drawing.Color]::White
    }
})

$buttonBatchAdd.Add_Click({
    # Create context menu for file/folder selection
    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

    $menuItemFiles = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuItemFiles.Text = "Add Files..."
    $menuItemFiles.Add_Click({
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Multiselect = $true
        $dialog.Title = "Select Files to Add"
        if ($dialog.ShowDialog() -eq "OK") {
            $addedCount = 0
            foreach ($file in $dialog.FileNames) {
                if ($listBoxBatchFiles.Items -notcontains $file) {
                    [void]$listBoxBatchFiles.Items.Add($file)
                    $addedCount++
                }
            }
            Update-BatchFilesListExtent
            if ($addedCount -gt 0) {
                $labelBatchFooter.Text = "Added $addedCount file(s)"
                $labelBatchFooter.ForeColor = [System.Drawing.Color]::LimeGreen
            }
        }
    })

    $menuItemFolder = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuItemFolder.Text = "Add Folder..."
    $menuItemFolder.Add_Click({
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = "Select Folder to Add (Recursive option is in the main tab)"
        $dialog.ShowNewFolderButton = $false
        if ($dialog.ShowDialog() -eq "OK") {
            # Use async loading for better performance with large folders
            Start-BatchFileLoading -folderPath $dialog.SelectedPath -recursive $checkBatchRecursive.Checked
        }
    })

    $menuItemBoth = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuItemBoth.Text = "Add Files && Folders..."
    $menuItemBoth.Add_Click({
        # First, let user select files
        $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $fileDialog.Multiselect = $true
        $fileDialog.Title = "Select Files (Click Cancel when done to select folders)"

        $addedCount = 0
        if ($fileDialog.ShowDialog() -eq "OK") {
            foreach ($file in $fileDialog.FileNames) {
                if ($listBoxBatchFiles.Items -notcontains $file) {
                    [void]$listBoxBatchFiles.Items.Add($file)
                    $addedCount++
                }
            }
        }

        # Then, let user select folders - use async loading for better performance
        $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderDialog.Description = "Select Folder (or Cancel to finish) - Recursive option is in the main tab"
        $folderDialog.ShowNewFolderButton = $false

        $continue = $true
        while ($continue) {
            if ($folderDialog.ShowDialog() -eq "OK") {
                # Use async loading for the folder
                Start-BatchFileLoading -folderPath $folderDialog.SelectedPath -recursive $checkBatchRecursive.Checked

                # Wait for loading to complete before asking for another folder
                while ($script:batchLoadingJobId) {
                    [System.Windows.Forms.Application]::DoEvents()
                    Start-Sleep -Milliseconds 100
                }

                # Ask if user wants to add more folders
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Folder loading complete. Add another folder?",
                    "Add More Folders",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                if ($result -eq [System.Windows.Forms.DialogResult]::No) {
                    $continue = $false
                }
            } else {
                $continue = $false
            }
        }

        if ($addedCount -gt 0) {
            $labelBatchFooter.Text = "Added $addedCount file(s) from individual selections and folders"
            $labelBatchFooter.ForeColor = [System.Drawing.Color]::LimeGreen
        }
    })

    [void]$contextMenu.Items.Add($menuItemFiles)
    [void]$contextMenu.Items.Add($menuItemFolder)
    [void]$contextMenu.Items.Add($menuItemBoth)

    # Show context menu at button location
    $contextMenu.Show($buttonBatchAdd, 0, $buttonBatchAdd.Height)
})

$buttonBatchRemove.Add_Click({
    for ($i = $listBoxBatchFiles.SelectedItems.Count - 1; $i -ge 0; $i--) {
        [void]$listBoxBatchFiles.Items.Remove($listBoxBatchFiles.SelectedItems[$i])
    }
})

$buttonBatchClear.Add_Click({
    # Stop any running job first
    if ($script:batchJobId) {
        try {
            Stop-Job -Id $script:batchJobId -ErrorAction SilentlyContinue
            Remove-Job -Id $script:batchJobId -Force -ErrorAction SilentlyContinue
        } catch { }
        $script:batchJobId = $null
    }

    # Clean up batch temp files with retry
    Start-Sleep -Milliseconds 300
    $tempFiles = @($script:batchProgressFile, $script:batchFileProgressFile, $script:batchPauseFile, $script:batchCacheFile, $script:batchTempFile, $script:batchLoadingTempFile, $hashSpeedFile)
    foreach ($file in $tempFiles) {
        if ($file -and (Test-Path $file)) {
            $retries = 3
            $deleted = $false
            while ($retries -gt 0 -and -not $deleted) {
                try {
                    Remove-Item $file -Force -ErrorAction Stop
                    $deleted = $true
                } catch {
                    $retries--
                    if ($retries -gt 0) {
                        Start-Sleep -Milliseconds 100
                    }
                }
            }
        }
    }

    $listBoxBatchFiles.Items.Clear()
    $textBoxBatchResults.Clear()
    $panelBatchProgressFill.Width = 0
    $panelBatchFileProgressFill.Width = 0
    $labelBatchFilePercent.Text = "0%"
    $labelBatchOverallPercent.Text = "0%"
    $labelBatchFooter.Text = "Ready"
    if ($checkDarkMode.Checked -and $script:DarkForeColor) { $labelBatchFooter.ForeColor = $script:DarkForeColor } else { $labelBatchFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray }
})

$buttonBatchPause.Add_Click({
    if ($script:batchShouldPause) {
        # Resume
        $script:batchShouldPause = $false
        $buttonBatchPause.Text = "Pause"
        $buttonBatchPause.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
        $textBoxBatchResults.ScrollBars = "None"  # Hide scrollbars when resuming
        # Remove "- paused" from footer
        $currentFooter = $labelBatchFooter.Text
        if ($currentFooter -like "*- paused*") {
            $labelBatchFooter.Text = $currentFooter -replace " - paused$", ""
        }
        # Delete pause file to signal resume
        if (Test-Path $script:batchPauseFile) {
            Remove-Item $script:batchPauseFile -Force -ErrorAction SilentlyContinue
        }
    } else {
        # Pause
        $script:batchShouldPause = $true
        $buttonBatchPause.Text = "Resume"
        $buttonBatchPause.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
        $textBoxBatchResults.ScrollBars = "Both"  # Show scrollbars when paused
        # Add "- paused" to footer
        $currentFooter = $labelBatchFooter.Text
        if ($currentFooter -notlike "*- paused*") {
            $labelBatchFooter.Text = $currentFooter + " - paused"
        }
        # Create pause file to signal pause
        try {
            [System.IO.File]::WriteAllText($script:batchPauseFile, "PAUSE")
        } catch { }
    }
})

$buttonBatchStop.Add_Click({
    if ($script:batchJobId) {
        try {
            Stop-Job -Id $script:batchJobId -ErrorAction SilentlyContinue
            Remove-Job -Id $script:batchJobId -ErrorAction SilentlyContinue

            # Preserve completed results and append cancellation message
            $completedResults = ""
            if (Test-Path $script:batchTempFile) {
                try {
                    $completedResults = [System.IO.File]::ReadAllText($script:batchTempFile)
                } catch { }
            }

            if ([string]::IsNullOrWhiteSpace($completedResults)) {
                $textBoxBatchResults.Clear()
                $textBoxBatchResults.AppendText("Batch operation cancelled. No files were completed.")
            } else {
                # Display results with color coding for [CACHED] entries
                $textBoxBatchResults.Clear()
                $lines = ($completedResults + "`r`n`r`n========== OPERATION CANCELLED ==========") -split "`r`n|`n"
                foreach ($line in $lines) {
                    if ($line -match '\[CACHED\]') {
                        # Use purple in dark mode, blue in light mode
                        $cachedColor = if ($checkDarkMode.Checked) { [System.Drawing.Color]::MediumOrchid } else { [System.Drawing.Color]::Blue }
                        Add-ColoredText -RichTextBox $textBoxBatchResults -Text ($line + "`r`n") -Color $cachedColor
                    } else {
                        $textBoxBatchResults.AppendText($line + "`r`n")
                    }
                }
            }

            # Restore scrollbars after stop
            $textBoxBatchResults.ScrollBars = "Both"
            $script:batchJobId = $null
            $script:batchLastDisplayedLength = 0

            # Clean up batch temp files with retry
            Start-Sleep -Milliseconds 300
            $tempFiles = @($script:batchProgressFile, $script:batchFileProgressFile, $script:batchPauseFile, $script:batchCacheFile, $script:batchTempFile, $script:batchLoadingTempFile, $hashSpeedFile)
            foreach ($file in $tempFiles) {
                if ($file -and (Test-Path $file)) {
                    $retries = 3
                    $deleted = $false
                    while ($retries -gt 0 -and -not $deleted) {
                        try {
                            Remove-Item $file -Force -ErrorAction Stop
                            $deleted = $true
                        } catch {
                            $retries--
                            if ($retries -gt 0) {
                                Start-Sleep -Milliseconds 100
                            }
                        }
                    }
                }
            }

            $buttonBatchHash.Visible = $true
            $buttonBatchClear.Visible = $true
            $buttonBatchPause.Visible = $false
            $buttonBatchPause.Enabled = $false
            $buttonBatchPause.Text = "Pause"
            $buttonBatchPause.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
            $script:batchShouldPause = $false
            $buttonBatchStop.Visible = $false
            $buttonBatchStop.Enabled = $false
            $buttonBatchExport.Enabled = $true
            $buttonExportHashCheck.Enabled = $true
            $buttonExportSFV.Enabled = $true
            $buttonExportVerifyLog.Enabled = $true

            # Re-enable other hash operations
            $buttonGenerate.Enabled = $true
            $buttonDupFind.Enabled = $true
            $buttonVerify.Enabled = $true

            $panelBatchProgressFill.Width = 0
            $panelBatchFileProgressFill.Width = 0
            $labelBatchFilePercent.Text = "0%"
            $labelBatchOverallPercent.Text = "0%"
            $labelBatchFooter.Text = "Cancelled"
        } catch { }
    }
})

$buttonBatchCopyResults.Add_Click({
    if (![string]::IsNullOrWhiteSpace($textBoxBatchResults.Text)) {
        [System.Windows.Forms.Clipboard]::SetText($textBoxBatchResults.Text)
        [System.Windows.Forms.MessageBox]::Show("Results copied to clipboard.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$buttonBatchExport.Add_Click({
    if ([string]::IsNullOrWhiteSpace($textBoxBatchResults.Text)) {
        [System.Windows.Forms.MessageBox]::Show("No results to export.", "Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "Text files (*.txt)|*.txt|CSV files (*.csv)|*.csv"
    $saveDialog.Title = "Export Hash Results"
    $saveDialog.FileName = "hash_results_" + (Get-Date -Format "yyyyMMdd_HHmmss")
    
    if ($saveDialog.ShowDialog() -eq "OK") {
        try {
            $exportPath = $saveDialog.FileName
            $lines = $textBoxBatchResults.Text -split "`r`n" | Where-Object { $_ -match '\S' }
            $timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
            $algorithm = $comboAlgo.SelectedItem
            $format = if ($radioFormatUpper.Checked) { "UPPERCASE" } elseif ($radioFormatHex.Checked) { "Hex (0x prefix)" } elseif ($radioFormatBase64.Checked) { "Base64" } else { "lowercase" }
            
            if ($exportPath -like "*.csv") {
                # CSV format: metadata + hash,filename
                $csvContent = "# Exported: $timestamp`r`n"
                $csvContent += "# Algorithm: $algorithm`r`n"
                $csvContent += "# Format: $format`r`n"
                $csvContent += "Hash,Filename`r`n"
                foreach ($line in $lines) {
                    if ($line -match '(.+)\t(.+)') {
                        $hash = $matches[1]
                        $filename = $matches[2]
                        $csvContent += "`"$hash`",`"$filename`"`r`n"
                    }
                }
                [System.IO.File]::WriteAllText($exportPath, $csvContent)
            } else {
                # TXT format: metadata header + tab-separated data
                $txtContent = "========================================`r`n"
                $txtContent += "Batch Hash Export`r`n"
                $txtContent += "Timestamp: $timestamp`r`n"
                $txtContent += "Algorithm: $algorithm`r`n"
                $txtContent += "Format: $format`r`n"
                $txtContent += "========================================`r`n`r`n"
                $txtContent += $textBoxBatchResults.Text
                [System.IO.File]::WriteAllText($exportPath, $txtContent)
            }
            
            [System.Windows.Forms.MessageBox]::Show("Results exported successfully.`n`n$exportPath", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$buttonExportHashCheck.Add_Click({
    if ([string]::IsNullOrWhiteSpace($textBoxBatchResults.Text)) {
        [System.Windows.Forms.MessageBox]::Show("No results to export.", "Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Parse results and collect file information
    $lines = $textBoxBatchResults.Text -split "`r`n" | Where-Object { $_ -match '\S' }
    $fileItems = @()

    foreach ($line in $lines) {
        if ($line -notmatch '^ERROR:' -and $line -notmatch '^Batch job' -and $line -notmatch '^Starting') {
            $parts = $line -split "`t"
            if ($parts.Count -ge 4) {
                $hash = $parts[0].Trim() -replace '[\r\n]+', ''
                $filePath = $parts[3].Trim()

                if (-not [string]::IsNullOrWhiteSpace($hash) -and (Test-Path $filePath)) {
                    $fileItems += @{
                        Hash = $hash
                        Path = $filePath
                        Name = [System.IO.Path]::GetFileName($filePath)
                    }
                }
            }
        }
    }

    if ($fileItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No valid results to export.", "Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Create file selection dialog
    $selectionForm = New-Object System.Windows.Forms.Form
    $selectionForm.Text = "Select Files for HashCheck Export"
    $selectionForm.Size = New-Object System.Drawing.Size(600, 500)
    $selectionForm.StartPosition = "CenterParent"
    $selectionForm.FormBorderStyle = "Sizable"
    $selectionForm.MinimumSize = New-Object System.Drawing.Size(500, 400)

    if ($checkDarkMode.Checked) {
        $selectionForm.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
        $selectionForm.ForeColor = [System.Drawing.Color]::White
    }

    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = "Select files to create HashCheck files for:"
    $lblInfo.Location = New-Object System.Drawing.Point(10, 10)
    $lblInfo.Size = New-Object System.Drawing.Size(560, 20)
    $selectionForm.Controls.Add($lblInfo)

    $checkedListBox = New-Object System.Windows.Forms.CheckedListBox
    $checkedListBox.Location = New-Object System.Drawing.Point(10, 35)
    $checkedListBox.Size = New-Object System.Drawing.Size(560, 340)
    $checkedListBox.CheckOnClick = $true
    $checkedListBox.Anchor = "Top,Bottom,Left,Right"

    if ($checkDarkMode.Checked) {
        $checkedListBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
        $checkedListBox.ForeColor = [System.Drawing.Color]::White
    }

    foreach ($item in $fileItems) {
        [void]$checkedListBox.Items.Add($item.Path, $true)
    }
    $selectionForm.Controls.Add($checkedListBox)

    $btnSelectAll = New-Object System.Windows.Forms.Button
    $btnSelectAll.Text = "Select All"
    $btnSelectAll.Location = New-Object System.Drawing.Point(10, 385)
    $btnSelectAll.Size = New-Object System.Drawing.Size(90, 30)
    $btnSelectAll.Anchor = "Bottom,Left"
    $btnSelectAll.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
    $btnSelectAll.ForeColor = [System.Drawing.Color]::White
    $btnSelectAll.FlatStyle = "Flat"
    $btnSelectAll.Add_Click({
        for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
            $checkedListBox.SetItemChecked($i, $true)
        }
    })
    $selectionForm.Controls.Add($btnSelectAll)

    $btnDeselectAll = New-Object System.Windows.Forms.Button
    $btnDeselectAll.Text = "Deselect All"
    $btnDeselectAll.Location = New-Object System.Drawing.Point(110, 385)
    $btnDeselectAll.Size = New-Object System.Drawing.Size(90, 30)
    $btnDeselectAll.Anchor = "Bottom,Left"
    $btnDeselectAll.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
    $btnDeselectAll.ForeColor = [System.Drawing.Color]::White
    $btnDeselectAll.FlatStyle = "Flat"
    $btnDeselectAll.Add_Click({
        for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
            $checkedListBox.SetItemChecked($i, $false)
        }
    })
    $selectionForm.Controls.Add($btnDeselectAll)

    $lblCount = New-Object System.Windows.Forms.Label
    $lblCount.Text = "$($fileItems.Count) file(s) available"
    $lblCount.Location = New-Object System.Drawing.Point(210, 392)
    $lblCount.Size = New-Object System.Drawing.Size(200, 20)
    $lblCount.Anchor = "Bottom,Left"
    $selectionForm.Controls.Add($lblCount)

    $btnExport = New-Object System.Windows.Forms.Button
    $btnExport.Text = "Export Selected"
    $btnExport.Location = New-Object System.Drawing.Point(380, 425)
    $btnExport.Size = New-Object System.Drawing.Size(100, 30)
    $btnExport.Anchor = "Bottom,Right"
    $btnExport.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
    $btnExport.ForeColor = [System.Drawing.Color]::White
    $btnExport.FlatStyle = "Flat"
    $btnExport.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $selectionForm.Controls.Add($btnExport)
    $selectionForm.AcceptButton = $btnExport

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(490, 425)
    $btnCancel.Size = New-Object System.Drawing.Size(80, 30)
    $btnCancel.Anchor = "Bottom,Right"
    $btnCancel.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
    $btnCancel.ForeColor = [System.Drawing.Color]::White
    $btnCancel.FlatStyle = "Flat"
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $selectionForm.Controls.Add($btnCancel)
    $selectionForm.CancelButton = $btnCancel

    # Show the dialog
    $dialogResult = $selectionForm.ShowDialog()

    if ($dialogResult -ne [System.Windows.Forms.DialogResult]::OK) {
        $selectionForm.Dispose()
        return
    }

    # Get selected files
    $selectedFiles = @()
    for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
        if ($checkedListBox.GetItemChecked($i)) {
            $selectedFiles += $fileItems[$i]
        }
    }
    $selectionForm.Dispose()

    if ($selectedFiles.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No files selected.", "Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Export HashCheck files for selected items
    $algorithm = $comboBatchAlgo.SelectedItem
    $exportCount = 0
    $errors = @()

    foreach ($item in $selectedFiles) {
        $result = Export-HashCheckFile -filePath $item.Path -hash $item.Hash -algorithm $algorithm
        if ($result) {
            $exportCount++
        } else {
            $errors += "$($item.Path) (export failed)"
        }
    }

    # Show success message
    $msg = "$exportCount file(s) exported. Each HashCheck file was saved to its relative files location."
    if ($errors.Count -gt 0) {
        $msg += "`n`nErrors: $($errors.Count)"
        if ($errors.Count -le 5) {
            $msg += "`n" + ($errors -join "`n")
        }
    }
    [System.Windows.Forms.MessageBox]::Show($msg, "HashCheck Export Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

$buttonExportSFV.Add_Click({
    if ([string]::IsNullOrWhiteSpace($textBoxBatchResults.Text)) {
        [System.Windows.Forms.MessageBox]::Show("No results to export.", "Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Check if CRC32 algorithm
    if ($comboBatchAlgo.SelectedItem -ne "CRC32") {
        [System.Windows.Forms.MessageBox]::Show("SFV format requires CRC32 algorithm.", "SFV Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Parse results and collect file information
    $lines = $textBoxBatchResults.Text -split "`r`n" | Where-Object { $_ -match '\S' }
    $fileItems = @()

    foreach ($line in $lines) {
        # Match CRC32 format: hash<TAB>...metadata...<TAB>filepath (with or without [CACHED] at end)
        if ($line -match '^([a-fA-F0-9]{8})\t') {
            $hash = $matches[1]
            # Split the line by tabs
            $parts = $line -split '\t'

            # The filepath is typically the 4th part (index 3)
            # If last part is [CACHED], filepath is at index 3, otherwise could be last
            $filePath = $null
            if ($parts.Count -ge 4) {
                if ($parts[-1] -eq '[CACHED]') {
                    $filePath = $parts[3]  # Fourth column is the filepath
                } else {
                    $filePath = $parts[3]  # Fourth column is still the filepath
                }
            }

            if ($filePath -and (Test-Path $filePath)) {
                $fileItems += @{
                    Hash = $hash
                    Path = $filePath
                    Name = [System.IO.Path]::GetFileName($filePath)
                }
            }
        }
    }

    if ($fileItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No valid CRC32 results to export.", "Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Create file selection dialog
    $selectionForm = New-Object System.Windows.Forms.Form
    $selectionForm.Text = "Select Files for SFV Export"
    $selectionForm.Size = New-Object System.Drawing.Size(600, 500)
    $selectionForm.StartPosition = "CenterParent"
    $selectionForm.FormBorderStyle = "Sizable"
    $selectionForm.MinimumSize = New-Object System.Drawing.Size(500, 400)

    if ($checkDarkMode.Checked) {
        $selectionForm.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
        $selectionForm.ForeColor = [System.Drawing.Color]::White
    }

    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = "Select files to include in SFV file:"
    $lblInfo.Location = New-Object System.Drawing.Point(10, 10)
    $lblInfo.Size = New-Object System.Drawing.Size(560, 20)
    $selectionForm.Controls.Add($lblInfo)

    $checkedListBox = New-Object System.Windows.Forms.CheckedListBox
    $checkedListBox.Location = New-Object System.Drawing.Point(10, 35)
    $checkedListBox.Size = New-Object System.Drawing.Size(560, 340)
    $checkedListBox.CheckOnClick = $true
    $checkedListBox.Anchor = "Top,Bottom,Left,Right"

    if ($checkDarkMode.Checked) {
        $checkedListBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
        $checkedListBox.ForeColor = [System.Drawing.Color]::White
    }

    foreach ($item in $fileItems) {
        [void]$checkedListBox.Items.Add($item.Path, $true)
    }
    $selectionForm.Controls.Add($checkedListBox)

    $btnSelectAll = New-Object System.Windows.Forms.Button
    $btnSelectAll.Text = "Select All"
    $btnSelectAll.Location = New-Object System.Drawing.Point(10, 385)
    $btnSelectAll.Size = New-Object System.Drawing.Size(90, 30)
    $btnSelectAll.Anchor = "Bottom,Left"
    $btnSelectAll.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
    $btnSelectAll.ForeColor = [System.Drawing.Color]::White
    $btnSelectAll.FlatStyle = "Flat"
    $btnSelectAll.Add_Click({
        for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
            $checkedListBox.SetItemChecked($i, $true)
        }
    })
    $selectionForm.Controls.Add($btnSelectAll)

    $btnDeselectAll = New-Object System.Windows.Forms.Button
    $btnDeselectAll.Text = "Deselect All"
    $btnDeselectAll.Location = New-Object System.Drawing.Point(110, 385)
    $btnDeselectAll.Size = New-Object System.Drawing.Size(90, 30)
    $btnDeselectAll.Anchor = "Bottom,Left"
    $btnDeselectAll.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
    $btnDeselectAll.ForeColor = [System.Drawing.Color]::White
    $btnDeselectAll.FlatStyle = "Flat"
    $btnDeselectAll.Add_Click({
        for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
            $checkedListBox.SetItemChecked($i, $false)
        }
    })
    $selectionForm.Controls.Add($btnDeselectAll)

    $lblCount = New-Object System.Windows.Forms.Label
    $lblCount.Text = "$($fileItems.Count) file(s) available"
    $lblCount.Location = New-Object System.Drawing.Point(210, 392)
    $lblCount.Size = New-Object System.Drawing.Size(200, 20)
    $lblCount.Anchor = "Bottom,Left"
    $selectionForm.Controls.Add($lblCount)

    $btnExport = New-Object System.Windows.Forms.Button
    $btnExport.Text = "Export Selected"
    $btnExport.Location = New-Object System.Drawing.Point(380, 425)
    $btnExport.Size = New-Object System.Drawing.Size(100, 30)
    $btnExport.Anchor = "Bottom,Right"
    $btnExport.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
    $btnExport.ForeColor = [System.Drawing.Color]::White
    $btnExport.FlatStyle = "Flat"
    $btnExport.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $selectionForm.Controls.Add($btnExport)
    $selectionForm.AcceptButton = $btnExport

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(490, 425)
    $btnCancel.Size = New-Object System.Drawing.Size(80, 30)
    $btnCancel.Anchor = "Bottom,Right"
    $btnCancel.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
    $btnCancel.ForeColor = [System.Drawing.Color]::White
    $btnCancel.FlatStyle = "Flat"
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $selectionForm.Controls.Add($btnCancel)
    $selectionForm.CancelButton = $btnCancel

    # Show the dialog
    $dialogResult = $selectionForm.ShowDialog()

    if ($dialogResult -ne [System.Windows.Forms.DialogResult]::OK) {
        $selectionForm.Dispose()
        return
    }

    # Get selected files
    $selectedFiles = @()
    for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
        if ($checkedListBox.GetItemChecked($i)) {
            $selectedFiles += $fileItems[$i]
        }
    }
    $selectionForm.Dispose()

    if ($selectedFiles.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No files selected.", "Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Now show save dialog
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "SFV files (*.sfv)|*.sfv"
    $saveDialog.Title = "Export SFV File"
    $saveDialog.FileName = "checksums.sfv"

    if ($saveDialog.ShowDialog() -eq "OK") {
        try {
            # Build hashtable from selected files
            $fileHashes = @{}
            foreach ($item in $selectedFiles) {
                $fileHashes[$item.Path] = $item.Hash
            }

            if (Export-SFVFile -outputPath $saveDialog.FileName -fileHashes $fileHashes) {
                [System.Windows.Forms.MessageBox]::Show("$($selectedFiles.Count) file checksum(s) included in SFV file.`n`n$($saveDialog.FileName)", "SFV Export Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } else {
                [System.Windows.Forms.MessageBox]::Show("Failed to export SFV file.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$buttonExportVerifyLog.Add_Click({
    if ([string]::IsNullOrWhiteSpace($textBoxBatchResults.Text)) {
        [System.Windows.Forms.MessageBox]::Show("No results to export.", "Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "Log files (*.txt;*.log)|*.txt;*.log|All Files (*.*)|*.*"
    $saveDialog.Title = "Export Verify Log"
    $saveDialog.FileName = "batch_verify_log.txt"
    
    if ($saveDialog.ShowDialog() -eq "OK") {
        try {
            # Parse results and create verify log format: filename: hash
            $verifyLogLines = @()
            # Use .Lines property for more reliable line access in RichTextBox
            $lines = @($textBoxBatchResults.Lines) | Where-Object { $_ -match '\S' }

            foreach ($line in $lines) {
                # Skip error lines
                if ($line -match '^ERROR:') { continue }

                # Try to match batch result format: hash<TAB>Size: xxx<TAB>Modified: xxx<TAB>filepath[<TAB>[CACHED]]
                # Use tab as delimiter to split the line
                $parts = $line -split '\t'

                # Primary format: hash<TAB>Size: xxx<TAB>Modified: xxx<TAB>filepath
                if ($parts.Count -ge 4 -and $parts[1] -match '^Size:' -and $parts[2] -match '^Modified:') {
                    # First part should be the hash
                    $hash = $parts[0].Trim()
                    # More lenient hash check - just needs to be hex or base64-like
                    if ($hash -match '^(?:0x)?[a-fA-F0-9]+$' -or $hash -match '^[A-Za-z0-9+/=]+$') {
                        # Fourth part (index 3) is the filepath, everything after might also be part of filepath or [CACHED]
                        # Join remaining parts in case filepath contains tabs
                        $filePath = ($parts[3..($parts.Count-1)] -join "`t").Trim()
                        $filePath = $filePath -replace '\s*\[CACHED\]\s*$', ''
                        if ($filePath) {
                            $verifyLogLines += "$filePath`: $hash"
                            continue
                        }
                    }
                }

                # Fallback: Try to match simple format: hash<tab>filename (2+ parts without Size/Modified)
                if ($parts.Count -ge 2 -and $parts[1] -notmatch '^Size:') {
                    $hash = $parts[0].Trim()
                    if ($hash -match '^(?:0x)?[a-fA-F0-9]+$' -or $hash -match '^[A-Za-z0-9+/=]+$') {
                        # Join all remaining parts (in case filepath has tabs)
                        $filePath = ($parts[1..($parts.Count-1)] -join "`t").Trim()
                        $filePath = $filePath -replace '\s*\[CACHED\]\s*$', ''
                        if ($filePath) {
                            $verifyLogLines += "$filePath`: $hash"
                            continue
                        }
                    }
                }

                # Final fallback: Try space-separated format: hash space filename
                if ($line -match '^((?:0x)?[a-fA-F0-9]+|[A-Za-z0-9+/=]+)\s+(.+)$') {
                    $hash = $matches[1].Trim()
                    $filePath = $matches[2].Trim() -replace '\s*\[CACHED\]\s*$', ''
                    if ($filePath) {
                        $verifyLogLines += "$filePath`: $hash"
                    }
                }
            }

            if ($verifyLogLines.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("No valid hash entries found in results.", "Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }

            # Write to file
            $verifyLogLines | Out-File -FilePath $saveDialog.FileName -Encoding UTF8

            [System.Windows.Forms.MessageBox]::Show("Verify log exported successfully.`n`n$($verifyLogLines.Count) entries saved to:`n$($saveDialog.FileName)`n`nYou can import this in the Verify tab.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$numericParallelThreads.Add_ValueChanged({
    $script:parallelThreadCount = [int]$numericParallelThreads.Value
    Save-Config
})

$numericNetworkTimeout.Add_ValueChanged({
    $script:networkPathTimeout = [int]$numericNetworkTimeout.Value
    Save-Config
})

$buttonBatchHash.Add_Click({
    if ($listBoxBatchFiles.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Add files first.", "No Files", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    if ($script:batchJobId) {
        [System.Windows.Forms.MessageBox]::Show("Batch operation already in progress.", "Busy", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Warn about very large batches
    if ($listBoxBatchFiles.Items.Count -gt 50000) {
        $result = [System.Windows.Forms.MessageBox]::Show(
            "You have $($listBoxBatchFiles.Items.Count) files selected. Processing this many files may take a very long time and consume significant resources.`n`nDo you want to continue?",
            "Large Batch Warning",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($result -eq [System.Windows.Forms.DialogResult]::No) {
            return
        }
    }

    # Check for network paths (skip for very large batches to avoid freeze)
    $networkFiles = @()
    $inaccessibleNetworkFiles = @()
    if ($listBoxBatchFiles.Items.Count -lt 10000) {
        foreach ($file in $listBoxBatchFiles.Items) {
            if (Test-Path $file) {
                if (Test-NetworkPath -path $file) {
                    $networkFiles += $file
                    $labelBatchFooter.Text = "Checking network path accessibility (timeout: $($script:networkPathTimeout)s per file)..."
                    $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange
                    [System.Windows.Forms.Application]::DoEvents()

                    if (-not (Test-NetworkPathAccessible -path $file)) {
                        $inaccessibleNetworkFiles += $file
                    }
                }
            }
        }
    } else {
        # Skip network check for very large batches
        $labelBatchFooter.Text = "Skipping network path check for large batch..."
        $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange
    }
    
    if ($inaccessibleNetworkFiles.Count -gt 0) {
        $msg = "The following network file(s) are not accessible or timed out:`n`n"
        $msg += ($inaccessibleNetworkFiles | ForEach-Object { [System.IO.Path]::GetFileName($_) }) -join "`n"
        $msg += "`n`nThe network share may be offline, unresponsive, or you may not have permission.`n`nDo you want to continue with accessible files only?"
        $result = [System.Windows.Forms.MessageBox]::Show($msg, "Network Files Inaccessible", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($result -eq [System.Windows.Forms.DialogResult]::No) {
            $labelBatchFooter.Text = "Batch operation cancelled"
            $labelBatchFooter.ForeColor = [System.Drawing.Color]::Red
            return
        }
        
        # Remove inaccessible files from the list
        foreach ($file in $inaccessibleNetworkFiles) {
            [void]$listBoxBatchFiles.Items.Remove($file)
        }
        
        if ($listBoxBatchFiles.Items.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No accessible files remaining.", "No Files", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            $labelBatchFooter.Text = "Ready"
            if ($checkDarkMode.Checked -and $script:DarkForeColor) { $labelBatchFooter.ForeColor = $script:DarkForeColor } else { $labelBatchFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray }
            return
        }
    } elseif ($networkFiles.Count -gt 0) {
        $labelBatchFooter.Text = "All $($networkFiles.Count) network file(s) accessible"
        $labelBatchFooter.ForeColor = [System.Drawing.Color]::Green
    }
    
    # Check for locked files (skip for large batches to avoid freeze)
    $lockedFiles = @()
    if ($listBoxBatchFiles.Items.Count -lt 10000) {
        foreach ($file in $listBoxBatchFiles.Items) {
            if (Test-Path $file) {
                if (Test-FileLocked -filePath $file) {
                    $lockedFiles += $file
                }
            }
        }

        if ($lockedFiles.Count -gt 0) {
            $msg = "The following file(s) are currently locked by another process:`n`n"
            $msg += ($lockedFiles | ForEach-Object { [System.IO.Path]::GetFileName($_) }) -join "`n"
            $msg += "`n`nPlease close these files and try again."
            [System.Windows.Forms.MessageBox]::Show($msg, "Files Locked", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
    }
    
    # Check for large files (skip for large batches to avoid freeze)
    $largeFiles = @()
    if ($listBoxBatchFiles.Items.Count -lt 10000) {
        foreach ($file in $listBoxBatchFiles.Items) {
            if (Test-Path $file) {
                $sizeGB = 0
                if (Test-LargeFile -filePath $file -sizeGB ([ref]$sizeGB)) {
                    $largeFiles += "$([System.IO.Path]::GetFileName($file)) ($sizeGB gigabytes)"
                }
            }
        }

        if ($largeFiles.Count -gt 0) {
            $msg = "The following file(s) are very large (>10GB):`n`n"
            $msg += $largeFiles -join "`n"
            $msg += "`n`nBatch processing may take considerable time and memory.`n`nContinue?"
            $result = [System.Windows.Forms.MessageBox]::Show($msg, "Large Files Warning", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($result -eq [System.Windows.Forms.DialogResult]::No) {
                return
            }
        }
    }

    # Check for special security attributes or key files that may cause hanging (skip for large batches to avoid freeze)
    $problematicFiles = @()
    if ($listBoxBatchFiles.Items.Count -lt 10000) {
        foreach ($file in $listBoxBatchFiles.Items) {
            if (Test-Path $file) {
                # Check if it's actually a directory (shouldn't be in file list)
                if (Test-Path $file -PathType Container) {
                    $problematicFiles += $file
                    continue
                }

                $fileName = [System.IO.Path]::GetFileName($file)
                $extension = [System.IO.Path]::GetExtension($file).ToLower()

                # Check for Recycle Bin and other special system folders/files
                $isRecycleBin = $fileName -match '(?i)(recycle|^\$recycle\.bin$|desktop\.ini)'

                # Check for God Mode folders or Control Panel items (CLSIDs in curly braces) - check full path
                $isGodModeOrCLSID = $file -match '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'

                # Check for archive files (can cause hanging in parallel batch processing)
                # Note: Archives hash fine in Main tab (single file), but can hang in batch mode
                $isArchive = $extension -eq '.zip' -or $extension -eq '.7z' -or $extension -eq '.rar' -or $extension -eq '.tar' -or $extension -eq '.gz' -or $extension -eq '.bz2' -or $extension -eq '.tgz'

                # Check for key files (SSH keys, PGP keys, certificates, etc.)
                $keyExtensions = @('.key', '.pem', '.ppk', '.pub', '.p12', '.pfx', '.cer', '.crt', '.der')
                $keyPatterns = @('_rsa', '_dsa', '_ecdsa', '_ed25519', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'no_key', 'private', 'publickey')

                $isKeyFile = $false
                if ($keyExtensions -contains $extension) {
                    $isKeyFile = $true
                } else {
                    foreach ($pattern in $keyPatterns) {
                        if ($fileName -like "*$pattern*") {
                            $isKeyFile = $true
                            break
                        }
                    }
                }

                # Check for special file attributes (System, Encrypted, Reparse Points/Symlinks, etc.)
                try {
                    $fileInfo = Get-Item -LiteralPath $file -Force -ErrorAction Stop
                    $hasSpecialAttributes = ($fileInfo.Attributes -band [System.IO.FileAttributes]::Encrypted) -or
                                           ($fileInfo.Attributes -band [System.IO.FileAttributes]::System) -or
                                           ($fileInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint)

                    # Also check if file is actually a shortcut (.lnk)
                    $isShortcut = $extension -eq '.lnk'

                    if ($isKeyFile -or $hasSpecialAttributes -or $isShortcut -or $isGodModeOrCLSID -or $isArchive -or $isRecycleBin) {
                        $problematicFiles += $file
                    }
                } catch {
                    # If we can't read attributes, consider it problematic
                    $problematicFiles += $file
                }
            }
        }

        if ($problematicFiles.Count -gt 0) {
            $msg = "Unable to hash certain selected files in batch mode due to special security attributes or file types:`n`n"
            $msg += "- Archive files (.zip, .7z, .rar, etc.) - can cause hanging in parallel processing`n"
            $msg += "- SSH keys, certificates, encrypted files`n"
            $msg += "- System folders (Recycle Bin, God Mode, etc.)`n`n"
            $msg += "Note: Archive files can be hashed individually in the Main tab.`n`n"
            $msg += "Continue without these files?"
            $result = [System.Windows.Forms.MessageBox]::Show($msg, "Unable to Hash Certain Files", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($result -eq [System.Windows.Forms.DialogResult]::No) {
                $labelBatchFooter.Text = "Batch operation cancelled"
                $labelBatchFooter.ForeColor = [System.Drawing.Color]::Red
                return
            }

            # Remove problematic files from the list
            foreach ($file in $problematicFiles) {
                [void]$listBoxBatchFiles.Items.Remove($file)
            }

            if ($listBoxBatchFiles.Items.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("No files remaining after removing problematic files.", "No Files", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                $labelBatchFooter.Text = "Ready"
                if ($checkDarkMode.Checked -and $script:DarkForeColor) { $labelBatchFooter.ForeColor = $script:DarkForeColor } else { $labelBatchFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray }
                return
            }
        }
    }

    try {
        $algoName = $comboBatchAlgo.SelectedItem
        $keyBytes = $null
        if ($algoName -like "HMAC*") { $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($textBoxBatchKey.Text) }
        $selectedFormat = if ($radioFormatUpper.Checked) { "uppercase" } elseif ($radioFormatHex.Checked) { "hex" } elseif ($radioFormatBase64.Checked) { "base64" } else { "lowercase" }

        # Show progress message BEFORE conversion for very large batches
        $totalFiles = $listBoxBatchFiles.Items.Count
        if ($totalFiles -gt 50000) {
            $labelBatchFooter.Text = "Preparing $totalFiles files for batch processing..."
            $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange
            [System.Windows.Forms.Application]::DoEvents()
        }

        # Convert listbox items to array (with chunked progress for very large batches)
        if ($totalFiles -gt 100000) {
            # For very large batches, use chunked conversion with progress updates
            $filesToHash = New-Object System.Collections.Generic.List[string]
            $chunkSize = 50000
            for ($i = 0; $i -lt $totalFiles; $i += $chunkSize) {
                $labelBatchFooter.Text = "Loading files... $([Math]::Min($i + $chunkSize, $totalFiles))/$totalFiles"
                [System.Windows.Forms.Application]::DoEvents()

                $endIndex = [Math]::Min($i + $chunkSize, $totalFiles)
                for ($j = $i; $j -lt $endIndex; $j++) {
                    $filesToHash.Add($listBoxBatchFiles.Items[$j])
                }
            }
            $filesToHash = $filesToHash.ToArray()
        } else {
            # For smaller batches, use fast direct conversion
            $filesToHash = @($listBoxBatchFiles.Items)
        }

        # Final progress update
        if ($totalFiles -gt 50000) {
            $labelBatchFooter.Text = "Files loaded - starting hash operation..."
            [System.Windows.Forms.Application]::DoEvents()
        }
        
        # Clear previous batch temp files to prevent duplicates
        if (Test-Path $script:batchTempFile) {
            Remove-Item $script:batchTempFile -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $script:batchProgressFile) {
            Remove-Item $script:batchProgressFile -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $script:batchFileProgressFile) {
            Remove-Item $script:batchFileProgressFile -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $script:batchCacheFile) {
            Remove-Item $script:batchCacheFile -Force -ErrorAction SilentlyContinue
        }

        $textBoxBatchResults.Text = "Starting parallel batch operation with $script:parallelThreadCount thread(s)...`r`n`r`n"
        $textBoxBatchResults.ScrollBars = "None"  # Hide scrollbars during batch operation
        $buttonBatchHash.Visible = $false
        $buttonBatchClear.Visible = $false
        $buttonBatchPause.Visible = $true
        $buttonBatchPause.Enabled = $true
        $buttonBatchStop.Visible = $true
        $buttonBatchStop.Enabled = $true
        $buttonBatchExport.Enabled = $false
        $buttonExportHashCheck.Enabled = $false
        $buttonExportSFV.Enabled = $false
        $buttonExportVerifyLog.Enabled = $false

        # Disable other hash operations to prevent conflicts
        $buttonGenerate.Enabled = $false
        $buttonDupFind.Enabled = $false
        $buttonVerify.Enabled = $false

        # Ensure timer is running to check batch job
        if (-not $uiTimer.Enabled) {
            $uiTimer.Start()
        }

        # Convert hashCache to array for serialization (optimized)
        $cacheArray = @()
        if ($script:hashCache -and $script:hashCache.Count -gt 0) {
            if ($script:hashCache.Count -gt 10000) {
                $labelBatchFooter.Text = "Loading hash cache ($($script:hashCache.Count) entries)..."
                $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange
                [System.Windows.Forms.Application]::DoEvents()
            }

            # Use more efficient array building
            $cacheArray = $script:hashCache.GetEnumerator() | ForEach-Object {
                @{Key = $_.Key; Value = $_.Value}
            }
        }
        
        # Start parallel batch job using runspaces
        $job = Start-Job -ScriptBlock {
            param($files, $algoName, $keyBytes, $format, $tempFile, $progressFile, $fileProgressFile, $speedFile, $threadCount, $cacheArray, $cacheFile, $pauseFile)
            
            # Helper function to check for pause
            function Wait-IfPaused {
                param($progressFile, $pauseFile, $completedCount, $totalFiles)
                while (Test-Path $pauseFile) {
                    # Write paused status with current progress
                    $percent = if ($totalFiles -gt 0) { [int](($completedCount * 100) / $totalFiles) } else { 0 }
                    try {
                        [System.IO.File]::WriteAllText($progressFile, "$completedCount|$percent|$totalFiles|PAUSED")
                    } catch { }
                    Start-Sleep -Milliseconds 500
                }
                return $true
            }

            # Reconstruct hashCache from array
            $hashCache = @{}
            if ($cacheArray) {
                foreach ($item in $cacheArray) {
                    $hashCache[$item.Key] = $item.Value
                }
            }

            # Load FastCRC32 class for correct CRC32 calculations
            try {
                $null = [FastCRC32]
            } catch {
                try {
                    Add-Type -TypeDefinition @"
using System;
using System.IO;

public class FastCRC32
{
    private static uint[] crcTable;

    static FastCRC32()
    {
        crcTable = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int j = 0; j < 8; j++)
            {
                if ((c & 1) != 0)
                    c = (c >> 1) ^ 0xEDB88320;
                else
                    c >>= 1;
            }
            crcTable[i] = c;
        }
    }

    public static uint ComputeHashStream(Stream stream)
    {
        uint crc = 0xFFFFFFFF;
        byte[] buffer = new byte[65536];
        int count;

        while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i < count; i++)
            {
                byte index = (byte)(crc ^ buffer[i]);
                crc = (crc >> 8) ^ crcTable[index];
            }
        }
        return crc ^ 0xFFFFFFFF;
    }
}
"@ -ErrorAction Stop
                } catch {
                    # FastCRC32 loading failed, will use PowerShell fallback
                }
            }

            function Format-HashOutputLocal {
                param($hashHex, [string]$format)
                switch ($format) {
                    "lowercase" { return $hashHex }
                    "uppercase" { return $hashHex.ToUpperInvariant() }
                    "hex" { return "0x" + $hashHex }
                    "base64" {
                        $bytes = New-Object byte[] ($hashHex.Length / 2)
                        for ($i = 0; $i -lt $hashHex.Length; $i += 2) {
                            $bytes[$i / 2] = [System.Convert]::ToByte($hashHex.Substring($i, 2), 16)
                        }
                        return [System.Convert]::ToBase64String($bytes)
                    }
                    default { return $hashHex }
                }
            }
            
            # Create runspace pool for parallel processing
            $runspacePool = [runspacefactory]::CreateRunspacePool(1, $threadCount)
            $runspacePool.Open()
            
            $scriptBlock = {
                param($file, $algoName, $keyBytes, $format, $fileIndex, $totalFiles, $hashCache, $fileProgressFile, $speedFile, $cacheFile)

                $result = @{
                    Index = $fileIndex
                    File = $file
                    Hash = $null
                    Size = "N/A"
                    Modified = "N/A"
                    Error = $null
                    Cached = $false
                }

                # Indicate this file is being processed
                try {
                    [System.IO.File]::WriteAllText($fileProgressFile, "0|$fileIndex")
                } catch { }
                
                try {
                    if (Test-Path $file -ErrorAction SilentlyContinue) {
                        # Check cache first
                        $fileItem = Get-Item -LiteralPath $file -ErrorAction SilentlyContinue
                        if ($fileItem) {
                            $cacheKey = "$file|$algoName|$format"
                            if ($hashCache -and $hashCache.ContainsKey($cacheKey)) {
                                $cached = $hashCache[$cacheKey]
                                # Verify file hasn't changed since cache
                                if ($cached.Modified -and $cached.Size) {
                                    try {
                                        $cachedModified = [DateTime]::Parse($cached.Modified)
                                        if ($fileItem.LastWriteTime -eq $cachedModified -and $fileItem.Length -eq $cached.Size) {
                                            # Use cached hash - it's already formatted
                                            $result.Hash = $cached.Hash
                                            $result.Cached = $true
                                            $fileSize = $fileItem.Length
                                            $result.Size = if ($fileSize -lt 1KB) { "$fileSize bytes" } 
                                                           elseif ($fileSize -lt 1MB) { "{0:N2} KB" -f ($fileSize / 1KB) }
                                                           elseif ($fileSize -lt 1GB) { "{0:N2} MB" -f ($fileSize / 1MB) }
                                                           else { "{0:N2} GB" -f ($fileSize / 1GB) }
                                            $result.Modified = $fileItem.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                                            return $result
                                        }
                                    } catch { }
                                }
                            }
                        }
                        $fs = [System.IO.File]::OpenRead($file)
                        try {
                            $fileSize = $fs.Length
                            $bufferSize = 65536
                            $buffer = New-Object byte[] $bufferSize
                            $bytesRead = 0
                            $totalBytesRead = 0
                            $startTime = [DateTime]::Now
                            $lastProgressUpdate = [DateTime]::MinValue
                            $lastPercent = -1

                            if ($algoName -eq "CRC32") {
                                # Use C# FastCRC32 implementation for correct results
                                try {
                                    $hashValue = [FastCRC32]::ComputeHashStream($fs)
                                    $hash = $hashValue.ToString("x8")
                                } catch {
                                    $result.Error = "CRC32 calculation failed: $($_.Exception.Message)"
                                    return $result
                                }
                            } else {
                                switch ($algoName) {
                                    "SHA256" { $algo = [System.Security.Cryptography.SHA256]::Create() }
                                    "SHA1"   { $algo = [System.Security.Cryptography.SHA1]::Create() }
                                    "SHA512" { $algo = [System.Security.Cryptography.SHA512]::Create() }
                                    "MD5"    { $algo = [System.Security.Cryptography.MD5]::Create() }
                                    "SHA384" { $algo = [System.Security.Cryptography.SHA384]::Create() }
                                    "RIPEMD160" { $algo = [System.Security.Cryptography.RIPEMD160]::Create() }
                                    "HMACSHA256" { $algo = [System.Security.Cryptography.HMACSHA256]::new($keyBytes) }
                                    "HMACSHA512" { $algo = [System.Security.Cryptography.HMACSHA512]::new($keyBytes) }
                                    default { throw "Unsupported algorithm" }
                                }

                                $algo.Initialize()
                                while (($bytesRead = $fs.Read($buffer, 0, $bufferSize)) -gt 0) {
                                    [void]$algo.TransformBlock($buffer, 0, $bytesRead, $buffer, 0)
                                    $totalBytesRead += $bytesRead
                                    $percent = if ($fileSize -gt 0) { [int](($totalBytesRead * 100) / $fileSize) } else { 100 }

                                    # Only update progress if percent changed or 100ms elapsed (prevents jumping)
                                    $now = [DateTime]::Now
                                    if ($percent -ne $lastPercent -or ($now - $lastProgressUpdate).TotalMilliseconds -gt 100) {
                                        $elapsed = ($now - $startTime).TotalSeconds
                                        if ($elapsed -gt 0) {
                                            $speedMBs = ($totalBytesRead / 1MB) / $elapsed
                                            try {
                                                [System.IO.File]::WriteAllText($fileProgressFile, "$percent|$fileIndex")
                                                [System.IO.File]::WriteAllText($speedFile, $speedMBs.ToString("F2"))
                                            } catch { }
                                            $lastProgressUpdate = $now
                                            $lastPercent = $percent
                                        }
                                    }
                                }
                                [void]$algo.TransformFinalBlock($buffer, 0, 0)
                                $hashBytes = $algo.Hash
                                $hash = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLowerInvariant()
                                if ($algo) { $algo.Dispose() }
                            }
                            
                            # Format hash
                            switch ($format) {
                                "lowercase" { $result.Hash = $hash }
                                "uppercase" { $result.Hash = $hash.ToUpperInvariant() }
                                "hex" { $result.Hash = "0x" + $hash }
                                "base64" {
                                    $bytes = New-Object byte[] ($hash.Length / 2)
                                    for ($i = 0; $i -lt $hash.Length; $i += 2) {
                                        $bytes[$i / 2] = [System.Convert]::ToByte($hash.Substring($i, 2), 16)
                                    }
                                    $result.Hash = [System.Convert]::ToBase64String($bytes)
                                }
                                default { $result.Hash = $hash }
                            }
                            
                            # Get file details
                            $fileItem = Get-Item -LiteralPath $file -ErrorAction SilentlyContinue
                            if ($fileItem) {
                                $fileSize = $fileItem.Length
                                $result.Size = if ($fileSize -lt 1KB) { "$fileSize bytes" }
                                               elseif ($fileSize -lt 1MB) { "{0:N2} KB" -f ($fileSize / 1KB) }
                                               elseif ($fileSize -lt 1GB) { "{0:N2} MB" -f ($fileSize / 1MB) }
                                               else { "{0:N2} GB" -f ($fileSize / 1GB) }
                                $result.Modified = $fileItem.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")

                                # Write cache entry immediately (incremental caching)
                                if ($result.Hash -and -not $result.Cached) {
                                    $cacheEntry = "$file|$algoName|$format|$($result.Hash)|$($fileItem.LastWriteTime.ToString('o'))|$($fileItem.Length)|$([DateTime]::Now.ToString('o'))"
                                    try {
                                        [System.IO.File]::AppendAllText($cacheFile, $cacheEntry + [Environment]::NewLine)
                                    } catch { }
                                }
                            }
                        } finally {
                            if ($fs) { $fs.Close(); $fs.Dispose() }
                        }
                    } else {
                        $result.Error = "File not found"
                    }
                } catch {
                    $result.Error = $_.Exception.Message
                    # Try to get file info even on error
                    $fileItem = Get-Item -LiteralPath $file -ErrorAction SilentlyContinue
                    if ($fileItem) {
                        $fileSize = $fileItem.Length
                        $result.Size = if ($fileSize -lt 1KB) { "$fileSize bytes" } 
                                       elseif ($fileSize -lt 1MB) { "{0:N2} KB" -f ($fileSize / 1KB) }
                                       elseif ($fileSize -lt 1GB) { "{0:N2} MB" -f ($fileSize / 1MB) }
                                       else { "{0:N2} GB" -f ($fileSize / 1GB) }
                        $result.Modified = $fileItem.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    }
                }
                
                return $result
            }
            
            # Create runspace jobs - launch gradually to allow pausing
            $runspaces = New-Object System.Collections.ArrayList
            $totalFiles = $files.Count
            $fileIndex = 0
            $filesToLaunch = New-Object System.Collections.Queue
            foreach ($file in $files) {
                $filesToLaunch.Enqueue($file)
            }
            
            # Wait for all runspaces to complete and collect results
            $completedCount = 0
            $results = @{}
            $writtenIndices = @{}  # Track which results have been written to prevent duplicates

            while ($runspaces.Count -gt 0 -or $filesToLaunch.Count -gt 0) {
                # Check for pause and update status
                Wait-IfPaused $progressFile $pauseFile $completedCount $totalFiles

                # Launch new runspaces up to thread limit (if not paused)
                if (-not (Test-Path $pauseFile)) {
                    while ($runspaces.Count -lt $threadCount -and $filesToLaunch.Count -gt 0) {
                        $file = $filesToLaunch.Dequeue()
                        $fileIndex++
                        $powershell = [powershell]::Create().AddScript($scriptBlock).AddArgument($file).AddArgument($algoName).AddArgument($keyBytes).AddArgument($format).AddArgument($fileIndex).AddArgument($totalFiles).AddArgument($hashCache).AddArgument($fileProgressFile).AddArgument($speedFile).AddArgument($cacheFile)
                        $powershell.RunspacePool = $runspacePool

                        [void]$runspaces.Add([PSCustomObject]@{
                            Pipe = $powershell
                            Status = $powershell.BeginInvoke()
                            Index = $fileIndex
                            File = $file
                        })
                    }
                }

                $toRemove = New-Object System.Collections.ArrayList

                foreach ($rs in $runspaces) {
                    if ($rs.Status.IsCompleted) {
                        try {
                            $result = $rs.Pipe.EndInvoke($rs.Status)
                            # EndInvoke returns an array, get the first element
                            if ($result -is [System.Collections.ICollection] -and $result.Count -gt 0) {
                                $result = $result[0]
                            }
                            $results[$result.Index] = $result

                            # Only write if not already written (prevent duplicates)
                            if (-not $writtenIndices.ContainsKey($result.Index)) {
                                $completedCount++
                                $writtenIndices[$result.Index] = $true

                                # Write result immediately for real-time display
                                if ($result.Error) {
                                    $resultLine = "ERROR: $($result.Error)`tSize: $($result.Size)`tModified: $($result.Modified)`t$($result.File)"
                                } else {
                                    $hashValue = if ($result.Hash) { $result.Hash.Trim() } else { "" }
                                    $isCached = if ($result.ContainsKey('Cached')) { $result.Cached } else { $false }
                                    $cachedMarker = if ($isCached) { "`t[CACHED]" } else { "" }
                                    $resultLine = "$hashValue`tSize: $($result.Size)`tModified: $($result.Modified)`t$($result.File)$cachedMarker"
                                }
                                try {
                                    [System.IO.File]::AppendAllText($tempFile, $resultLine + [Environment]::NewLine)
                                } catch { }

                                # Update progress
                                $percent = [int](($completedCount * 100) / $totalFiles)
                                try {
                                    [System.IO.File]::WriteAllText($progressFile, "$completedCount|$percent|$totalFiles")
                                } catch { }
                            }

                            [void]$toRemove.Add($rs)
                        } catch {
                            # Handle error - only write if not already written
                            if (-not $writtenIndices.ContainsKey($rs.Index)) {
                                $results[$rs.Index] = @{
                                    Index = $rs.Index
                                    File = $rs.File
                                    Hash = $null
                                    Size = "N/A"
                                    Modified = "N/A"
                                    Error = $_.Exception.Message
                                    Cached = $false
                                }
                                $completedCount++
                                $writtenIndices[$rs.Index] = $true

                                # Write error result immediately
                                $resultLine = "ERROR: $($_.Exception.Message)`tSize: N/A`tModified: N/A`t$($rs.File)"
                                try {
                                    [System.IO.File]::AppendAllText($tempFile, $resultLine + [Environment]::NewLine)
                                } catch { }
                            }

                            [void]$toRemove.Add($rs)
                        } finally {
                            $rs.Pipe.Dispose()
                        }
                    }
                }

                # Remove completed runspaces
                foreach ($rs in $toRemove) {
                    [void]$runspaces.Remove($rs)
                }

                Start-Sleep -Milliseconds 100
            }
            
            # All results have been written in real-time, just cleanup
            $runspacePool.Close()
            $runspacePool.Dispose()

        } -ArgumentList $filesToHash, $algoName, $keyBytes, $selectedFormat, $script:batchTempFile, $script:batchProgressFile, $script:batchFileProgressFile, $hashSpeedFile, $script:parallelThreadCount, $cacheArray, $script:batchCacheFile, $script:batchPauseFile

        $script:batchJobId = $job.Id
        $script:batchTotalFiles = $filesToHash.Count
        $script:batchCurrentFile = 0
        $script:batchLastDisplayedLength = 0  # Track how much of the temp file we've displayed
        $textBoxBatchResults.Clear()
        # Results will appear as they are written to the temp file

        # Force UI update to prevent "not responding" appearance
        $labelBatchFooter.Text = "Batch job started - processing $($filesToHash.Count) file(s)..."
        $labelBatchFooter.ForeColor = [System.Drawing.Color]::DarkOrange
        [System.Windows.Forms.Application]::DoEvents()
        
    } catch {
        $textBoxBatchResults.Text = "Error: $($_.Exception.Message)"
        $buttonBatchHash.Visible = $true
        $buttonBatchClear.Visible = $true
        $buttonBatchPause.Visible = $false
        $buttonBatchPause.Enabled = $false
        $buttonBatchStop.Visible = $false
        $buttonBatchStop.Enabled = $false
        $buttonBatchExport.Enabled = $true
        $buttonExportHashCheck.Enabled = $true
        $buttonExportSFV.Enabled = $true
        $buttonExportVerifyLog.Enabled = $true
    }
})

# Progress polling timer
$script:hashProgress = 0
$script:hashDone = $false
$script:hashResult = $null
$script:hashError = $null

$uiTimer = New-Object System.Windows.Forms.Timer
$uiTimer.Interval = 250
$uiTimer.Add_Tick({
    try {
        if (Test-Path $hashProgressFile) {
            try { $script:hashProgress = [int]([System.IO.File]::ReadAllText($hashProgressFile)) } catch { }
        }

        if (Test-Path $hashResultFile) {
            try {
                $script:hashResult = [System.IO.File]::ReadAllText($hashResultFile)
                $script:hashDone = $true
                Clear-HashTempFiles
            } catch { }
        }

        if (Test-Path $hashErrorFile) {
            try {
                $script:hashError = [System.IO.File]::ReadAllText($hashErrorFile)
                $script:hashDone = $true
                Clear-HashTempFiles
            } catch { }
        }

        # Update progress bar with smoothing to reduce jitter
        $targetWidth = [int](($panelProgressBackground.Width * $script:hashProgress) / 100)
        if ($targetWidth -lt 0) { $targetWidth = 0 }
        if ($targetWidth -gt $panelProgressBackground.Width) { $targetWidth = $panelProgressBackground.Width }
        
        # Smooth progress: move towards target gradually
        $currentWidth = $panelProgressFill.Width
        if ($targetWidth -gt $currentWidth) {
            $step = [int]([math]::Max(1, ($targetWidth - $currentWidth) / 5))
            $panelProgressFill.Width = [int]([math]::Min($targetWidth, $currentWidth + $step))
        } elseif ($targetWidth -lt $currentWidth -and $targetWidth -lt $panelProgressBackground.Width) {
            # Only decrease if not at or near end
            $panelProgressFill.Width = $targetWidth
        } else {
            $panelProgressFill.Width = $targetWidth
        }
        
        # Display speed if available
        $speedText = ""
        if (Test-Path $hashSpeedFile) {
            try {
                $speed = [System.IO.File]::ReadAllText($hashSpeedFile)
                $speedText = " - $speed MB/s"
            } catch { }
        }
        
        $labelFooter.Text = "Progress: " + $script:hashProgress.ToString() + "%" + $speedText

        if ($script:hashDone) {
            $uiTimer.Stop()
            $panelProgressFill.Width = $panelProgressBackground.Width
            Start-Sleep -Milliseconds 300
            $panelProgressFill.Width = 0
            $buttonStop.Enabled = $false
            $buttonGenerate.Enabled = $true
            $script:currentJobId = $null

            if ($script:hashError) {
                $textBoxResult.BackColor = [System.Drawing.Color]::LightYellow
                $textBoxResult.Text = "Error: " + $script:hashError
                $labelFooter.Text = "Error occurred"
                } elseif ($script:hashResult) {

                # respect dark mode theme for output background/foreground
                if ($checkDarkMode.Checked -and $script:DarkPanelColor) {
                    $textBoxResult.BackColor = $script:DarkPanelColor
                    $textBoxResult.ForeColor = $script:DarkOutputFore
                } else {
                    $textBoxResult.BackColor = [System.Drawing.Color]::White
                    $textBoxResult.ForeColor = [System.Drawing.Color]::Black
                }
                
                # Apply output formatting
                $selectedFormat = if ($radioFormatUpper.Checked) { "uppercase" } elseif ($radioFormatHex.Checked) { "hex" } elseif ($radioFormatBase64.Checked) { "base64" } else { "lowercase" }
                $formattedHash = Format-HashOutput -hashHex $script:hashResult -format $selectedFormat
                
                # Get file details
                $fileInfo = Get-Item -LiteralPath $textBoxInput.Text -ErrorAction SilentlyContinue
                $fileDetails = ""
                if ($fileInfo) {
                    $fileSize = $fileInfo.Length
                    $sizeStr = if ($fileSize -lt 1KB) { "$fileSize bytes" } 
                               elseif ($fileSize -lt 1MB) { "{0:N2} KB" -f ($fileSize / 1KB) }
                               elseif ($fileSize -lt 1GB) { "{0:N2} MB" -f ($fileSize / 1MB) }
                               else { "{0:N2} GB" -f ($fileSize / 1GB) }
                    $modifiedDate = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    $fullPath = $fileInfo.FullName
                    $fileDetails = "`r`n`r`nFile: $fullPath`r`nSize: $sizeStr`r`nModified: $modifiedDate"
                }
                
                $textBoxResult.Font = $script:fontOutput
                # Format with hash on single line, file details below
                $textBoxResult.Text = $formattedHash + $fileDetails
                 $script:generatedHash = $formattedHash
                 $labelFooter.Text = "Hash generated successfully"

                if ($checkAutoCopy.Checked) { [System.Windows.Forms.Clipboard]::SetText($formattedHash) }
                
                # Cache the hash result for file mode
                if ($radioFile.Checked -and $fileInfo) {
                    $currentAlgo = $comboAlgo.SelectedItem
                    Set-CachedHash -filePath $textBoxInput.Text -algorithm $currentAlgo -format $selectedFormat -hash $formattedHash
                }
                
                if ($checkLog.Checked) {
                    $timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
                    $mode = if ($radioString.Checked) { "String" } else { "File" }
                    $currentFormat = if ($radioFormatUpper.Checked) { "uppercase" } elseif ($radioFormatHex.Checked) { "hex" } elseif ($radioFormatBase64.Checked) { "base64" } else { "lowercase" }
                    
                    # Get file details for log
                    $sizeField = "N/A"
                    $modifiedField = "N/A"
                    if ($radioFile.Checked -and $fileInfo) {
                        $fileSize = $fileInfo.Length
                        $sizeField = if ($fileSize -lt 1KB) { "$fileSize bytes" } 
                                     elseif ($fileSize -lt 1MB) { "{0:N2} KB" -f ($fileSize / 1KB) }
                                     elseif ($fileSize -lt 1GB) { "{0:N2} MB" -f ($fileSize / 1MB) }
                                     else { "{0:N2} GB" -f ($fileSize / 1GB) }
                        $modifiedField = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    }
                    
                    $line = "$timestamp | Mode: $mode | Input: $($textBoxInput.Text) | Algo: $($comboAlgo.SelectedItem) | Format: $currentFormat | Size: $sizeField | Modified: $modifiedField | Hash: $formattedHash"
                    [System.IO.File]::AppendAllText($logPath, $line + [Environment]::NewLine)
                }
                
                # Show toast notification for file mode
                if ($radioFile.Checked -and $checkToastNotifications.Checked) {
                    $fileName = [System.IO.Path]::GetFileName($textBoxInput.Text)
                    Show-ToastNotification -title "Hash Complete" -message "File: $fileName"
                }
                
                # Show balloon tip if minimized to tray (only if toast notifications are disabled)
                if ($form.WindowState -eq 'Minimized' -and $script:notifyIcon -and $script:notifyIcon.Visible -and -not $checkToastNotifications.Checked) {
                    $fileName = [System.IO.Path]::GetFileName($textBoxInput.Text)
                    $script:notifyIcon.BalloonTipTitle = "Hash Complete"
                    $script:notifyIcon.BalloonTipText = "File: $fileName"
                    $script:notifyIcon.BalloonTipIcon = 'Info'
                    $script:notifyIcon.ShowBalloonTip(5000)
                }
            }

            $script:hashProgress = 0
            $script:hashDone = $false
            $script:hashResult = $null
            $script:hashError = $null
        }
        
        # Auto-refresh log viewer if log file exists (happens after hash completion)
        try {
            if ((Test-Path $logPath) -and ((Get-Item $logPath).Length -gt 0)) {
                $textBoxLogViewer.Text = Add-LineNumbers ([System.IO.File]::ReadAllText($logPath))
            } elseif (Test-Path $logPath) {
                $textBoxLogViewer.Text = "No log entries."
            }
        } catch { }

        # Check batch file loading job
        if ($script:batchLoadingJobId) {
            $loadJob = Get-Job -Id $script:batchLoadingJobId -ErrorAction SilentlyContinue

            # Only process after job completes to ensure all data is written
            if ($loadJob -and $loadJob.State -eq 'Completed' -and (Test-Path $script:batchLoadingTempFile)) {
                # Give a tiny delay to ensure file is fully flushed
                Start-Sleep -Milliseconds 100

                try {
                    # Read entire file using StreamReader with ReadWrite share to avoid locking issues
                    $fileStream = $null
                    $reader = $null
                    try {
                        $fileStream = [System.IO.FileStream]::new($script:batchLoadingTempFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                        $reader = [System.IO.StreamReader]::new($fileStream)

                        # Read entire file content
                        $content = $reader.ReadToEnd()

                        if (-not [string]::IsNullOrWhiteSpace($content)) {
                            $addedThisRound = 0
                            $isComplete = $false
                            $hasError = $false
                            $errorMsg = ""

                            # Check for completion/error markers
                            if ($content -match "===COMPLETE===\|(\d+)") {
                                $isComplete = $true
                            }
                            if ($content -match "===ERROR===\|(.+)") {
                                $errorMsg = $matches[1]
                                $hasError = $true
                            }

                            # Process all batches - wait until job completes before adding to ListBox
                            if ($isComplete) {
                                # Job complete - now add all files to ListBox in one shot
                                $labelBatchFooter.Text = "Processing file list..."
                                $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange
                                [System.Windows.Forms.Application]::DoEvents()

                                $batches = $content -split "===BATCH==="
                                $filesToAdd = New-Object System.Collections.Generic.List[string]

                                # First pass - collect all unique files
                                foreach ($batch in $batches) {
                                    $batch = $batch.Trim()
                                    if ([string]::IsNullOrWhiteSpace($batch)) { continue }
                                    if ($batch -match "===COMPLETE===|===ERROR===") { continue }

                                    if ($batch -match "^(\d+)\|") {
                                        $filePathsSection = $batch.Substring($matches[0].Length)
                                        $filePaths = $filePathsSection -split "[\r\n]+" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

                                        foreach ($filePath in $filePaths) {
                                            $cleanPath = $filePath.Trim()
                                            if (-not [string]::IsNullOrWhiteSpace($cleanPath) -and $script:batchLoadingAddedFiles.Add($cleanPath)) {
                                                $filesToAdd.Add($cleanPath)
                                                $addedThisRound++
                                            }
                                        }
                                    }
                                }

                                # Second pass - add all to ListBox with updates suspended
                                if ($filesToAdd.Count -gt 0) {
                                    $labelBatchFooter.Text = "Adding $($filesToAdd.Count) files to list..."
                                    [System.Windows.Forms.Application]::DoEvents()

                                    $listBoxBatchFiles.BeginUpdate()
                                    try {
                                        $listBoxBatchFiles.Items.AddRange($filesToAdd.ToArray())
                                    } catch {
                                        # AddRange failed, fall back to individual adds
                                        foreach ($file in $filesToAdd) {
                                            [void]$listBoxBatchFiles.Items.Add($file)
                                        }
                                    } finally {
                                        $listBoxBatchFiles.EndUpdate()
                                    }
                                } else {
                                    # Debug: no files collected
                                    $labelBatchFooter.Text = "Debug: 0 files collected from batches (batches: $($batches.Count))"
                                    $labelBatchFooter.ForeColor = [System.Drawing.Color]::Red
                                }
                            } else {
                                # Job still running - don't process yet, just update footer
                                $labelBatchFooter.Text = "Enumerating files..."
                                $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange
                            }

                            # Update footer with current count
                            if (-not $isComplete -and -not $hasError) {
                                $currentCount = $listBoxBatchFiles.Items.Count
                                $labelBatchFooter.Text = "Loading files... ($currentCount found so far)"
                                $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange
                            }

                            # Handle completion or error
                            if ($isComplete -or $hasError) {
                                # Hide and stop spinner
                                $script:spinnerTimer.Stop()
                                $script:batchLoadingSpinner.Visible = $false

                                # Clean up
                                Remove-Item $script:batchLoadingTempFile -Force -ErrorAction SilentlyContinue
                                if ($loadJob) {
                                    Remove-Job -Id $script:batchLoadingJobId -Force -ErrorAction SilentlyContinue
                                }
                                $script:batchLoadingJobId = $null
                                $script:batchLoadingAddedFiles = $null
                                $buttonBatchAdd.Enabled = $true
                                Update-BatchFilesListExtent

                                # Show final status
                                if ($hasError) {
                                    $labelBatchFooter.Text = "Error loading files: $errorMsg"
                                    $labelBatchFooter.ForeColor = [System.Drawing.Color]::Red
                                } else {
                                    $totalAdded = $listBoxBatchFiles.Items.Count
                                    # Extract expected count from completion marker for debugging
                                    $expectedCount = 0
                                    if ($content -match "===COMPLETE===\|(\d+)") {
                                        $expectedCount = [int]$matches[1]
                                    }
                                    if ($totalAdded -gt 0) {
                                        if ($expectedCount -gt 0 -and $expectedCount -ne $totalAdded) {
                                            $labelBatchFooter.Text = "Warning: Loaded $totalAdded of $expectedCount files (enumeration issue)"
                                            $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange
                                        } else {
                                            $labelBatchFooter.Text = "Folder loading complete - $totalAdded file(s) total"
                                            $labelBatchFooter.ForeColor = [System.Drawing.Color]::LimeGreen
                                        }
                                    } else {
                                        $labelBatchFooter.Text = "No files found in folder"
                                        $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange
                                    }
                                }
                            }
                        }
                    } finally {
                        if ($reader) { $reader.Close() }
                        if ($fileStream) { $fileStream.Close() }
                    }
                } catch {
                    # Silently ignore read errors (file might be locked temporarily)
                    # Only clean up if job is no longer running
                    if ($loadJob -and ($loadJob.State -eq 'Completed' -or $loadJob.State -eq 'Failed' -or $loadJob.State -eq 'Stopped')) {
                        $script:spinnerTimer.Stop()
                        $script:batchLoadingSpinner.Visible = $false
                        if (Test-Path $script:batchLoadingTempFile) {
                            Remove-Item $script:batchLoadingTempFile -Force -ErrorAction SilentlyContinue
                        }
                        Remove-Job -Id $script:batchLoadingJobId -Force -ErrorAction SilentlyContinue
                        $script:batchLoadingJobId = $null
                        $script:batchLoadingAddedFiles = $null
                        $buttonBatchAdd.Enabled = $true
                        $labelBatchFooter.Text = "Error loading files: $($_.Exception.Message)"
                        $labelBatchFooter.ForeColor = [System.Drawing.Color]::Red
                    }
                }
            } elseif ($loadJob -and $loadJob.State -eq 'Completed') {
                # Job completed but no temp file - clean up
                $script:spinnerTimer.Stop()
                $script:batchLoadingSpinner.Visible = $false
                Remove-Job -Id $script:batchLoadingJobId -Force -ErrorAction SilentlyContinue
                $script:batchLoadingJobId = $null
                $script:batchLoadingAddedFiles = $null
                $buttonBatchAdd.Enabled = $true
                Update-BatchFilesListExtent
                $totalCount = $listBoxBatchFiles.Items.Count
                $labelBatchFooter.Text = "Folder loading complete - $totalCount file(s) total"
                $labelBatchFooter.ForeColor = [System.Drawing.Color]::LimeGreen
            } elseif ($loadJob -and ($loadJob.State -eq 'Failed' -or $loadJob.State -eq 'Stopped')) {
                # Job failed or stopped
                $script:spinnerTimer.Stop()
                $script:batchLoadingSpinner.Visible = $false
                Remove-Job -Id $script:batchLoadingJobId -Force -ErrorAction SilentlyContinue
                $script:batchLoadingJobId = $null
                $script:batchLoadingAddedFiles = $null
                $buttonBatchAdd.Enabled = $true
                $labelBatchFooter.Text = "File loading cancelled or failed"
                $labelBatchFooter.ForeColor = [System.Drawing.Color]::Orange
            }
        }

        # Check batch job completion
        if ($script:batchJobId) {
            # Update file-level progress (format: filePercent|fileIndex)
            if (Test-Path $script:batchFileProgressFile) {
                try {
                    $fileProgressData = [System.IO.File]::ReadAllText($script:batchFileProgressFile)
                    $fileParts = $fileProgressData -split '\|'
                    if ($fileParts.Count -eq 2) {
                        $filePercent = [int]$fileParts[0]
                        # $currentFileIndex = [int]$fileParts[1]  # Removed unused variable assignment

                        # Smooth file progress bar update
                        $targetFileWidth = [int](($panelBatchFileProgressBackground.Width * $filePercent) / 100)
                        if ($targetFileWidth -lt 0) { $targetFileWidth = 0 }
                        if ($targetFileWidth -gt $panelBatchFileProgressBackground.Width) { $targetFileWidth = $panelBatchFileProgressBackground.Width }

                        # Smooth progress: move towards target gradually
                        $currentFileWidth = $panelBatchFileProgressFill.Width
                        if ($targetFileWidth -gt $currentFileWidth) {
                            # Increasing - gradual
                            $step = [int]([math]::Max(1, ($targetFileWidth - $currentFileWidth) / 5))
                            $panelBatchFileProgressFill.Width = [int]([math]::Min($targetFileWidth, $currentFileWidth + $step))
                        } elseif ($targetFileWidth -lt $currentFileWidth) {
                            # Decreasing (new file started) - also gradual to reduce jumping
                            $step = [int]([math]::Max(1, ($currentFileWidth - $targetFileWidth) / 3))
                            $panelBatchFileProgressFill.Width = [int]([math]::Max($targetFileWidth, $currentFileWidth - $step))
                        } else {
                            $panelBatchFileProgressFill.Width = $targetFileWidth
                        }

                        # Display speed if available for file progress
                        $fileSpeedText = ""
                        if (Test-Path $hashSpeedFile) {
                            try {
                                $fileSpeed = [System.IO.File]::ReadAllText($hashSpeedFile)
                                $fileSpeedText = "$fileSpeed MB/s - "
                            } catch { }
                        }

                        $labelBatchFilePercent.Text = "$fileSpeedText$filePercent%"
                        $script:batchFileProgress = $filePercent
                    }
                } catch { }
            }

            # Update batch progress (format: completedCount|overallPercent|totalFiles)
            if (Test-Path $script:batchProgressFile) {
                try {
                    $progressData = [System.IO.File]::ReadAllText($script:batchProgressFile)
                    $parts = $progressData -split '\|'

                    # Check for PAUSED phase (4 parts with last part being "PAUSED")
                    if ($parts.Count -eq 4 -and $parts[3] -eq "PAUSED") {
                        # Update footer to show paused state
                        $currentFooter = $labelBatchFooter.Text
                        if ($currentFooter -notlike "*paused*") {
                            $labelBatchFooter.Text = $currentFooter -replace "$", " - paused"
                        }
                        # Don't update batch progress bar when paused
                    } elseif ($parts.Count -eq 3 -and -not $script:batchShouldPause) {
                        $completedCount = [int]$parts[0]
                        $overallPercent = [int]$parts[1]
                        $totalFiles = [int]$parts[2]

                        $script:batchCurrentFile = $completedCount
                        $script:batchTotalFiles = $totalFiles

                        # Smooth batch progress bar update
                        $targetWidth = [int](($panelBatchProgressBackground.Width * $overallPercent) / 100)
                        if ($targetWidth -lt 0) { $targetWidth = 0 }
                        if ($targetWidth -gt $panelBatchProgressBackground.Width) { $targetWidth = $panelBatchProgressBackground.Width }

                        # Smooth progress: move towards target gradually
                        $currentWidth = $panelBatchProgressFill.Width
                        if ($targetWidth -gt $currentWidth) {
                            $step = [int]([math]::Max(1, ($targetWidth - $currentWidth) / 5))
                            $panelBatchProgressFill.Width = [int]([math]::Min($targetWidth, $currentWidth + $step))
                        } elseif ($targetWidth -lt $currentWidth -and $targetWidth -lt $panelBatchProgressBackground.Width) {
                            # Only decrease if not at or near end
                            $panelBatchProgressFill.Width = $targetWidth
                        } else {
                            $panelBatchProgressFill.Width = $targetWidth
                        }

                        $labelBatchOverallPercent.Text = "$overallPercent%"

                        $labelBatchFooter.Text = "Files completed: $completedCount/$totalFiles - Overall: $overallPercent%"
                    }
                } catch { }
            }
            
            $batchJob = Get-Job -Id $script:batchJobId -ErrorAction SilentlyContinue
            if ($batchJob) {
                # Read and display results as they're written (skip update when paused to prevent flashing)
                if ((Test-Path $script:batchTempFile) -and -not $script:batchShouldPause) {
                    try {
                        # Use FileStream with FileShare.ReadWrite to avoid locking issues
                        $fileStream = [System.IO.File]::Open($script:batchTempFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                        $reader = New-Object System.IO.StreamReader($fileStream)
                        $currentResults = $reader.ReadToEnd()
                        $reader.Close()
                        $fileStream.Close()

                        $currentLength = $currentResults.Length

                        # Only update if new content has been added
                        if ($currentLength -gt $script:batchLastDisplayedLength) {
                            # Display results with color coding for [CACHED] entries
                            # Preserve scrollbar state during updates
                            $savedScrollBars = $textBoxBatchResults.ScrollBars
                            $textBoxBatchResults.Clear()
                            $lines = $currentResults -split "`r`n|`n"
                            foreach ($line in $lines) {
                                if (-not [string]::IsNullOrWhiteSpace($line)) {
                                    if ($line -match '\[CACHED\]') {
                                        # Use purple in dark mode, blue in light mode
                                        $cachedColor = if ($checkDarkMode.Checked) { [System.Drawing.Color]::MediumOrchid } else { [System.Drawing.Color]::Blue }
                                        Add-ColoredText -RichTextBox $textBoxBatchResults -Text ($line + "`r`n") -Color $cachedColor
                                    } else {
                                        $textBoxBatchResults.AppendText($line + "`r`n")
                                    }
                                }
                            }
                            $textBoxBatchResults.ScrollBars = $savedScrollBars
                            # Auto-scroll to bottom
                            $textBoxBatchResults.SelectionStart = $textBoxBatchResults.TextLength
                            $textBoxBatchResults.ScrollToCaret()

                            # Update tracking variable
                            $script:batchLastDisplayedLength = $currentLength
                        }
                    } catch { }
                }

                # Read and apply cache entries incrementally
                if (Test-Path $script:batchCacheFile) {
                    try {
                        $cacheEntries = [System.IO.File]::ReadAllLines($script:batchCacheFile)
                        foreach ($entry in $cacheEntries) {
                            if ($entry -and $entry.Contains("|")) {
                                try {
                                    $parts = $entry -split '\|'
                                    if ($parts.Count -eq 7) {
                                        $filePath = $parts[0]
                                        $algorithm = $parts[1]
                                        $format = $parts[2]
                                        $hash = $parts[3]
                                        $modified = $parts[4]
                                        $size = $parts[5]
                                        $timestamp = $parts[6]

                                        $cacheKey = "$filePath|$algorithm|$format"
                                        # Only add if not already in cache (avoid duplicates)
                                        if (-not $script:hashCache.ContainsKey($cacheKey)) {
                                            $script:hashCache[$cacheKey] = @{
                                                Hash = $hash
                                                Modified = $modified
                                                Size = [long]$size
                                                Timestamp = $timestamp
                                            }
                                        }
                                    }
                                } catch { }
                            }
                        }
                        # Save cache to disk
                        Save-HashCache
                    } catch { }
                }

                $labelBatchFooter.Refresh()
            }
            
            if ($batchJob -and $batchJob.State -eq "Completed") {
                try {
                    if (Test-Path $script:batchTempFile) {
                        # Read final results to ensure everything is displayed
                        $fileStream = [System.IO.File]::Open($script:batchTempFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                        $reader = New-Object System.IO.StreamReader($fileStream)
                        $batchResults = $reader.ReadToEnd()
                        $reader.Close()
                        $fileStream.Close()

                        # Only update if not already displayed (might have been shown during live update)
                        if ($batchResults.Length -gt $script:batchLastDisplayedLength) {
                            # Display results with color coding for [CACHED] entries
                            $textBoxBatchResults.Clear()
                            $lines = $batchResults -split "`r`n|`n"
                            foreach ($line in $lines) {
                                if (-not [string]::IsNullOrWhiteSpace($line)) {
                                    if ($line -match '\[CACHED\]') {
                                        # Use purple in dark mode, blue in light mode
                                        $cachedColor = if ($checkDarkMode.Checked) { [System.Drawing.Color]::MediumOrchid } else { [System.Drawing.Color]::Blue }
                                        Add-ColoredText -RichTextBox $textBoxBatchResults -Text ($line + "`r`n") -Color $cachedColor
                                    } else {
                                        $textBoxBatchResults.AppendText($line + "`r`n")
                                    }
                                }
                            }
                        }

                        # Cache has already been written incrementally during batch execution
                        # Just ensure it's saved to disk one final time
                        Save-HashCache

                        # Reset tracking variable
                        $script:batchLastDisplayedLength = 0

                        # Log to file if enabled
                        if ($checkBatchLog.Checked) {
                            $timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
                            $logEntry = "========== Batch Operation: $timestamp ==========`r`n"
                            $logEntry += "Algorithm: $($comboBatchAlgo.SelectedItem)`r`n"
                            $logEntry += "Format: $currentFormat`r`n"
                            $logEntry += "Files processed: $script:batchTotalFiles`r`n"
                            $logEntry += $batchResults + "`r`n`r`n"
                            [System.IO.File]::AppendAllText($batchLogPath, $logEntry)
                            
                            # Auto-refresh batch log viewer
                            Start-Sleep -Milliseconds 50
                            try {
                                if ((Test-Path $batchLogPath) -and ((Get-Item $batchLogPath).Length -gt 0)) {
                                    $textBoxBatchLogViewer.Text = Add-LineNumbers ([System.IO.File]::ReadAllText($batchLogPath))
                                    $textBoxBatchLogViewer.Refresh()
                                } elseif (Test-Path $batchLogPath) {
                                    $textBoxBatchLogViewer.Text = "No batch log entries."
                                }
                            } catch { }
                        }
                        
                        Remove-Item $script:batchTempFile -Force -ErrorAction SilentlyContinue
                    } else {
                        $textBoxBatchResults.Text = "Batch operation completed but no results found.`r`nTemp file: $script:batchTempFile"
                    }
                } catch {
                    $textBoxBatchResults.Text = "Error reading batch results: $($_.Exception.Message)"
                }
                
                # Clean up batch temp files with retry
                Start-Sleep -Milliseconds 300
                $tempFiles = @($script:batchProgressFile, $script:batchFileProgressFile, $script:batchCacheFile, $script:batchTempFile, $script:batchLoadingTempFile, $hashSpeedFile)
                foreach ($file in $tempFiles) {
                    if ($file -and (Test-Path $file)) {
                        $retries = 3
                        $deleted = $false
                        while ($retries -gt 0 -and -not $deleted) {
                            try {
                                Remove-Item $file -Force -ErrorAction Stop
                                $deleted = $true
                            } catch {
                                $retries--
                                if ($retries -gt 0) {
                                    Start-Sleep -Milliseconds 100
                                }
                            }
                        }
                    }
                }

                # Add batch files to recent files list
                foreach ($file in $listBoxBatchFiles.Items) {
                    if (Test-Path $file) {
                        Add-RecentFile -filePath $file
                    }
                }
                Save-Config

                Remove-Job -Id $script:batchJobId -ErrorAction SilentlyContinue
                $script:batchJobId = $null
                $textBoxBatchResults.ScrollBars = "Both"  # Restore scrollbars after batch operation
                $buttonBatchHash.Visible = $true
                $buttonBatchClear.Visible = $true
                $buttonBatchPause.Visible = $false
                $buttonBatchPause.Enabled = $false
                $buttonBatchStop.Visible = $false
                $buttonBatchStop.Enabled = $false
                $buttonBatchExport.Enabled = $true
                $buttonExportHashCheck.Enabled = $true
                $buttonExportSFV.Enabled = $true
                $buttonExportVerifyLog.Enabled = $true

                # Re-enable other hash operations
                $buttonGenerate.Enabled = $true
                $buttonDupFind.Enabled = $true
                $buttonVerify.Enabled = $true

                $panelBatchProgressFill.Width = $panelBatchProgressBackground.Width
                $panelBatchFileProgressFill.Width = $panelBatchFileProgressBackground.Width
                $labelBatchOverallPercent.Text = "100%"
                $labelBatchFilePercent.Text = "100%"

                # Brief pause to show completion
                Start-Sleep -Milliseconds 500

                # Reset progress bars
                $panelBatchProgressFill.Width = 0
                $panelBatchFileProgressFill.Width = 0
                $labelBatchOverallPercent.Text = "0%"
                $labelBatchFilePercent.Text = "0%"

                $labelBatchFooter.Text = "Batch completed - $script:batchTotalFiles files processed"
                if ($checkDarkMode.Checked -and $script:DarkForeColor) { $labelBatchFooter.ForeColor = $script:DarkForeColor } else { $labelBatchFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray }
                
                # Show toast notification
                if ($checkToastNotifications.Checked) {
                    Show-ToastNotification -title "Batch Hash Complete" -message "$script:batchTotalFiles files processed successfully"
                }
                
                # Show balloon tip if minimized to tray (only if toast notifications are disabled)
                if ($form.WindowState -eq 'Minimized' -and $script:notifyIcon -and $script:notifyIcon.Visible -and -not $checkToastNotifications.Checked) {
                    $script:notifyIcon.BalloonTipTitle = "Batch Hash Complete"
                    $script:notifyIcon.BalloonTipText = "$script:batchTotalFiles files processed successfully"
                    $script:notifyIcon.BalloonTipIcon = 'Info'
                    $script:notifyIcon.ShowBalloonTip(5000)
                }
                
                # Restore from tray if minimized (only if not using tray minimization)
                if (($form.WindowState -eq 'Minimized' -or -not $form.Visible) -and -not $checkMinimizeToTray.Checked) {
                    $form.Show()
                    $form.WindowState = 'Normal'
                    $form.Activate()
                    if ($script:notifyIcon) {
                        $script:notifyIcon.Visible = $false
                    }
                }
            } elseif ($batchJob -and $batchJob.State -eq "Failed") {
                $textBoxBatchResults.Text = "Batch operation failed.`r`n$($batchJob.ChildJobs[0].JobStateInfo.Reason)"
                Remove-Job -Id $script:batchJobId -ErrorAction SilentlyContinue
                $script:batchJobId = $null
                $textBoxBatchResults.ScrollBars = "Both"  # Restore scrollbars after batch operation
                $buttonBatchHash.Visible = $true
                $buttonBatchClear.Visible = $true
                $buttonBatchPause.Visible = $false
                $buttonBatchPause.Enabled = $false
                $buttonBatchStop.Visible = $false
                $buttonBatchStop.Enabled = $false
                $buttonBatchExport.Enabled = $true
                $buttonExportHashCheck.Enabled = $true
                $buttonExportSFV.Enabled = $true
                $buttonExportVerifyLog.Enabled = $true

                # Re-enable other hash operations
                $buttonGenerate.Enabled = $true
                $buttonDupFind.Enabled = $true
                $buttonVerify.Enabled = $true

                $panelBatchProgressFill.Width = 0
                $labelBatchFooter.Text = "Batch failed"
            }
        }

        # Check verify job progress
        if ($script:verifyJobId) {
            # Update verify progress (format: completedCount|percent|totalFiles)
            if (Test-Path $script:verifyProgressFile) {
                try {
                    $progressData = [System.IO.File]::ReadAllText($script:verifyProgressFile)
                    $parts = $progressData -split '\|'

                    if ($parts.Count -eq 4 -and $parts[3] -eq "PAUSED") {
                        $currentFooter = $labelVerifyFooter.Text
                        if ($currentFooter -notlike "*paused*") {
                            $labelVerifyFooter.Text = $currentFooter + " - paused"
                        }
                    } elseif ($parts.Count -ge 3 -and -not $script:verifyShouldPause) {
                        $completedCount = [int]$parts[0]
                        $percent = [int]$parts[1]
                        $totalFiles = [int]$parts[2]

                        # Update progress bar
                        $script:verifyTargetWidth = [int](($percent / 100.0) * $panelVerifyProgressBackground.Width)
                        $labelVerifyFooter.Text = "Verified: $completedCount/$totalFiles ($percent%)"
                    }
                } catch { }
            }

            $verifyJob = Get-Job -Id $script:verifyJobId -ErrorAction SilentlyContinue
            if ($verifyJob) {
                # Read and display results as they're written
                if ((Test-Path $script:verifyTempFile) -and -not $script:verifyShouldPause) {
                    try {
                        $fileStream = [System.IO.File]::Open($script:verifyTempFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                        $reader = New-Object System.IO.StreamReader($fileStream)
                        $currentResults = $reader.ReadToEnd()
                        $reader.Close()
                        $fileStream.Close()

                        $currentLength = $currentResults.Length

                        if ($currentLength -gt $script:verifyLastDisplayedLength) {
                            $savedScrollBars = $textBoxVerifyResults.ScrollBars
                            $textBoxVerifyResults.Clear()
                            $lines = $currentResults -split "`r`n|`n"

                            # Reset counters
                            $script:verifyMatchCount = 0
                            $script:verifyMismatchCount = 0
                            $script:verifyMissingCount = 0

                            foreach ($line in $lines) {
                                if (-not [string]::IsNullOrWhiteSpace($line)) {
                                    $parts = $line -split '\|', 2
                                    if ($parts.Count -eq 2) {
                                        $status = $parts[0]
                                        $resultLine = $parts[1]

                                        # Update counters
                                        switch ($status) {
                                            "MATCH" { $script:verifyMatchCount++ }
                                            "MISMATCH" { $script:verifyMismatchCount++ }
                                            "MISSING" { $script:verifyMissingCount++ }
                                            "ERROR" { $script:verifyMismatchCount++ }
                                        }

                                        # Color code output
                                        $lineColor = [System.Drawing.Color]::Black
                                        if ($status -eq "MATCH") {
                                            $lineColor = [System.Drawing.Color]::Green
                                        } elseif ($status -in @("MISMATCH", "MISSING", "ERROR")) {
                                            $lineColor = [System.Drawing.Color]::Red
                                        }

                                        Add-ColoredText -RichTextBox $textBoxVerifyResults -Text ($resultLine + "`r`n") -Color $lineColor
                                    }
                                }
                            }
                            $textBoxVerifyResults.ScrollBars = $savedScrollBars
                            $textBoxVerifyResults.SelectionStart = $textBoxVerifyResults.TextLength
                            $textBoxVerifyResults.ScrollToCaret()

                            $script:verifyLastDisplayedLength = $currentLength
                        }
                    } catch { }
                }

                if ($verifyJob.State -eq "Completed") {
                    try {
                        # Display final results
                        if (Test-Path $script:verifyTempFile) {
                            $fileStream = [System.IO.File]::Open($script:verifyTempFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                            $reader = New-Object System.IO.StreamReader($fileStream)
                            $verifyResults = $reader.ReadToEnd()
                            $reader.Close()
                            $fileStream.Close()

                            if ($verifyResults.Length -gt $script:verifyLastDisplayedLength) {
                                $textBoxVerifyResults.Clear()
                                $lines = $verifyResults -split "`r`n|`n"

                                # Reset counters for final count
                                $script:verifyMatchCount = 0
                                $script:verifyMismatchCount = 0
                                $script:verifyMissingCount = 0

                                foreach ($line in $lines) {
                                    if (-not [string]::IsNullOrWhiteSpace($line)) {
                                        $parts = $line -split '\|', 2
                                        if ($parts.Count -eq 2) {
                                            $status = $parts[0]
                                            $resultLine = $parts[1]

                                            switch ($status) {
                                                "MATCH" { $script:verifyMatchCount++ }
                                                "MISMATCH" { $script:verifyMismatchCount++ }
                                                "MISSING" { $script:verifyMissingCount++ }
                                                "ERROR" { $script:verifyMismatchCount++ }
                                            }

                                            $lineColor = [System.Drawing.Color]::Black
                                            if ($status -eq "MATCH") {
                                                $lineColor = [System.Drawing.Color]::Green
                                            } elseif ($status -in @("MISMATCH", "MISSING", "ERROR")) {
                                                $lineColor = [System.Drawing.Color]::Red
                                            }

                                            Add-ColoredText -RichTextBox $textBoxVerifyResults -Text ($resultLine + "`r`n") -Color $lineColor
                                        }
                                    }
                                }
                            }

                            # Add summary
                            $summary = "`r`n`r`n========== VERIFICATION SUMMARY ==========`r`n"
                            $summary += "Total: $script:verifyTotalFiles | Match: $script:verifyMatchCount | Mismatch: $script:verifyMismatchCount | Missing: $script:verifyMissingCount`r`n"
                            $summary += "==========================================`r`n"
                            $textBoxVerifyResults.AppendText($summary)

                            Remove-Item $script:verifyTempFile -Force -ErrorAction SilentlyContinue
                        }
                    } catch {
                        $textBoxVerifyResults.Text = "Error reading verification results: $($_.Exception.Message)"
                    }

                    # Clean up temp files
                    Start-Sleep -Milliseconds 300
                    $tempFiles = @($script:verifyProgressFile, $script:verifyTempFile, $script:verifyPauseFile)
                    foreach ($file in $tempFiles) {
                        if ($file -and (Test-Path $file)) {
                            try {
                                Remove-Item $file -Force -ErrorAction SilentlyContinue
                            } catch { }
                        }
                    }

                    Remove-Job -Id $script:verifyJobId -ErrorAction SilentlyContinue
                    $script:verifyJobId = $null
                    $script:verifyRunning = $false
                    $textBoxVerifyResults.ScrollBars = "Both"
                    $buttonVerify.Enabled = $true
                    $buttonVerifyStop.Enabled = $false
                    $buttonVerifyPause.Enabled = $false
                    $buttonVerifyPause.Text = "Pause"
                    $buttonVerifyPause.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)

                    # Re-enable other hash operations
                    $buttonGenerate.Enabled = $true
                    $buttonDupFind.Enabled = $true
                    $buttonBatchHash.Enabled = $true

                    # Update progress bar to 100%
                    $panelVerifyProgressFill.Width = $panelVerifyProgressBackground.Width
                    $script:verifyTargetWidth = $panelVerifyProgressBackground.Width
                    $script:verifyCurrentWidth = $panelVerifyProgressBackground.Width

                    Start-Sleep -Milliseconds 500

                    # Reset progress bar
                    $panelVerifyProgressFill.Width = 0
                    $script:verifyTargetWidth = 0
                    $script:verifyCurrentWidth = 0

                    $labelVerifyFooter.Text = "Verification completed - $script:verifyTotalFiles files verified"
                    if ($checkDarkMode.Checked -and $script:DarkForeColor) { $labelVerifyFooter.ForeColor = $script:DarkForeColor } else { $labelVerifyFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray }

                    # Show toast notification
                    if ($checkToastNotifications.Checked) {
                        Show-ToastNotification -title "Verification Complete" -message "$script:verifyMatchCount matches, $script:verifyMismatchCount mismatches, $script:verifyMissingCount missing"
                    }
                } elseif ($verifyJob.State -eq "Failed") {
                    $textBoxVerifyResults.Text = "Verification failed.`r`n$($verifyJob.ChildJobs[0].JobStateInfo.Reason)"
                    Remove-Job -Id $script:verifyJobId -ErrorAction SilentlyContinue
                    $script:verifyJobId = $null
                    $script:verifyRunning = $false
                    $textBoxVerifyResults.ScrollBars = "Both"
                    $buttonVerify.Enabled = $true
                    $buttonVerifyStop.Enabled = $false
                    $buttonVerifyPause.Enabled = $false
                    $buttonGenerate.Enabled = $true
                    $buttonDupFind.Enabled = $true
                    $buttonBatchHash.Enabled = $true
                    $panelVerifyProgressFill.Width = 0
                    $labelVerifyFooter.Text = "Verification failed"
                }
            }
        }

        # Smooth animation for Verify tab progress bar
        if ($script:verifyTargetWidth -ne $script:verifyCurrentWidth) {
            if ($script:verifyTargetWidth -gt $script:verifyCurrentWidth) {
                # Moving forward - smooth increment
                $step = [int]([math]::Max(1, ($script:verifyTargetWidth - $script:verifyCurrentWidth) / 5))
                $script:verifyCurrentWidth = [int]([math]::Min($script:verifyTargetWidth, $script:verifyCurrentWidth + $step))
            } else {
                # Moving backward - instant update (file completed, moving to next)
                $script:verifyCurrentWidth = $script:verifyTargetWidth
            }
            $panelVerifyProgressFill.Width = $script:verifyCurrentWidth
            $panelVerifyProgressFill.Refresh()
        }

        # Check duplicate finder job
        if ($script:dupJobId) {
            # Check if runspace is still running
            $isRunspaceCompleted = $false
            if ($script:dupHandle) {
                $isRunspaceCompleted = $script:dupHandle.IsCompleted
            }

            # Read and process incremental results from temp file
            if (Test-Path $script:dupTempFile) {
                try {
                    $allLines = [System.IO.File]::ReadAllLines($script:dupTempFile)
                    $newLines = $allLines | Select-Object -Skip $script:dupLastReadLine
                    $script:dupLastReadLine = $allLines.Count

                    $hasUpdates = $false
                    foreach ($line in $newLines) {
                        if ($line -match '^DUPLICATE\|(.+)$') {
                            $dupData = $matches[1] | ConvertFrom-Json
                            $script:dupSets[$dupData.Hash] = $dupData
                            $hasUpdates = $true
                        } elseif ($line -match '^UPDATE\|(.+)$') {
                            $dupData = $matches[1] | ConvertFrom-Json
                            $script:dupSets[$dupData.Hash] = $dupData
                            $hasUpdates = $true
                        }
                    }

                    # Rebuild display from current duplicate sets (only if there are updates)
                    if ($hasUpdates -and $script:dupSets.Count -gt 0) {
                        $output = ""
                        $dupCount = 0
                        $totalDups = 0
                        $totalWastedBytes = 0
                        $allFilePaths = @()

                        # Sort by set number for consistent display
                        $sortedSets = $script:dupSets.Values | Sort-Object SetNumber

                        foreach ($dupSet in $sortedSets) {
                            $dupCount++
                            $totalDups += $dupSet.Files.Count

                            # Calculate wasted space (all duplicates except one original)
                            if ($dupSet.Size) {
                                $totalWastedBytes += ($dupSet.Size * ($dupSet.Files.Count - 1))
                            }

                            $output += "==================== Duplicate Set #$dupCount ====================`n"
                            $output += "Hash: $($dupSet.Hash)`n"
                            $fileSize = if ($dupSet.Size) {
                                if ($dupSet.Size -lt 1KB) { "$($dupSet.Size) bytes" }
                                elseif ($dupSet.Size -lt 1MB) { "{0:N2} KB" -f ($dupSet.Size / 1KB) }
                                elseif ($dupSet.Size -lt 1GB) { "{0:N2} MB" -f ($dupSet.Size / 1MB) }
                                else { "{0:N2} GB" -f ($dupSet.Size / 1GB) }
                            } else { "Unknown" }
                            $output += "Size: $fileSize`n"
                            $output += "Files ($($dupSet.Files.Count)):`n"

                            foreach ($file in $dupSet.Files) {
                                # Check if this file was cached
                                $cachedMarker = ""
                                if ($dupSet.CachedFiles -and ($dupSet.CachedFiles -contains $file)) {
                                    $cachedMarker = " [CACHED]"
                                }
                                $output += "  - $file$cachedMarker`n"
                                $allFilePaths += $file
                            }
                            $output += "`n"
                        }

                        # Add summary header with wasted space
                        $wastedStr = if ($totalWastedBytes -lt 1KB) { "$totalWastedBytes bytes" }
                                     elseif ($totalWastedBytes -lt 1MB) { "{0:N2} KB" -f ($totalWastedBytes / 1KB) }
                                     elseif ($totalWastedBytes -lt 1GB) { "{0:N2} MB" -f ($totalWastedBytes / 1MB) }
                                     else { "{0:N2} GB" -f ($totalWastedBytes / 1GB) }

                        $summary = "SUMMARY: $dupCount duplicate set(s) found | $totalDups total files | Wasted space: $wastedStr`n`n"
                        $output = $summary + $output

                        # Suspend layout to prevent flickering during updates
                        $textBoxDupResults.SuspendLayout()

                        # Set text first
                        $textBoxDupResults.Text = $output

                        # Reset selection and scroll to bottom
                        $textBoxDupResults.SelectionStart = $textBoxDupResults.Text.Length
                        $textBoxDupResults.SelectionLength = 0

                        # Resume layout
                        $textBoxDupResults.ResumeLayout()
                        $textBoxDupResults.ScrollToCaret()
                    }
                } catch { }
            }

            # Update progress
            if (Test-Path $script:dupProgressFile) {
                try {
                    $progressData = [System.IO.File]::ReadAllText($script:dupProgressFile)

                    $parts = $progressData -split '\|'

                    if ($parts.Count -ge 3) {
                        $percent = [int]$parts[0]
                        $total = [int]$parts[1]
                        $status = $parts[2].Trim()

                        # Handle phase-based progress
                        if ($status -like "PHASE:*") {
                            $phase = $status -replace "PHASE:", ""

                            if ($phase -eq "PAUSED") {
                                # PAUSED phase - replace "loading, please wait..." with "paused"
                                $currentFooter = $labelDupFooter.Text
                                if ($currentFooter -like "*loading, please wait*") {
                                    $labelDupFooter.Text = $currentFooter -replace "loading, please wait\.\.\.","paused"
                                } elseif ($currentFooter -notlike "*paused*") {
                                    $labelDupFooter.Text = $currentFooter -replace "$","- paused"
                                }
                            } elseif ($phase -like "SCANNING*") {
                                # SCANNING phase - show file count, no percentage (we don't know total)
                                $pathName = if ($parts.Count -ge 4) { $parts[3].Trim() } else { "" }
                                $labelDupFooter.Text = "SCANNING: $pathName - $total files found - loading, please wait..."
                                $labelDupProgressPercent.Text = "-"  # Dash for consistency
                                $panelDupEnumFill.Width = 0  # Hide blue bar during scanning
                                $panelDupProgressFill.Width = 0  # Hide green bar
                            } elseif ($phase -eq "FILTERING") {
                                # FILTERING phase - blue bar 0-100%
                                $labelDupFooter.Text = "FILTERING files... ($total found)"
                                $labelDupProgressPercent.Text = "$percent%"
                                $panelDupEnumFill.Width = [int](($panelDupProgressBackground.Width * $percent) / 100)
                                $panelDupProgressFill.Width = 0  # Hide green bar
                            } elseif ($phase -eq "GROUPING") {
                                # GROUPING phase - blue bar 0-100%
                                $labelDupFooter.Text = "GROUPING by size... ($total files)"
                                $labelDupProgressPercent.Text = "$percent%"
                                $panelDupEnumFill.Width = [int](($panelDupProgressBackground.Width * $percent) / 100)
                                $panelDupProgressFill.Width = 0  # Hide green bar
                            } elseif ($phase -eq "HASHING") {
                                # HASHING phase - green bar 0-100%
                                $panelDupEnumFill.Width = 0  # Hide blue bar

                                $labelDupProgressPercent.Text = "$percent%"

                                # Smooth progress bar update for green bar
                                $targetDupWidth = [int](($panelDupProgressBackground.Width * $percent) / 100)
                                if ($targetDupWidth -lt 0) { $targetDupWidth = 0 }
                                if ($targetDupWidth -gt $panelDupProgressBackground.Width) { $targetDupWidth = $panelDupProgressBackground.Width }

                                $currentDupWidth = $panelDupProgressFill.Width
                                if ($targetDupWidth -gt $currentDupWidth) {
                                    $step = [int]([math]::Max(1, ($targetDupWidth - $currentDupWidth) / 5))
                                    $panelDupProgressFill.Width = [int]([math]::Min($targetDupWidth, $currentDupWidth + $step))
                                } else {
                                    $panelDupProgressFill.Width = $targetDupWidth
                                }

                                # Calculate actual processed count from percent
                                $processed = [int](($percent / 100.0) * $total)
                                $labelDupFooter.Text = "HASHING... $processed of $total files ($percent%) - Found $($script:dupSets.Count) duplicate sets"
                            }
                        } elseif ($status -eq "STARTING") {
                            $labelDupFooter.Text = "Starting duplicate scan..."
                            $labelDupProgressPercent.Text = "0%"
                            $panelDupEnumFill.Width = 0
                            $panelDupProgressFill.Width = 0
                        }

                        # Check if completed or stopped
                        if ($status -eq "COMPLETE" -or $status -eq "STOPPED") {
                            if ($isRunspaceCompleted -or -not $script:dupHandle) {
                                # Runspace is done, finalize
                                $finalDupCount = $script:dupSets.Count
                                $finalTotalDups = 0
                                foreach ($set in $script:dupSets.Values) {
                                    $finalTotalDups += $set.Files.Count
                                }

                                if ($finalDupCount -eq 0) {
                                    $summary = "No duplicate files found.`r`n`r`nTotal files scanned: $total`r`n"
                                    $textBoxDupResults.Text = $summary
                                    $labelDupFooter.Text = "No duplicates found - scanned $total files"
                                } else {
                                    # Prepend summary to existing output
                                    $summary = "========== SUMMARY ==========`r`n"
                                    $summary += "Total files scanned: $total`r`n"
                                    $summary += "Duplicate sets found: $finalDupCount`r`n"
                                    $summary += "Total duplicate files: $finalTotalDups`r`n"
                                    $summary += "========================================`r`n`r`n"

                                    $textBoxDupResults.Text = $summary + $textBoxDupResults.Text

                                    if ($status -eq "STOPPED") {
                                        $labelDupFooter.Text = "Stopped - Found $finalDupCount duplicate sets ($finalTotalDups files) in $processed of $total files"
                                    } else {
                                        $labelDupFooter.Text = "Complete - Found $finalDupCount duplicate sets ($finalTotalDups files) in $total files"
                                    }
                                }

                                # Cleanup temp files with retry (wait for timer to release files)
                                Start-Sleep -Milliseconds 300
                                $tempFiles = @($script:dupTempFile, $script:dupProgressFile, "$($script:dupProgressFile).stop", $script:dupPauseFile)
                                foreach ($file in $tempFiles) {
                                    if ($file -and (Test-Path $file)) {
                                        $retries = 3
                                        $deleted = $false
                                        while ($retries -gt 0 -and -not $deleted) {
                                            try {
                                                Remove-Item $file -Force -ErrorAction Stop
                                                $deleted = $true
                                            } catch {
                                                $retries--
                                                if ($retries -gt 0) {
                                                    Start-Sleep -Milliseconds 100
                                                }
                                            }
                                        }
                                    }
                                }

                                # Dispose runspace
                                if ($script:dupRunspace) {
                                    try {
                                        if ($script:dupHandle) {
                                            $script:dupRunspace.EndInvoke($script:dupHandle)
                                        }
                                        $script:dupRunspace.Dispose()
                                    } catch { }
                                    $script:dupRunspace = $null
                                }
                                $script:dupJobId = $null
                                $script:dupHandle = $null
                                $script:dupSets = @{}
                                $script:dupLastReadLine = 0
                                $script:dupShouldStop = $false
                                $script:dupStopTime = $null
                                $buttonDupFind.Enabled = $true
                                $buttonDupPause.Enabled = $false
                                $buttonDupStop.Enabled = $false
                                $buttonDupAddFolder.Enabled = $true
                                $buttonDupRemoveFolder.Enabled = $true
                                $buttonDupExport.Enabled = $true
                                $script:dupScanRunning = $false  # Re-enable user interaction
                                $textBoxDupResults.ScrollBars = "Both"  # Restore scrollbars after scan

                                # Re-enable other hash operations
                                $buttonGenerate.Enabled = $true
                                $buttonBatchHash.Enabled = $true
                                $buttonVerify.Enabled = $true

                                $panelDupProgressFill.Width = $panelDupProgressBackground.Width
                                $labelDupProgressPercent.Text = "100%"

                                # Brief pause to show completion
                                Start-Sleep -Milliseconds 300

                                # Reset progress bar
                                $panelDupProgressFill.Width = 0
                                $labelDupProgressPercent.Text = "0%"
                            }
                        }
                    }
                } catch {
                    # Silently ignore progress read errors
                }
            } else {
                # Progress file doesn't exist yet - keep current status
            }
        }
    } catch { }
})

# Generate button
$buttonGenerate.Add_Click({
    Write-VerboseOutput "Generate button clicked"
    $inputText = $textBoxInput.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($inputText)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter input.", "Missing Input", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $algoName = $comboAlgo.SelectedItem
    Write-VerboseOutput "Algorithm: $algoName"
    $keyBytes = $null
    if ($algoName -like "HMAC*") { $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($textBoxKey.Text) }

    if ($radioFile.Checked) {
        if ([string]::IsNullOrWhiteSpace($inputText)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a file path.", "Missing File", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        if (-not (Test-Path $inputText)) {
            [System.Windows.Forms.MessageBox]::Show("File not found.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            return
        }
        
        # Check if network path and verify accessibility
        if (Test-NetworkPath -path $inputText) {
            $labelFooter.Text = "Checking network path (timeout: $($script:networkPathTimeout)s)..."
            $labelFooter.ForeColor = [System.Drawing.Color]::Orange
            [System.Windows.Forms.Application]::DoEvents()
            
            if (-not (Test-NetworkPathAccessible -path $inputText)) {
                [System.Windows.Forms.MessageBox]::Show("Network path is not accessible or timed out.`n`nThe network share may be offline, unresponsive, or you may not have permission.`n`nPath: $inputText", "Network Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                $labelFooter.Text = "Network path check failed"
                $labelFooter.ForeColor = [System.Drawing.Color]::Red
                return
            }
            $labelFooter.Text = "Network path: Connected"
            $labelFooter.ForeColor = [System.Drawing.Color]::Green
        }
        
        # Check if file is locked
        if (Test-FileLocked -filePath $inputText) {
            [System.Windows.Forms.MessageBox]::Show("File is currently locked by another process.`n`nThe file may be open in another application or being accessed by another user.`n`nPlease close the file and try again.", "File Locked", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        # Check for large files (>10GB)
        $sizeGB = 0
        if (Test-LargeFile -filePath $inputText -sizeGB ([ref]$sizeGB)) {
            $result = [System.Windows.Forms.MessageBox]::Show("This file is very large ($sizeGB gigabytes).`n`nHashing may take several minutes and consume significant memory.`n`nDo you want to continue?", "Large File Warning", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($result -eq [System.Windows.Forms.DialogResult]::No) {
                return
            }
        }
        
        # Check hash cache
        $selectedFormat = if ($radioFormatUpper.Checked) { "uppercase" } elseif ($radioFormatHex.Checked) { "hex" } elseif ($radioFormatBase64.Checked) { "base64" } else { "lowercase" }
        $cachedHash = Get-CachedHash -filePath $inputText -algorithm $algoName -format $selectedFormat
        
        if ($cachedHash) {
            # Use cached hash
            $fileInfo = Get-Item -LiteralPath $inputText -ErrorAction SilentlyContinue
            $fileDetails = ""
            if ($fileInfo) {
                $fileSize = $fileInfo.Length
                $sizeStr = if ($fileSize -lt 1KB) { "$fileSize bytes" } 
                           elseif ($fileSize -lt 1MB) { "{0:N2} KB" -f ($fileSize / 1KB) }
                           elseif ($fileSize -lt 1GB) { "{0:N2} MB" -f ($fileSize / 1MB) }
                           else { "{0:N2} GB" -f ($fileSize / 1GB) }
                $modifiedDate = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                $fullPath = $fileInfo.FullName
                $fileDetails = "`r`n`r`nFile: $fullPath`r`nSize: $sizeStr`r`nModified: $modifiedDate`r`n`r`n[Cached result - file unchanged]"
            }
            
            if ($checkDarkMode.Checked -and $script:DarkPanelColor) {
                $textBoxResult.BackColor = $script:DarkPanelColor
                $textBoxResult.ForeColor = $script:DarkOutputFore
            } else {
                $textBoxResult.BackColor = [System.Drawing.Color]::White
                $textBoxResult.ForeColor = [System.Drawing.Color]::Black
            }
            
            $textBoxResult.Font = $script:fontOutput
            # Format with hash on single line, file details below
            $textBoxResult.Text = $cachedHash + $fileDetails
            $script:generatedHash = $cachedHash
            $labelFooter.Text = "Hash retrieved from cache"
            
            if ($checkAutoCopy.Checked) { [System.Windows.Forms.Clipboard]::SetText($cachedHash) }
            
            # Log cached hash if logging enabled
            if ($checkLog.Checked -and $fileInfo) {
                $timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
                $line = "$timestamp | Mode: File | Input: $($fileInfo.FullName) | Algo: $algoName | Format: $selectedFormat | Size: $sizeStr | Modified: $modifiedDate | Hash: $cachedHash | [CACHED]"
                [System.IO.File]::AppendAllText($logPath, $line + [Environment]::NewLine)
                
                # Auto-refresh log viewer
                try {
                    if ((Test-Path $logPath) -and ((Get-Item $logPath).Length -gt 0)) {
                        $textBoxLogViewer.Text = [System.IO.File]::ReadAllText($logPath)
                    } elseif (Test-Path $logPath) {
                        $textBoxLogViewer.Text = "No log entries."
                    }
                } catch { }
            }
            
            # Add to recent files
            Add-RecentFile -filePath $inputText
            Save-Config
            return
        }
        
        # Add to recent files
        Add-RecentFile -filePath $inputText
        Save-Config
        
        $textBoxResult.Text = "Computing hash..."
        $textBoxResult.BackColor = [System.Drawing.Color]::LightYellow
        $textBoxResult.ForeColor = [System.Drawing.Color]::Black
        $panelProgressFill.Width = 0
        $script:hashProgress = 0
        $script:lastProgress = 0
        $script:hashDone = $false
        $script:hashResult = $null
        $script:hashError = $null
        $uiTimer.Start()
        $buttonGenerate.Enabled = $false
        $buttonStop.Enabled = $true
        Start-HashJob -inputPath $inputText -algoName $algoName -keyBytes $keyBytes
    } else {
        try {
            # Caching for string mode
            $selectedFormat = if ($radioFormatUpper.Checked) { "uppercase" } elseif ($radioFormatHex.Checked) { "hex" } elseif ($radioFormatBase64.Checked) { "base64" } else { "lowercase" }
            $cacheKey = "STR|$inputText|$algoName|$selectedFormat"
            if ($algoName -like "HMAC*") {
                $cacheKey += "|$($textBoxKey.Text)"
            }
            $cachedHash = $script:hashCache[$cacheKey]
            if ($cachedHash) {
                $hash = $cachedHash.Hash
                $displayHash = ($hash -replace "`r?`n", "") + " [CACHED]"
                $textBoxResult.Text = $displayHash
                $textBoxResult.Font = $script:fontOutput
                if ($checkDarkMode.Checked -and $script:DarkPanelColor) {
                    $textBoxResult.BackColor = $script:DarkPanelColor
                    $textBoxResult.ForeColor = $script:DarkOutputFore
                } else {
                    $textBoxResult.BackColor = [System.Drawing.Color]::White
                    $textBoxResult.ForeColor = [System.Drawing.Color]::Black
                }
                $script:generatedHash = $hash
                $labelFooter.Text = "Hash retrieved from cache"
                if ($checkAutoCopy.Checked) { [System.Windows.Forms.Clipboard]::SetText($hash) }
                if ($checkLog.Checked) {
                    $timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
                    $line = "$timestamp | Mode: String | Input: $inputText | Algo: $algoName | Format: $selectedFormat | Hash: $hash | [CACHED]"
                    [System.IO.File]::AppendAllText($logPath, $line + [Environment]::NewLine)
                }
                return
            }
            # Not cached, compute hash
            if ($algoName -eq "CRC32") {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($inputText)
                $crc32 = [FastCRC32]::ComputeHash($bytes)
                $hash = $crc32.ToString("x8")
                $algo = $null
            } else {
                switch ($algoName) {
                    "SHA256" { $algo = [System.Security.Cryptography.SHA256]::Create() }
                    "SHA1"   { $algo = [System.Security.Cryptography.SHA1]::Create() }
                    "SHA512" { $algo = [System.Security.Cryptography.SHA512]::Create() }
                    "MD5"    { $algo = [System.Security.Cryptography.MD5]::Create() }
                    "SHA384" { $algo = [System.Security.Cryptography.SHA384]::Create() }
                    "RIPEMD160" { $algo = [System.Security.Cryptography.RIPEMD160]::Create() }
                    "HMACSHA256" { $algo = [System.Security.Cryptography.HMACSHA256]::new($keyBytes) }
                    "HMACSHA512" { $algo = [System.Security.Cryptography.HMACSHA512]::new($keyBytes) }
                    default { throw "Unsupported algorithm: $algoName" }
                }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($inputText)
                $hashBytes = $algo.ComputeHash($bytes)
                $hash = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLowerInvariant()
            }
            $hash = Format-HashOutput -hashHex $hash -format $selectedFormat
            # Store in cache
            $script:hashCache[$cacheKey] = @{ Hash = $hash; Timestamp = [DateTime]::Now.ToString("o") }
            Save-HashCache
            $textBoxResult.Text = $hash -replace "`r?`n", ""
            $textBoxResult.Font = $script:fontOutput
            if ($checkDarkMode.Checked -and $script:DarkPanelColor) {
                $textBoxResult.BackColor = $script:DarkPanelColor
                $textBoxResult.ForeColor = $script:DarkOutputFore
            } else {
                $textBoxResult.BackColor = [System.Drawing.Color]::White
                $textBoxResult.ForeColor = [System.Drawing.Color]::Black
            }
            $script:generatedHash = $hash
            $labelFooter.Text = "Hash generated successfully"
            if ($checkAutoCopy.Checked) { [System.Windows.Forms.Clipboard]::SetText($hash) }
            if ($checkLog.Checked) {
                $timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
                $line = "$timestamp | Mode: String | Input: $inputText | Algo: $algoName | Format: $selectedFormat | Hash: $hash"
                [System.IO.File]::AppendAllText($logPath, $line + [Environment]::NewLine)
            }
        } catch {
            $textBoxResult.Text = "Error: $($_.Exception.Message)"
            $textBoxResult.BackColor = [System.Drawing.Color]::LightYellow
            if ($checkDarkMode.Checked -and $script:DarkForeColor) { $textBoxResult.ForeColor = $script:DarkForeColor } else { $textBoxResult.ForeColor = [System.Drawing.Color]::Black }
            $labelFooter.Text = "Error occurred"
        } finally {
            if ($algo) { $algo.Dispose() }
        }
    }
})

# Compare button
$buttonCompare.Add_Click({
    $compareHash = $textBoxCompare.Text.Trim()

    if (-not $script:generatedHash) {
        $textBoxResult.Text = "No hash generated yet."
        $textBoxResult.BackColor = [System.Drawing.Color]::LightYellow
        $textBoxResult.ForeColor = [System.Drawing.Color]::Black
        $labelFooter.Text = "No hash to compare"
        return
    }

    if (-not $compareHash) {
        $textBoxResult.Text = (($script:generatedHash -replace "`r?`n", "") + " No comparison hash provided.") -replace "`r?`n", ""
        $textBoxResult.BackColor = [System.Drawing.Color]::LightYellow
        $textBoxResult.ForeColor = [System.Drawing.Color]::Black
        $labelFooter.Text = "No comparison hash"
        return
    }

    if ($script:generatedHash -eq $compareHash) {
        $textBoxResult.Font = $script:fontOutput
        $textBoxResult.BackColor = [System.Drawing.Color]::LightGreen
        $textBoxResult.ForeColor = [System.Drawing.Color]::Black
        $hashLine = $script:generatedHash -replace "`r?`n", ""

        # Clear and rebuild with mixed alignment
        $textBoxResult.Clear()
        $textBoxResult.SelectionAlignment = [System.Windows.Forms.HorizontalAlignment]::Left
        $textBoxResult.AppendText($hashLine + "`r`n`r`n`r`n")
        $textBoxResult.SelectionAlignment = [System.Windows.Forms.HorizontalAlignment]::Center
        $textBoxResult.AppendText("MATCH")

        $labelFooter.Text = "Hashes match!"
    } else {
        $textBoxResult.Font = $script:fontOutput
        $textBoxResult.BackColor = [System.Drawing.Color]::LightCoral
        $textBoxResult.ForeColor = [System.Drawing.Color]::Black
        $hashLine = $script:generatedHash -replace "`r?`n", ""

        # Clear and rebuild with mixed alignment
        $textBoxResult.Clear()
        $textBoxResult.SelectionAlignment = [System.Windows.Forms.HorizontalAlignment]::Left
        $textBoxResult.AppendText($hashLine + "`r`n`r`n`r`n")
        $textBoxResult.SelectionAlignment = [System.Windows.Forms.HorizontalAlignment]::Center
        $textBoxResult.AppendText("MISMATCH")

        $labelFooter.Text = "Hashes do not match"
    }
})

# Show form
Write-VerboseOutput "Loading GUI form..."
$form.Topmost = $true
$form.Add_Shown({
    Write-VerboseOutput "Form shown - initializing UI components"
    $form.Activate()
    $form.Topmost = $false
    # apply dark mode state at startup
    Set-DarkMode -enabled $checkDarkMode.Checked
    Write-VerboseOutput "Dark mode applied: $($checkDarkMode.Checked)"
    
    # Reapply HMAC field colors after dark mode sets everything
    # Main tab
    $textBoxKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
    $textBoxKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
    # Batch tab
    $textBoxBatchKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
    $textBoxBatchKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
    # Verify tab
    $textBoxVerifyKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
    $textBoxVerifyKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
    
    # Reapply red color to Clear Cache button after initial dark mode setup
    $buttonClearCache.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
    
    # Initialize tray icon
    Initialize-TrayIcon -mainForm $form
    
    # Load saved config
    Get-Config
    # Update recent files list
    Update-RecentFilesList
})

$form.Add_FormClosing({
    param($s, $e)

    # Check if any operations are running
    $operationRunning = $false
    $operationMessage = ""

    if (-not $buttonVerify.Enabled) {
        $operationRunning = $true
        $operationMessage = "Verification is still running. Do you want to stop and exit?"
    } elseif ($script:batchJobId) {
        $operationRunning = $true
        $operationMessage = "Batch hashing is still running. Do you want to stop and exit?"
    } elseif ($script:currentJobId) {
        $operationRunning = $true
        $operationMessage = "Hash generation is still running. Do you want to stop and exit?"
    } elseif ($script:dupJobId) {
        $operationRunning = $true
        $operationMessage = "Duplicate file finder is still running. Do you want to stop and exit?"
    }

    if ($operationRunning) {
        $result = [System.Windows.Forms.MessageBox]::Show(
            $operationMessage,
            "Operation In Progress",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )

        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            # Stop verification
            $script:verifyShouldStop = $true
            # Stop batch job if running
            if ($script:batchJobId) {
                Stop-Job -Id $script:batchJobId -ErrorAction SilentlyContinue
                Remove-Job -Id $script:batchJobId -ErrorAction SilentlyContinue
                $script:batchJobId = $null
            }
            # Stop main hash job if running
            if ($script:currentJobId) {
                Stop-Job -Id $script:currentJobId -ErrorAction SilentlyContinue
                Remove-Job -Id $script:currentJobId -ErrorAction SilentlyContinue
                $script:currentJobId = $null
            }
            # Stop duplicate finder job if running
            if ($script:dupJobId) {
                if ($script:dupRunspace) {
                    try {
                        $script:dupRunspace.Stop()
                        $script:dupRunspace.Dispose()
                    } catch { }
                    $script:dupRunspace = $null
                }
                $script:dupJobId = $null
                $script:dupHandle = $null
            }
            # Don't cancel the close - let it proceed
        } else {
            # Cancel the close
            $e.Cancel = $true
            return
        }
    }

    # Clean up all temp files
    Start-Sleep -Milliseconds 100  # Brief delay to ensure files are released

    $tempFiles = @(
        $script:dupTempFile,
        $script:dupProgressFile,
        "$($script:dupProgressFile).stop",
        $script:dupPauseFile,
        $script:batchProgressFile,
        $script:batchFileProgressFile,
        $script:batchPauseFile,
        $script:batchCacheFile,
        $script:batchTempFile,
        $script:batchLoadingTempFile,
        $script:verifyProgressFile,
        $script:verifyTempFile,
        $script:verifyPauseFile,
        $hashSpeedFile
    )

    foreach ($file in $tempFiles) {
        if ($file -and (Test-Path $file)) {
            try {
                Remove-Item $file -Force -ErrorAction Stop
            } catch {
                # Try again after a short delay
                Start-Sleep -Milliseconds 50
                try {
                    Remove-Item $file -Force -ErrorAction SilentlyContinue
                } catch { }
            }
        }
    }

    Save-Config
    if ($script:notifyIcon) {
        $script:notifyIcon.Visible = $false
        $script:notifyIcon.Dispose()
    }
})

# Minimize to tray handler
$form.Add_Resize({
    if ($form.WindowState -eq 'Minimized' -and $checkMinimizeToTray.Checked) {
        # Show tray icon (keep taskbar icon to prevent app closing)
        $script:notifyIcon.Visible = $true
        
        if ($script:currentJobId -or $script:batchJobId) {
            $script:notifyIcon.BalloonTipTitle = "CrunchHash v3.0"
            $script:notifyIcon.BalloonTipText = "Still working in background. Double-click to restore."
            $script:notifyIcon.BalloonTipIcon = 'Info'
        } else {
            $script:notifyIcon.BalloonTipTitle = "CrunchHash v3.0"
            $script:notifyIcon.BalloonTipText = "Minimized to tray. Double-click to restore."
            $script:notifyIcon.BalloonTipIcon = 'Info'
        }
        $script:notifyIcon.ShowBalloonTip(3000)
    }
})

# Set tooltips for controls
$tooltip.SetToolTip($comboAlgo, "Choose the hash algorithm to use")
$tooltip.SetToolTip($comboBatchAlgo, "Choose the hash algorithm for batch processing")
$tooltip.SetToolTip($textBoxKey, "Enter HMAC secret key (required for HMAC algorithms)")
$tooltip.SetToolTip($textBoxBatchKey, "Enter HMAC secret key for batch operations")
$tooltip.SetToolTip($textBoxCompare, "Enter a hash to compare with the generated hash")
$tooltip.SetToolTip($checkAutoCopy, "Automatically copy generated hashes to clipboard")
$tooltip.SetToolTip($checkDarkMode, "Enable dark theme for the interface")
$tooltip.SetToolTip($checkLog, "Save hash operations to Hash_GUI_Log.txt")
$tooltip.SetToolTip($checkBatchLog, "Save batch operations to Batch_GUI_Log.txt")
$tooltip.SetToolTip($checkMinimizeToTray, "Show tray icon when window is minimized")
$tooltip.SetToolTip($checkToastNotifications, "Display Windows notifications when operations complete")
$tooltip.SetToolTip($numericParallelThreads, "Number of parallel threads for batch processing (1-8)")
$tooltip.SetToolTip($numericNetworkTimeout, "Timeout in seconds for network path verification (1-30). Prevents hanging on unresponsive network servers.")
$tooltip.SetToolTip($buttonExportHashCheck, "Export hashes as HashCheck-compatible .sha256 files")
$tooltip.SetToolTip($buttonExportSFV, "Export hashes as SFV file (CRC32 format)")
$tooltip.SetToolTip($buttonExportVerifyLog, "Export hashes in format compatible with Verify tab import")
$tooltip.SetToolTip($radioFormatLower, "Output hash in lowercase")
$tooltip.SetToolTip($radioFormatUpper, "Output hash in UPPERCASE")
$tooltip.SetToolTip($radioFormatHex, "Output hash with 0x prefix")
$tooltip.SetToolTip($radioFormatBase64, "Output hash in Base64 encoding")
$tooltip.SetToolTip($checkBatchRecursive, "When enabled, folders added via Browse will include all files in subfolders recursively")
$tooltip.SetToolTip($listBoxBatchFiles, "List of files to hash in batch mode")
$tooltip.SetToolTip($buttonBatchAdd, "Add files to the batch queue")
$tooltip.SetToolTip($buttonBatchRemove, "Remove selected files from the batch queue")
$tooltip.SetToolTip($buttonBatchHash, "Start hashing all files in the queue")
$tooltip.SetToolTip($buttonBatchClear, "Clear all files from the batch queue")
$tooltip.SetToolTip($buttonBatchStop, "Stop the currently running batch operation")
$tooltip.SetToolTip($textBoxBatchResults, "Results of batch hash operations")
$tooltip.SetToolTip($buttonBatchCopyResults, "Copy batch results to clipboard")
$tooltip.SetToolTip($buttonBatchExport, "Export batch results to TXT or CSV file")
$tooltip.SetToolTip($textBoxBatchLogViewer, "View batch operation history from Batch_GUI_Log.txt")
$tooltip.SetToolTip($buttonRefreshBatchLog, "Reload the batch log file")
$tooltip.SetToolTip($buttonClearBatchLog, "Delete all entries from the batch log file")
$tooltip.SetToolTip($buttonOpenBatchLog, "Open Batch_GUI_Log.txt in Notepad")
$tooltip.SetToolTip($textBoxInput, "Enter file path, folder path, or text string to hash")
$tooltip.SetToolTip($buttonBrowse, "Browse for a file to hash")
$tooltip.SetToolTip($buttonGenerate, "Generate hash for the selected file or text")
$tooltip.SetToolTip($buttonCompare, "Compare generated hash with expected hash")
$tooltip.SetToolTip($buttonCopy, "Copy the generated hash to clipboard")
$tooltip.SetToolTip($buttonClear, "Clear all input and output fields")
$tooltip.SetToolTip($buttonStop, "Stop the currently running hash operation")
$tooltip.SetToolTip($textBoxResult, "Generated hash result will appear here")
$tooltip.SetToolTip($textBoxLogViewer, "View hash operation history from Hash_GUI_Log.txt")
$tooltip.SetToolTip($buttonRefreshLog, "Reload the hash log file")
$tooltip.SetToolTip($buttonClearLog, "Delete all entries from the hash log file")
$tooltip.SetToolTip($buttonOpenLog, "Open Hash_GUI_Log.txt in Notepad")
$tooltip.SetToolTip($listBoxRecentFiles, "List of recently hashed files")
$tooltip.SetToolTip($buttonRecentHash, "Re-hash selected files individually")
$tooltip.SetToolTip($buttonRecentBatch, "Re-hash selected files in batch mode")
$tooltip.SetToolTip($buttonRecentClear, "Clear the recent files list")
$tooltip.SetToolTip($buttonRecentRefresh, "Refresh the recent files display")
$tooltip.SetToolTip($textBoxVerifyInput, "Paste hash list to verify (format: hash *filename)")
$tooltip.SetToolTip($textBoxVerifyKey, "Enter HMAC key for verification (if needed)")
$tooltip.SetToolTip($textBoxVerifyBasePath, "Base directory for relative file paths")
$tooltip.SetToolTip($buttonVerifyBrowse, "Browse for base directory")
$tooltip.SetToolTip($buttonVerify, "Verify all hashes in the list")
$tooltip.SetToolTip($buttonVerifyStop, "Stop the current verification process")
$tooltip.SetToolTip($buttonVerifyClear, "Clear verification input and results")
$tooltip.SetToolTip($buttonImportBatchLog, "Import hash list from a batch log file")
$tooltip.SetToolTip($textBoxVerifyResults, "Verification results will appear here")
$tooltip.SetToolTip($numericFontSize, "Adjust font size for text boxes (8-24)")
$tooltip.SetToolTip($buttonClearCache, "Clear all cached hash results. Forces re-computation of hashes. Useful if cache is outdated or corrupted.")
$tooltip.SetToolTip($buttonVerboseShell, "Launch CrunchHash in a new PowerShell window with verbose output for debugging and diagnostics")

# Duplicate Finder tab tooltips
$tooltip.SetToolTip($buttonDupAddFolder, "Add a directory to search for duplicate files")
$tooltip.SetToolTip($buttonDupRemoveFolder, "Remove selected directories from the search list")
$tooltip.SetToolTip($checkDupRecursive, "Search subdirectories recursively for duplicate files")
$tooltip.SetToolTip($comboDupAlgo, "Select hash algorithm to use for detecting duplicates (MD5 is fastest)")
$tooltip.SetToolTip($textBoxDupExtensions, "Filter files by extensions (e.g., *.jpg,*.png or .mp4,.avi). Leave empty to search all files.")
$tooltip.SetToolTip($buttonDupFind, "Start searching for duplicate files in the selected directories (uses hash cache for faster scanning)")
$tooltip.SetToolTip($buttonDupPause, "Pause/resume the current duplicate search")
$tooltip.SetToolTip($buttonDupStop, "Stop the current duplicate search")
$tooltip.SetToolTip($textBoxDupResults, "Duplicate files found will be listed here, grouped by hash.")
$tooltip.SetToolTip($buttonDupExport, "Export duplicate file results to a text file")
$tooltip.SetToolTip($buttonDupClear, "Clear the duplicate search results and reset the search")

# Start the UI timer
$uiTimer.Start()
Write-VerboseOutput "UI timer started"
Write-VerboseOutput "CrunchHash is ready"

$null = $form.ShowDialog()

# Clean exit
Write-VerboseOutput "Form closed - exiting application"
[System.Environment]::Exit(0)