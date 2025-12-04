# Parse command-line arguments
param(
    [switch]$Portable
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Portable mode flag - prevents config/cache file creation
$script:PortableMode = $Portable

# Add compiled CRC32 class for performance
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
"@

$exePath = $PSScriptRoot
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
$script:batchTempFile = [System.IO.Path]::Combine($PSScriptRoot, "batch_results.tmp")
$script:batchProgressFile = [System.IO.Path]::Combine($PSScriptRoot, "batch_progress.tmp")
$script:batchTotalFiles = 0
$script:batchCurrentFile = 0
$script:recentFiles = @()
$script:hashCache = @{}
$script:notifyIcon = $null
$script:parallelThreadCount = 4
$script:dragDropBorderActive = $false

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
        # Limit cache to 1000 most recent entries
        if ($script:hashCache.Count -gt 1000) {
            $sorted = $script:hashCache.GetEnumerator() | Sort-Object { $_.Value.Timestamp } -Descending | Select-Object -First 1000
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
    param([string]$path)
    
    try {
        if (Test-Path $path -ErrorAction Stop) {
            # Try to read file attributes to verify access
            $null = Get-Item -LiteralPath $path -ErrorAction Stop
            return $true
        }
        return $false
    } catch {
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
        $sfvContent = "; Generated by Hashps1 v2.1 on $([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))`r`n"
        $sfvContent += "; Total files: $($fileHashes.Count)`r`n`r`n"
        
        foreach ($entry in $fileHashes.GetEnumerator()) {
            $fileName = [System.IO.Path]::GetFileName($entry.Key)
            $sfvContent += "$fileName $($entry.Value)`r`n"
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
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Hashps1 v2.1").Show($toast)
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
            $iconPath = Join-Path $PSScriptRoot "hashps1.ico"
        } else {
            # For compiled exe, use the exe's directory
            $exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
            $iconPath = Join-Path (Split-Path -Parent $exePath) "hashps1.ico"
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
        
        $script:notifyIcon.Text = "Hashps1 v2.1"
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
        }
        $config | ConvertTo-Json | Out-File -FilePath $configPath -Force -Encoding UTF8
    } catch { }
}

function Load-Config {
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
    
    # Keep only last 50
    if ($script:recentFiles.Count -gt 50) {
        $script:recentFiles = $script:recentFiles[0..49]
    }
    
    # Update UI
    Update-RecentFilesList
}

function Update-RecentFilesList {
    if ($listBoxRecentFiles) {
        $listBoxRecentFiles.Items.Clear()
        foreach ($file in $script:recentFiles) {
            if (Test-Path $file) {
                $listBoxRecentFiles.Items.Add($file)
            }
        }
    }
}

function Start-HashJob {
    param($inputPath, $algoName, $keyBytes)

    Clear-HashTempFiles

    $job = Start-Job -ScriptBlock {
        param($inputPath, $algoName, $keyBytes, $progressFile, $resultFile, $errorFile, $speedFile)

        # Load FastCRC32 class in job scope
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
"@

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
                    "Label" {
                        $ctrl.BackColor = $tabColor
                        $ctrl.ForeColor = $fgColor
                    }
                    "Button" {
                        $ctrl.BackColor = $accentColor
                        $ctrl.ForeColor = [System.Drawing.Color]::White
                        $ctrl.FlatStyle = 'Standard'
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
                    "Label" {
                        $ctrl.BackColor = [System.Drawing.Color]::White
                        $ctrl.ForeColor = [System.Drawing.Color]::Black
                    }
                    "Button" {
                        $ctrl.BackColor = [System.Drawing.Color]::FromArgb(0,122,204)
                        $ctrl.ForeColor = [System.Drawing.Color]::White
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
$form.Text = "Hashps1 v2.1"
$form.Size = New-Object System.Drawing.Size(600, 700)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 10)
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

$tabControl.TabPages.AddRange(@($tabMain, $tabLogViewer, $tabBatch, $tabBatchLogViewer, $tabRecentFiles, $tabVerify, $tabSettings, $tabAbout))
$form.Controls.Add($tabControl)

# Main Tab Controls
$labelHeader = New-Object System.Windows.Forms.Label
$labelHeader.Text = "hashps1 v2.1"
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
$buttonStop.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
$buttonStop.ForeColor = [System.Drawing.Color]::White
$buttonStop.Enabled = $false

$textBoxResult = New-Object System.Windows.Forms.TextBox
$textBoxResult.Location = New-Object System.Drawing.Point(20, 400)
$textBoxResult.Size = New-Object System.Drawing.Size(540, 180)
$textBoxResult.Multiline = $true
$textBoxResult.ReadOnly = $true
$textBoxResult.BackColor = [System.Drawing.Color]::White
$textBoxResult.Font = $script:fontOutput
$textBoxResult.ScrollBars = "Vertical"
$textBoxResult.WordWrap = $true

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
Hashps1 v2.1

A professional hashing interface for cryptographic operations.

Core Features:
* String/File mode selection with drag-and-drop support with visual feedback
* 9 hash algorithms: SHA256, SHA1, SHA512, MD5, SHA384, RIPEMD160, CRC32, HMACSHA256, HMACSHA512
* Fast CRC32 implementation using compiled C# for 10-20x speedup
* HMAC key support for keyed hash algorithms (HMACSHA256, HMACSHA512)
* Real-time progress tracking with speed indicator (MB/s)
* Hash comparison with visual verdict (MATCH/MISMATCH)
* File details display (size, modified date, full path)
* File locking detection - warns if files are in use by other processes
* Large file warnings - alerts for files >10GB with confirmation dialog
* Hash result caching - skips re-hashing unchanged files (based on path + modified time)
* Network path support - UNC paths and mapped drives with connection verification
* Portable mode - run with -Portable flag to disable config/cache persistence

Hash Output Formats:
* lowercase (default)
* UPPERCASE
* Hex with 0x prefix
* Base64 encoded

Export Formats:
* TXT/CSV - Structured batch results export
* HashCheck - Individual .sha256/.md5/etc files alongside originals
* SFV - Simple File Verification format for CRC32

Batch Operations:
* Hash multiple files with progress tracking
* Configurable parallel processing (1-8 threads) for faster operations
* Independent algorithm selector per tab
* Real-time hash streaming as files complete
* Export batch results to multiple formats
* Full file paths in results for traceability
* Stop/resume with preservation of completed hashes
* Pre-flight checks for locked and large files

Hash Verification:
* Verify multiple files against hash list
* Supports hash<tab>filename or hash<space>filename format
* Base directory support for relative paths
* Independent algorithm selector
* Real-time progress with file-by-file tracking
* Detailed results: MATCH/MISMATCH/MISSING/ERROR

Recent Files:
* Quick access to previously hashed files (last 50)
* Multi-selection support (Ctrl+Click, Shift+Click)
* Single file: Quick hash in Main tab
* Multiple files: Batch processing
* Dual-button system with conditional enable/disable

User Interface:
* Dark mode theme with PlanetArchives color palette
* Adjustable output font size (8-24pt)
* Automatic copy to clipboard option
* Settings persistence across sessions
* 8 organized tabs for different operations
* Keyboard shortcuts (Ctrl+Enter to hash, Ctrl+C to copy)
* System tray minimization during long operations
* Toast notifications for background operation completion
* Visual drag-drop feedback with color highlights

Logging:
* Comprehensive logging with format tracking
* Separate logs for single and batch operations
* Auto-refresh after clearing logs
* Open logs in Notepad for external editing

Technical Details:
* PowerShell 5.1+ with .NET Framework 4.8
* Windows Forms GUI (System.Windows.Forms, System.Drawing)
* Asynchronous file hashing with background jobs
* Parallel batch processing support (configurable thread count)
* Temp file communication for progress tracking
* 250ms timer polling for smooth UI updates
* JSON config persistence (HashGUI_Config.json)
* Hash cache with automatic size limiting (max 1000 entries)
* Windows 10+ toast notification support

Keyboard Shortcuts:
* Ctrl+Enter - Generate hash (from any tab)
* Ctrl+C - Copy selected text to clipboard

Command Line:
* -Portable - Run in portable mode (no config/cache files created)

Author: Dustin W. Deen
GitHub: https://github.com/thestickybullgod/hashps1

Enhanced with assistance from GitHub Copilot (December 2025)
"@
$labelAbout.Location = New-Object System.Drawing.Point(20, 20)
$labelAbout.Size = New-Object System.Drawing.Size(520, 2000)
$labelAbout.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$labelAbout.TextAlign = "TopLeft"
$labelAbout.BackColor = [System.Drawing.Color]::Transparent
$labelAbout.AutoSize = $false

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
$buttonClearLog.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
$buttonClearLog.ForeColor = [System.Drawing.Color]::White

$buttonOpenLog = New-Object System.Windows.Forms.Button
$buttonOpenLog.Text = "Open in Notepad"
$buttonOpenLog.Location = New-Object System.Drawing.Point(240, 430)
$buttonOpenLog.Size = New-Object System.Drawing.Size(120, 30)
$buttonOpenLog.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonOpenLog.ForeColor = [System.Drawing.Color]::White

# Settings Tab
$checkAutoCopy = New-Object System.Windows.Forms.CheckBox
$checkAutoCopy.Text = "Auto-copy generated hash"
$checkAutoCopy.Location = New-Object System.Drawing.Point(20, 20)
$checkAutoCopy.Size = New-Object System.Drawing.Size(300, 20)
$checkAutoCopy.Checked = $true

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

$labelPortableMode = New-Object System.Windows.Forms.Label
$labelPortableMode.Text = if ($script:PortableMode) { "WARNING: Portable Mode Enabled (config/cache disabled)" } else { "Portable Mode: Disabled (use -Portable flag)" }
$labelPortableMode.Location = New-Object System.Drawing.Point(20, 335)
$labelPortableMode.Size = New-Object System.Drawing.Size(500, 20)
$labelPortableMode.ForeColor = if ($script:PortableMode) { [System.Drawing.Color]::Orange } else { [System.Drawing.Color]::Gray }

# Add controls to Settings Tab
$tabSettings.Controls.Add($checkAutoCopy)
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
$tabSettings.Controls.Add($labelPortableMode)

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

$labelBatchKey = New-Object System.Windows.Forms.Label
$labelBatchKey.Text = "HMAC Key:"
$labelBatchKey.Location = New-Object System.Drawing.Point(20, 162)
$labelBatchKey.Size = New-Object System.Drawing.Size(80, 20)
$labelBatchKey.Visible = $true

$textBoxBatchKey = New-Object System.Windows.Forms.TextBox
$textBoxBatchKey.Location = New-Object System.Drawing.Point(100, 160)
$textBoxBatchKey.Size = New-Object System.Drawing.Size(460, 20)
$textBoxBatchKey.UseSystemPasswordChar = $true
$textBoxBatchKey.Visible = $true
$textBoxBatchKey.Enabled = $false
$textBoxBatchKey.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$textBoxBatchKey.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)

$buttonBatchAdd = New-Object System.Windows.Forms.Button
$buttonBatchAdd.Text = "Add Files"
$buttonBatchAdd.Location = New-Object System.Drawing.Point(20, 188)
$buttonBatchAdd.Size = New-Object System.Drawing.Size(100, 30)
$buttonBatchAdd.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonBatchAdd.ForeColor = [System.Drawing.Color]::White

$buttonBatchRemove = New-Object System.Windows.Forms.Button
$buttonBatchRemove.Text = "Remove Selected"
$buttonBatchRemove.Location = New-Object System.Drawing.Point(130, 188)
$buttonBatchRemove.Size = New-Object System.Drawing.Size(120, 30)
$buttonBatchRemove.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
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
$buttonBatchStop.Location = New-Object System.Drawing.Point(480, 188)
$buttonBatchStop.Size = New-Object System.Drawing.Size(80, 30)
$buttonBatchStop.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
$buttonBatchStop.ForeColor = [System.Drawing.Color]::White
$buttonBatchStop.Enabled = $false

$textBoxBatchResults = New-Object System.Windows.Forms.TextBox
$textBoxBatchResults.Location = New-Object System.Drawing.Point(20, 228)
$textBoxBatchResults.Size = New-Object System.Drawing.Size(540, 305)
$textBoxBatchResults.Multiline = $true
$textBoxBatchResults.ReadOnly = $true
$textBoxBatchResults.ScrollBars = "Both"
$textBoxBatchResults.Font = New-Object System.Drawing.Font("Consolas", 9)
$textBoxBatchResults.WordWrap = $false

$buttonBatchCopyResults = New-Object System.Windows.Forms.Button
$buttonBatchCopyResults.Text = "Copy Results"
$buttonBatchCopyResults.Location = New-Object System.Drawing.Point(20, 543)
$buttonBatchCopyResults.Size = New-Object System.Drawing.Size(100, 30)
$buttonBatchCopyResults.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$buttonBatchCopyResults.ForeColor = [System.Drawing.Color]::White

$buttonBatchExport = New-Object System.Windows.Forms.Button
$buttonBatchExport.Text = "Export TXT/CSV..."
$buttonBatchExport.Location = New-Object System.Drawing.Point(130, 543)
$buttonBatchExport.Size = New-Object System.Drawing.Size(130, 30)
$buttonBatchExport.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$buttonBatchExport.ForeColor = [System.Drawing.Color]::White

$buttonExportHashCheck = New-Object System.Windows.Forms.Button
$buttonExportHashCheck.Text = "HashCheck"
$buttonExportHashCheck.Location = New-Object System.Drawing.Point(270, 543)
$buttonExportHashCheck.Size = New-Object System.Drawing.Size(80, 30)
$buttonExportHashCheck.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$buttonExportHashCheck.ForeColor = [System.Drawing.Color]::White

$buttonExportSFV = New-Object System.Windows.Forms.Button
$buttonExportSFV.Text = "SFV"
$buttonExportSFV.Location = New-Object System.Drawing.Point(360, 543)
$buttonExportSFV.Size = New-Object System.Drawing.Size(60, 30)
$buttonExportSFV.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$buttonExportSFV.ForeColor = [System.Drawing.Color]::White

$checkBatchLog = New-Object System.Windows.Forms.CheckBox
$checkBatchLog.Text = "Log to file"
$checkBatchLog.Location = New-Object System.Drawing.Point(450, 550)
$checkBatchLog.AutoSize = $true

$labelBatchFooter = New-Object System.Windows.Forms.Label
$labelBatchFooter.Text = "Ready"
$labelBatchFooter.Location = New-Object System.Drawing.Point(20, 578)
$labelBatchFooter.Size = New-Object System.Drawing.Size(540, 20)
$labelBatchFooter.TextAlign = "MiddleLeft"
$labelBatchFooter.ForeColor = [System.Drawing.Color]::DarkSlateGray
$labelBatchFooter.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$panelBatchProgressBackground = New-Object System.Windows.Forms.Panel
$panelBatchProgressBackground.Location = New-Object System.Drawing.Point(20, 603)
$panelBatchProgressBackground.Size = New-Object System.Drawing.Size(540, 10)
$panelBatchProgressBackground.BackColor = [System.Drawing.Color]::LightGray
$panelBatchProgressBackground.BorderStyle = 'FixedSingle'

$panelBatchProgressFill = New-Object System.Windows.Forms.Panel
$panelBatchProgressFill.Location = New-Object System.Drawing.Point(0, 0)
$panelBatchProgressFill.Size = New-Object System.Drawing.Size(0, 10)
$panelBatchProgressFill.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$panelBatchProgressBackground.Controls.Add($panelBatchProgressFill)

$tabBatch.Controls.Add($labelBatchInfo)
$tabBatch.Controls.Add($labelBatchAlgo)
$tabBatch.Controls.Add($comboBatchAlgo)
$tabBatch.Controls.Add($listBoxBatchFiles)
$tabBatch.Controls.Add($labelBatchKey)
$tabBatch.Controls.Add($textBoxBatchKey)
$tabBatch.Controls.Add($buttonBatchAdd)
$tabBatch.Controls.Add($buttonBatchRemove)
$tabBatch.Controls.Add($buttonBatchHash)
$tabBatch.Controls.Add($buttonBatchClear)
$tabBatch.Controls.Add($buttonBatchStop)
$tabBatch.Controls.Add($buttonBatchCopyResults)
$tabBatch.Controls.Add($buttonBatchExport)
$tabBatch.Controls.Add($buttonExportHashCheck)
$tabBatch.Controls.Add($buttonExportSFV)
$tabBatch.Controls.Add($checkBatchLog)
$tabBatch.Controls.Add($textBoxBatchResults)
$tabBatch.Controls.Add($panelBatchProgressBackground)
$tabBatch.Controls.Add($labelBatchFooter)

# Batch Log Viewer Tab
$textBoxBatchLogViewer = New-Object System.Windows.Forms.TextBox
$textBoxBatchLogViewer.Location = New-Object System.Drawing.Point(20, 20)
$textBoxBatchLogViewer.Size = New-Object System.Drawing.Size(540, 400)
$textBoxBatchLogViewer.Multiline = $true
$textBoxBatchLogViewer.ReadOnly = $true
$textBoxBatchLogViewer.ScrollBars = "Both"
$textBoxBatchLogViewer.WordWrap = $false
$textBoxBatchLogViewer.Font = New-Object System.Drawing.Font("Consolas", 10)

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
$buttonClearBatchLog.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
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
$labelRecentInfo.Text = "Recently hashed files:"
$labelRecentInfo.Location = New-Object System.Drawing.Point(20, 10)
$labelRecentInfo.Size = New-Object System.Drawing.Size(540, 20)

$listBoxRecentFiles = New-Object System.Windows.Forms.ListBox
$listBoxRecentFiles.Location = New-Object System.Drawing.Point(20, 35)
$listBoxRecentFiles.Size = New-Object System.Drawing.Size(540, 400)
$listBoxRecentFiles.Font = New-Object System.Drawing.Font("Consolas", 9)
$listBoxRecentFiles.SelectionMode = "MultiSimple"

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
$buttonRecentClear.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
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
$buttonVerifyClear.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
$buttonVerifyClear.ForeColor = [System.Drawing.Color]::White

$textBoxVerifyResults = New-Object System.Windows.Forms.TextBox
$textBoxVerifyResults.Location = New-Object System.Drawing.Point(20, 353)
$textBoxVerifyResults.Size = New-Object System.Drawing.Size(540, 187)
$textBoxVerifyResults.Multiline = $true
$textBoxVerifyResults.ReadOnly = $true
$textBoxVerifyResults.ScrollBars = "Both"
$textBoxVerifyResults.Font = New-Object System.Drawing.Font("Consolas", 9)
$textBoxVerifyResults.WordWrap = $false

$panelVerifyProgressBackground = New-Object System.Windows.Forms.Panel
$panelVerifyProgressBackground.Location = New-Object System.Drawing.Point(20, 550)
$panelVerifyProgressBackground.Size = New-Object System.Drawing.Size(540, 10)
$panelVerifyProgressBackground.BackColor = [System.Drawing.Color]::LightGray
$panelVerifyProgressBackground.BorderStyle = 'FixedSingle'

$panelVerifyProgressFill = New-Object System.Windows.Forms.Panel
$panelVerifyProgressFill.Location = New-Object System.Drawing.Point(0, 0)
$panelVerifyProgressFill.Size = New-Object System.Drawing.Size(0, 10)
$panelVerifyProgressFill.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$panelVerifyProgressBackground.Controls.Add($panelVerifyProgressFill)

$labelVerifyFooter = New-Object System.Windows.Forms.Label
$labelVerifyFooter.Text = "Ready"
$labelVerifyFooter.Location = New-Object System.Drawing.Point(20, 565)
$labelVerifyFooter.Size = New-Object System.Drawing.Size(540, 20)
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
$tabVerify.Controls.Add($textBoxVerifyResults)
$tabVerify.Controls.Add($panelVerifyProgressBackground)
$tabVerify.Controls.Add($labelVerifyFooter)

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
            if (Test-NetworkPathAccessible -path $files[0]) {
                $labelFooter.Text = "Network path: Connected"
                $labelFooter.ForeColor = [System.Drawing.Color]::Green
            } else {
                $labelFooter.Text = "Network path: Not accessible"
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
    if (Test-Path $logPath) { $textBoxLogViewer.Text = Get-Content $logPath -Raw } else { $textBoxLogViewer.Text = "No log entries." }
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
    if (Test-Path $batchLogPath) { $textBoxBatchLogViewer.Text = Get-Content $batchLogPath -Raw } else { $textBoxBatchLogViewer.Text = "No batch log entries." }
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

$buttonRecentHash.Add_Click({
    if ($listBoxRecentFiles.SelectedItems.Count -ne 1) {
        return
    }
    
    $selectedFile = $listBoxRecentFiles.SelectedItems[0].ToString()
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
        $listBoxBatchFiles.Items.Add($file)
    }
    $tabControl.SelectedTab = $tabBatch
    [System.Windows.Forms.MessageBox]::Show("$($validFiles.Count) file(s) added to Batch tab.`n`nClick 'Hash All' to process.", "Ready", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

# Update button states based on selection
$listBoxRecentFiles.Add_SelectedIndexChanged({
    $selectedCount = $listBoxRecentFiles.SelectedItems.Count
    
    if ($selectedCount -eq 0) {
        $buttonRecentHash.Enabled = $false
        $buttonRecentBatch.Enabled = $false
    } elseif ($selectedCount -eq 1) {
        $buttonRecentHash.Enabled = $true
        $buttonRecentBatch.Enabled = $false
    } else {
        $buttonRecentHash.Enabled = $false
        $buttonRecentBatch.Enabled = $true
    }
})

$buttonRecentClear.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show("Clear recent files list?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
        $script:recentFiles = @()
        Update-RecentFilesList
        Save-Config
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
})

$buttonVerify.Add_Click({
    if ([string]::IsNullOrWhiteSpace($textBoxVerifyInput.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please paste a hash list first.", "Verify", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $textBoxVerifyResults.Text = "Verifying files...`r`n"
    $panelVerifyProgressFill.Width = 0
    $labelVerifyFooter.Text = "Processing..."
    [System.Windows.Forms.Application]::DoEvents()
    
    $lines = $textBoxVerifyInput.Text -split "`r?`n" | Where-Object { $_ -match '\S' }
    $basePath = $textBoxVerifyBasePath.Text.Trim()
    $algoName = $comboVerifyAlgo.SelectedItem
    $keyBytes = $null
    if ($algoName -like "HMAC*") { $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($textBoxVerifyKey.Text) }
    
    $results = @()
    $matchCount = 0
    $mismatchCount = 0
    $missingCount = 0
    $totalLines = $lines.Count
    $currentLine = 0
    $startTime = [DateTime]::Now
    
    foreach ($line in $lines) {
        $currentLine++
        $percent = if ($totalLines -gt 0) { [int](($currentLine * 100) / $totalLines) } else { 0 }
        $panelVerifyProgressFill.Width = [int](($percent / 100.0) * $panelVerifyProgressBackground.Width)
        $elapsed = ([DateTime]::Now - $startTime).TotalSeconds
        $labelVerifyFooter.Text = "Processing file $currentLine of $totalLines ($percent percent) - $([int]$elapsed)s elapsed"
        [System.Windows.Forms.Application]::DoEvents()
        
        # Parse line: hash and filename separated by tab or space
        if ($line -match '^([a-fA-F0-9]+|0x[a-fA-F0-9]+|[A-Za-z0-9+/]+=*)\s+(.+)$') {
            $expectedHash = $matches[1].Trim()
            $filename = $matches[2].Trim()
            
            # Construct full path
            $fullPath = if ([string]::IsNullOrWhiteSpace($basePath)) {
                $filename
            } else {
                Join-Path $basePath $filename
            }
            
            if (-not (Test-Path $fullPath)) {
                $results += "MISSING: $filename"
                $missingCount++
                continue
            }
            
            try {
                # Compute hash
                if ($algoName -eq "CRC32") {
                    $fs = [System.IO.File]::OpenRead($fullPath)
                    try {
                        $crc32 = [FastCRC32]::ComputeHashStream($fs, $null)
                        $computedHash = $crc32.ToString("x8")
                    } finally {
                        $fs.Close()
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
                    
                    $fs = [System.IO.File]::OpenRead($fullPath)
                    try {
                        $hashBytes = $algo.ComputeHash($fs)
                        $computedHash = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLowerInvariant()
                    } finally {
                        $fs.Close()
                        if ($algo) { $algo.Dispose() }
                    }
                }
                
                # Normalize expected hash for comparison
                $normalizedExpected = $expectedHash.ToLowerInvariant() -replace '^0x', '' -replace '[^a-f0-9]', ''
                
                if ($computedHash -eq $normalizedExpected) {
                    $results += "MATCH: $filename"
                    $matchCount++
                } else {
                    $results += "MISMATCH: $filename (expected: $expectedHash, got: $computedHash)"
                    $mismatchCount++
                }
            } catch {
                $results += "ERROR: $filename - $($_.Exception.Message)"
                $mismatchCount++
            }
        } else {
            $results += "INVALID LINE: $line"
        }
    }
    
    $summary = "`r`n========== VERIFICATION SUMMARY ==========`r`n"
    $summary += "Total: $($lines.Count) | Match: $matchCount | Mismatch: $mismatchCount | Missing: $missingCount`r`n"
    $summary += "==========================================`r`n`r`n"
    
    $textBoxVerifyResults.Text = $summary + ($results -join "`r`n")
    $panelVerifyProgressFill.Width = $panelVerifyProgressBackground.Width
    $totalElapsed = ([DateTime]::Now - $startTime).TotalSeconds
    $labelVerifyFooter.Text = "Completed - $totalLines files verified in $([int]$totalElapsed)s"
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
})

# Keyboard shortcuts
$form.Add_KeyDown({
    param($sender, $e)
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
                    $listBoxBatchFiles.Items.Add($file)
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
    }
    
    # Reset background color
    if ($checkDarkMode.Checked -and $script:DarkPanelColor) {
        $listBoxBatchFiles.BackColor = $script:DarkPanelColor
    } else {
        $listBoxBatchFiles.BackColor = [System.Drawing.Color]::White
    }
})

$buttonBatchAdd.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Multiselect = $true
    if ($dialog.ShowDialog() -eq "OK") {
        foreach ($file in $dialog.FileNames) {
            if ($listBoxBatchFiles.Items -notcontains $file) {
                $listBoxBatchFiles.Items.Add($file)
            }
        }
    }
})

$buttonBatchRemove.Add_Click({
    for ($i = $listBoxBatchFiles.SelectedItems.Count - 1; $i -ge 0; $i--) {
        $listBoxBatchFiles.Items.Remove($listBoxBatchFiles.SelectedItems[$i])
    }
})

$buttonBatchClear.Add_Click({
    $listBoxBatchFiles.Items.Clear()
    $textBoxBatchResults.Clear()
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
                    Remove-Item $script:batchTempFile -Force -ErrorAction SilentlyContinue
                } catch { }
            }
            
            if ([string]::IsNullOrWhiteSpace($completedResults)) {
                $textBoxBatchResults.Text = "Batch operation cancelled. No files were completed."
            } else {
                $textBoxBatchResults.Text = $completedResults + "`r`n`r`n========== OPERATION CANCELLED =========="
            }
            
            $script:batchJobId = $null
            $buttonBatchHash.Enabled = $true
            $buttonBatchStop.Enabled = $false
            $panelBatchProgressFill.Width = 0
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
    
    # Parse results to create HashCheck format files
    $lines = $textBoxBatchResults.Text -split "`r`n" | Where-Object { $_ -match '\S' }
    $algorithm = $comboBatchAlgo.SelectedItem
    $exportCount = 0
    $errors = @()
    $debugInfo = @()
    
    foreach ($line in $lines) {
        # Skip error lines and status messages
        if ($line -match '^ERROR:' -or $line -match '^Batch job' -or $line -match '^Starting') { continue }
        
        # Split by tab and extract parts
        $parts = $line -split "`t"
        $debugInfo += "Line has $($parts.Count) parts"
        $debugInfo += "Part 0: '$($parts[0])' (length: $($parts[0].Length))"
        if ($parts.Count -ge 2) { $debugInfo += "Part 1: '$($parts[1])'" }
        if ($parts.Count -ge 3) { $debugInfo += "Part 2: '$($parts[2])'" }
        if ($parts.Count -ge 4) { $debugInfo += "Part 3: '$($parts[3])'" }
        
        if ($parts.Count -ge 4) {
            $hash = $parts[0].Trim() -replace '[\r\n]+', ''
            $filePath = $parts[3].Trim()
            
            $debugInfo += "Hash after clean: '$hash' (length: $($hash.Length))"
            $debugInfo += "File: '$filePath'"
            
            if ([string]::IsNullOrWhiteSpace($hash)) {
                $errors += "$filePath (hash empty)"
                continue
            }
            
            if (Test-Path $filePath) {
                $result = Export-HashCheckFile -filePath $filePath -hash $hash -algorithm $algorithm
                if ($result) {
                    $exportCount++
                    $debugInfo += "SUCCESS: $result"
                } else {
                    $errors += "$filePath (export failed)"
                    $debugInfo += "FAILED: Export returned null"
                }
            } else {
                $errors += "$filePath (not found)"
            }
        } else {
            $debugInfo += "Skipped line (not enough parts): $line"
        }
    }
    
    $msg = "HashCheck files created: $exportCount"
    if ($errors.Count -gt 0) {
        $msg += "`n`nErrors: $($errors.Count)"
        if ($errors.Count -le 5) {
            $msg += "`n" + ($errors -join "`n")
        }
    }
    # Uncomment to see debug info:
    # $msg += "`n`nDebug:`n" + ($debugInfo -join "`n")
    [System.Windows.Forms.MessageBox]::Show($msg, "HashCheck Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
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
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "SFV files (*.sfv)|*.sfv"
    $saveDialog.Title = "Export SFV File"
    $saveDialog.FileName = "checksums.sfv"
    
    if ($saveDialog.ShowDialog() -eq "OK") {
        try {
            # Parse results and build hashtable
            $fileHashes = @{}
            $lines = $textBoxBatchResults.Text -split "`r`n" | Where-Object { $_ -match '\S' }
            
            foreach ($line in $lines) {
                if ($line -match '^([a-fA-F0-9]{8})\t.+\t(.+)$') {
                    $hash = $matches[1]
                    $filePath = $matches[2]
                    $fileHashes[$filePath] = $hash
                }
            }
            
            if (Export-SFVFile -outputPath $saveDialog.FileName -fileHashes $fileHashes) {
                [System.Windows.Forms.MessageBox]::Show("SFV file exported successfully.`n`n$($saveDialog.FileName)", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } else {
                [System.Windows.Forms.MessageBox]::Show("Failed to export SFV file.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$numericParallelThreads.Add_ValueChanged({
    $script:parallelThreadCount = [int]$numericParallelThreads.Value
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
    
    # Check for locked files
    $lockedFiles = @()
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
    
    # Check for large files
    $largeFiles = @()
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
    
    try {
        $algoName = $comboBatchAlgo.SelectedItem
        $keyBytes = $null
        if ($algoName -like "HMAC*") { $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($textBoxBatchKey.Text) }
        $selectedFormat = if ($radioFormatUpper.Checked) { "uppercase" } elseif ($radioFormatHex.Checked) { "hex" } elseif ($radioFormatBase64.Checked) { "base64" } else { "lowercase" }
        
        # Convert listbox items to array
        $filesToHash = @()
        foreach ($item in $listBoxBatchFiles.Items) {
            $filesToHash += $item
        }
        
        $textBoxBatchResults.Text = "Starting parallel batch operation with $script:parallelThreadCount thread(s)...`r`n`r`n"
        $buttonBatchHash.Enabled = $false
        $buttonBatchStop.Enabled = $true
        
        # Ensure timer is running to check batch job
        if (-not $uiTimer.Enabled) {
            $uiTimer.Start()
        }
        
        # Convert hashCache to array for serialization
        $cacheArray = @()
        if ($script:hashCache) {
            foreach ($key in $script:hashCache.Keys) {
                $cacheArray += @{Key = $key; Value = $script:hashCache[$key]}
            }
        }
        
        # Start parallel batch job using runspaces
        $job = Start-Job -ScriptBlock {
            param($files, $algoName, $keyBytes, $format, $tempFile, $progressFile, $speedFile, $threadCount, $cacheArray)
            
            # Reconstruct hashCache from array
            $hashCache = @{}
            if ($cacheArray) {
                foreach ($item in $cacheArray) {
                    $hashCache[$item.Key] = $item.Value
                }
            }
            
            # Load FastCRC32 class in job scope
            Add-Type -TypeDefinition @"
using System;
using System.IO;

public class FastCRC32Parallel
{
    private static uint[] crcTable;
    
    static FastCRC32Parallel()
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
"@
            
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
                param($file, $algoName, $keyBytes, $format, $fileIndex, $totalFiles, $hashCache)
                
                $result = @{
                    Index = $fileIndex
                    File = $file
                    Hash = $null
                    Size = "N/A"
                    Modified = "N/A"
                    Error = $null
                    Cached = $false
                }
                
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
                            if ($algoName -eq "CRC32") {
                                # Load CRC32 class if not already loaded
                                if (-not ([System.Management.Automation.PSTypeName]'FastCRC32Parallel').Type) {
                                    Add-Type -TypeDefinition @"
using System;
using System.IO;

public class FastCRC32Parallel
{
    private static uint[] crcTable;
    
    static FastCRC32Parallel()
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
"@
                                }
                                $crc32 = [FastCRC32Parallel]::ComputeHashStream($fs)
                                $hash = $crc32.ToString("x8")
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
                                
                                $hashBytes = $algo.ComputeHash($fs)
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
            
            # Create runspace jobs
            $runspaces = New-Object System.Collections.ArrayList
            $totalFiles = $files.Count
            $fileIndex = 0
            
            foreach ($file in $files) {
                $fileIndex++
                $powershell = [powershell]::Create().AddScript($scriptBlock).AddArgument($file).AddArgument($algoName).AddArgument($keyBytes).AddArgument($format).AddArgument($fileIndex).AddArgument($totalFiles).AddArgument($hashCache)
                $powershell.RunspacePool = $runspacePool
                
                [void]$runspaces.Add([PSCustomObject]@{
                    Pipe = $powershell
                    Status = $powershell.BeginInvoke()
                    Index = $fileIndex
                    File = $file
                })
            }
            
            # Wait for all runspaces to complete and collect results
            $completedCount = 0
            $results = @{}
            
            while ($runspaces.Count -gt 0) {
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
                            $completedCount++
                            
                            # Update progress
                            $percent = [int](($completedCount * 100) / $totalFiles)
                            try {
                                [System.IO.File]::WriteAllText($progressFile, "$completedCount|$percent|$totalFiles")
                            } catch { }
                            
                            [void]$toRemove.Add($rs)
                        } catch {
                            # Handle error
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
            
            # Write results in order
            for ($i = 1; $i -le $totalFiles; $i++) {
                if ($results.ContainsKey($i)) {
                    $r = $results[$i]
                    if ($r.Error) {
                        $resultLine = "ERROR: $($r.Error)`tSize: $($r.Size)`tModified: $($r.Modified)`t$($r.File)"
                    } else {
                        $hashValue = if ($r.Hash) { $r.Hash.Trim() } else { "" }
                        $isCached = if ($r.ContainsKey('Cached')) { $r.Cached } else { $false }
                        $cachedMarker = if ($isCached) { "`t[CACHED]" } else { "" }
                        $resultLine = "$hashValue`tSize: $($r.Size)`tModified: $($r.Modified)`t$($r.File)$cachedMarker"
                    }
                    try {
                        [System.IO.File]::AppendAllText($tempFile, $resultLine + [Environment]::NewLine)
                    } catch { }
                }
            }
            
            $runspacePool.Close()
            $runspacePool.Dispose()
            
        } -ArgumentList $filesToHash, $algoName, $keyBytes, $selectedFormat, $script:batchTempFile, $script:batchProgressFile, $hashSpeedFile, $script:parallelThreadCount, $cacheArray
        
        $script:batchJobId = $job.Id
        $script:batchTotalFiles = $filesToHash.Count
        $script:batchCurrentFile = 0
        $textBoxBatchResults.Text = "Batch job started (ID: $($job.Id)). Processing $($filesToHash.Count) files with parallel execution..."
        
    } catch {
        $textBoxBatchResults.Text = "Error: $($_.Exception.Message)"
        $buttonBatchHash.Enabled = $true
        $buttonBatchStop.Enabled = $false
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
                $textBoxResult.TextAlign = "Left"
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
            if (Test-Path $logPath) {
                $textBoxLogViewer.Text = [System.IO.File]::ReadAllText($logPath)
            }
        } catch { }
        
        # Check batch job completion
        if ($script:batchJobId) {
            # Update batch progress (format: completedCount|overallPercent|totalFiles)
            if (Test-Path $script:batchProgressFile) {
                try {
                    $progressData = [System.IO.File]::ReadAllText($script:batchProgressFile)
                    $parts = $progressData -split '\|'
                    if ($parts.Count -eq 3) {
                        $completedCount = [int]$parts[0]
                        $overallPercent = [int]$parts[1]
                        $totalFiles = [int]$parts[2]
                        
                        $script:batchCurrentFile = $completedCount
                        $script:batchTotalFiles = $totalFiles
                        
                        # Direct progress update for accuracy
                        $targetWidth = [int](($panelBatchProgressBackground.Width * $overallPercent) / 100)
                        if ($targetWidth -lt 0) { $targetWidth = 0 }
                        if ($targetWidth -gt $panelBatchProgressBackground.Width) { $targetWidth = $panelBatchProgressBackground.Width }
                        $panelBatchProgressFill.Width = $targetWidth
                        
                        # Display speed if available
                        $batchSpeedText = ""
                        if (Test-Path $hashSpeedFile) {
                            try {
                                $batchSpeed = [System.IO.File]::ReadAllText($hashSpeedFile)
                                $batchSpeedText = " - $batchSpeed MB/s"
                            } catch { }
                        }
                        
                        $labelBatchFooter.Text = "Files completed: $completedCount/$totalFiles - Progress: $overallPercent%$batchSpeedText"
                    }
                } catch { }
            }
            
            $batchJob = Get-Job -Id $script:batchJobId -ErrorAction SilentlyContinue
            if ($batchJob) {
                # Read and display results as they're written
                if (Test-Path $script:batchTempFile) {
                    try {
                        $currentResults = [System.IO.File]::ReadAllText($script:batchTempFile)
                        if ($currentResults -ne $textBoxBatchResults.Text) {
                            $textBoxBatchResults.Text = $currentResults
                            # Auto-scroll to bottom
                            $textBoxBatchResults.SelectionStart = $textBoxBatchResults.Text.Length
                            $textBoxBatchResults.ScrollToCaret()
                        }
                    } catch { }
                }
                
                $labelBatchFooter.Refresh()
            }
            
            if ($batchJob -and $batchJob.State -eq "Completed") {
                try {
                    if (Test-Path $script:batchTempFile) {
                        $batchResults = [System.IO.File]::ReadAllText($script:batchTempFile)
                        $textBoxBatchResults.Text = $batchResults
                        
                        # Cache the batch results for future use
                        $algoName = $comboBatchAlgo.SelectedItem
                        $currentFormat = if ($radioFormatUpper.Checked) { "uppercase" } elseif ($radioFormatHex.Checked) { "hex" } elseif ($radioFormatBase64.Checked) { "base64" } else { "lowercase" }
                        foreach ($line in $batchResults -split "`r`n|`n") {
                            if ($line -and -not $line.StartsWith("ERROR:") -and $line.Contains("`t")) {
                                try {
                                    $parts = $line -split "`t"
                                    if ($parts.Count -ge 4) {
                                        $hash = $parts[0].Trim()
                                        $filePath = $parts[3].Trim()
                                        # Skip if already cached (has [CACHED] marker)
                                        if (-not $line.EndsWith("[CACHED]") -and $hash -and $filePath -and (Test-Path $filePath)) {
                                            Set-CachedHash -filePath $filePath -algorithm $algoName -format $currentFormat -hash $hash
                                        }
                                    }
                                } catch { }
                            }
                        }
                        
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
                                if (Test-Path $batchLogPath) {
                                    $textBoxBatchLogViewer.Text = [System.IO.File]::ReadAllText($batchLogPath)
                                    $textBoxBatchLogViewer.Refresh()
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
                
                if (Test-Path $script:batchProgressFile) {
                    Remove-Item $script:batchProgressFile -Force -ErrorAction SilentlyContinue
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
                $buttonBatchHash.Enabled = $true
                $buttonBatchStop.Enabled = $false
                $panelBatchProgressFill.Width = $panelBatchProgressBackground.Width
                $labelBatchFooter.Text = "Batch completed - $script:batchTotalFiles files processed"
                
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
                $buttonBatchHash.Enabled = $true
                $buttonBatchStop.Enabled = $false
                $panelBatchProgressFill.Width = 0
                $labelBatchFooter.Text = "Batch failed"
            }
        }
    } catch { }
})

# Generate button
$buttonGenerate.Add_Click({
    $inputText = $textBoxInput.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($inputText)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter input.", "Missing Input", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $algoName = $comboAlgo.SelectedItem
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
            if (-not (Test-NetworkPathAccessible -path $inputText)) {
                [System.Windows.Forms.MessageBox]::Show("Network path is not accessible.`n`nThe network share may be offline or you may not have permission.`n`nPath: $inputText", "Network Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
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
            $textBoxResult.TextAlign = "Left"
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
                    if (Test-Path $logPath) {
                        $textBoxLogViewer.Text = [System.IO.File]::ReadAllText($logPath)
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
            if ($algoName -eq "CRC32") {
                # CRC32 for string (using compiled C# class)
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
            
            # Apply output formatting
            $selectedFormat = if ($radioFormatUpper.Checked) { "uppercase" } elseif ($radioFormatHex.Checked) { "hex" } elseif ($radioFormatBase64.Checked) { "base64" } else { "lowercase" }
            $hash = Format-HashOutput -hashHex $hash -format $selectedFormat
            
            $textBoxResult.Text = $hash
            $textBoxResult.Font = $script:fontOutput

            # apply current theme colors immediately
            if ($checkDarkMode.Checked -and $script:DarkPanelColor) {
                $textBoxResult.BackColor = $script:DarkPanelColor
                $textBoxResult.ForeColor = $script:DarkOutputFore
            } else {
                $textBoxResult.BackColor = [System.Drawing.Color]::White
                $textBoxResult.ForeColor = [System.Drawing.Color]::Black
            }

            $textBoxResult.TextAlign = "Center"
            $script:generatedHash = $hash
            $labelFooter.Text = "Hash generated successfully"

            if ($checkAutoCopy.Checked) { [System.Windows.Forms.Clipboard]::SetText($hash) }

            if ($checkLog.Checked) {
                $timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
                $line = "$timestamp | Mode: String | Input: $inputText | Algo: $algoName | Format: $selectedFormat | Size: N/A | Modified: N/A | Hash: $hash"
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
        $textBoxResult.Text = "$script:generatedHash`r`n`r`nNo comparison hash provided."
        $textBoxResult.BackColor = [System.Drawing.Color]::LightYellow
        $textBoxResult.ForeColor = [System.Drawing.Color]::Black
        $labelFooter.Text = "No comparison hash"
        return
    }

    if ($script:generatedHash -eq $compareHash) {
        $textBoxResult.Font = $script:fontVerdict
        $textBoxResult.BackColor = [System.Drawing.Color]::LightGreen
        $textBoxResult.ForeColor = [System.Drawing.Color]::Black
        $textBoxResult.Text = "$script:generatedHash`r`n`r`nMATCH"
        $labelFooter.Text = "Hashes match!"
    } else {
        $textBoxResult.Font = $script:fontVerdict
        $textBoxResult.BackColor = [System.Drawing.Color]::LightCoral
        $textBoxResult.ForeColor = [System.Drawing.Color]::Black
        $textBoxResult.Text = "$script:generatedHash`r`n`r`nMISMATCH"
        $labelFooter.Text = "Hashes do not match"
    }
    $textBoxResult.TextAlign = "Center"
})

# Show form
$form.Topmost = $true
$form.Add_Shown({
    $form.Activate()
    $form.Topmost = $false
    # apply dark mode state at startup
    Set-DarkMode -enabled $checkDarkMode.Checked
    
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
    
    # Initialize tray icon
    Initialize-TrayIcon -mainForm $form
    
    # Load saved config
    Load-Config
    # Update recent files list
    Update-RecentFilesList
})

$form.Add_FormClosing({
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
            $script:notifyIcon.BalloonTipTitle = "Hashps1 v2.1"
            $script:notifyIcon.BalloonTipText = "Still working in background. Double-click to restore."
            $script:notifyIcon.BalloonTipIcon = 'Info'
        } else {
            $script:notifyIcon.BalloonTipTitle = "Hashps1 v2.1"
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
$tooltip.SetToolTip($buttonExportHashCheck, "Export hashes as HashCheck-compatible .sha256 files")
$tooltip.SetToolTip($buttonExportSFV, "Export hashes as SFV file (CRC32 format)")
$tooltip.SetToolTip($radioFormatLower, "Output hash in lowercase")
$tooltip.SetToolTip($radioFormatUpper, "Output hash in UPPERCASE")
$tooltip.SetToolTip($radioFormatHex, "Output hash with 0x prefix")
$tooltip.SetToolTip($radioFormatBase64, "Output hash in Base64 encoding")
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
$tooltip.SetToolTip($buttonVerifyClear, "Clear verification input and results")
$tooltip.SetToolTip($textBoxVerifyResults, "Verification results will appear here")
$tooltip.SetToolTip($numericFontSize, "Adjust font size for text boxes (8-16)")

[void]$form.ShowDialog()