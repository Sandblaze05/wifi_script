# Run this file first for setting up the service

$ErrorActionPreference = "Stop"

# Configuration paths
$configDir = "C:\ProgramData\VITWiFiLogin"
$configFile = "$configDir\config.ini"

function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-ColorOutput Red "ERROR: This script must be run as Administrator!"
    pause
    exit 1
}

Write-ColorOutput Cyan "==================================================="
Write-ColorOutput Cyan "  VIT WiFi Login Service - Configuration Setup"
Write-ColorOutput Cyan "==================================================="
Write-Host ""

if (-not (Test-Path $configDir)) {
    Write-Host "Creating configuration directory: $configDir"
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    Write-ColorOutput Green "✓ Directory created successfully"
} else {
    Write-ColorOutput Green "✓ Configuration directory exists"
}

$configExists = Test-Path $configFile
if ($configExists) {
    Write-ColorOutput Yellow "⚠ Configuration file already exists!"
    Write-Host "Current location: $configFile"
    Write-Host ""
    $overwrite = Read-Host "Do you want to update it? (Y/N)"
    if ($overwrite -ne "Y" -and $overwrite -ne "y") {
        Write-Host "Operation cancelled."
        pause
        exit 0
    }
    
    # Read existing values
    $existingContent = Get-Content $configFile
    $existingUserId = ($existingContent | Select-String "userId=(.+)").Matches.Groups[1].Value
    $existingPassword = ($existingContent | Select-String "password=(.+)").Matches.Groups[1].Value
}

Write-Host ""
Write-ColorOutput Cyan "Enter your VIT WiFi credentials:"
Write-Host ""

if ($existingUserId -and $existingUserId -ne "YOUR_USER_ID") {
    Write-Host "Current User ID: $existingUserId"
    $newUserId = Read-Host "New User ID (press Enter to keep current)"
    if ([string]::IsNullOrWhiteSpace($newUserId)) {
        $userId = $existingUserId
    } else {
        $userId = $newUserId.Trim()
    }
} else {
    do {
        $userId = Read-Host "User ID (e.g., 22BCT1234)"
        $userId = $userId.Trim()
        if ([string]::IsNullOrWhiteSpace($userId)) {
            Write-ColorOutput Red "User ID cannot be empty!"
        }
    } while ([string]::IsNullOrWhiteSpace($userId))
}

if ($existingPassword -and $existingPassword -ne "YOUR_PASSWORD") {
    Write-Host "Password is already set (hidden for security)"
    $updatePassword = Read-Host "Update password? (Y/N)"
    if ($updatePassword -eq "Y" -or $updatePassword -eq "y") {
        do {
            $securePassword = Read-Host "Password" -AsSecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            
            if ([string]::IsNullOrWhiteSpace($password)) {
                Write-ColorOutput Red "Password cannot be empty!"
            }
        } while ([string]::IsNullOrWhiteSpace($password))
    } else {
        $password = $existingPassword
    }
} else {
    do {
        $securePassword = Read-Host "Password" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        
        if ([string]::IsNullOrWhiteSpace($password)) {
            Write-ColorOutput Red "Password cannot be empty!"
        }
    } while ([string]::IsNullOrWhiteSpace($password))
}

$configContent = @"
# VIT WiFi Login Service Configuration
# Last updated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

[Credentials]
userId=$userId
password=$password

# Notes:
# - Special characters in password will be automatically URL-encoded
# - Restart the service after changing this file
# - Keep this file secure (contains sensitive credentials)
"@

try {
    Set-Content -Path $configFile -Value $configContent -Encoding UTF8
    Write-Host ""
    Write-ColorOutput Green "==================================================="
    Write-ColorOutput Green "✓ Configuration saved successfully!"
    Write-ColorOutput Green "==================================================="
    Write-Host ""
    Write-Host "Configuration file: $configFile"
    Write-Host "User ID: $userId"
    Write-Host "Password: ********** (hidden)"
    
    # Set file permissions to restrict access
    Write-Host ""
    Write-Host "Setting secure file permissions..."
    $acl = Get-Acl $configFile
    $acl.SetAccessRuleProtection($true, $false)
    
    # Add SYSTEM full control
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")
    $acl.AddAccessRule($systemRule)
    
    # Add Administrators full control
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
    $acl.AddAccessRule($adminRule)
    
    Set-Acl $configFile $acl
    Write-ColorOutput Green "✓ File permissions secured"
    
    # Check if service exists and offer to restart
    $service = Get-Service -Name "VITWiFiLogin" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host ""
        if ($service.Status -eq "Running") {
            Write-ColorOutput Yellow "⚠ Service is currently running"
            $restart = Read-Host "Restart service to apply new configuration? (Y/N)"
            if ($restart -eq "Y" -or $restart -eq "y") {
                Write-Host "Restarting service..."
                Restart-Service -Name "VITWiFiLogin" -Force
                Write-ColorOutput Green "✓ Service restarted successfully"
            } else {
                Write-ColorOutput Yellow "⚠ Remember to restart the service manually for changes to take effect!"
                Write-Host "Use: Restart-Service -Name 'VITWiFiLogin'"
            }
        } else {
            Write-ColorOutput Yellow "⚠ Service is not running"
            $start = Read-Host "Start service now? (Y/N)"
            if ($start -eq "Y" -or $start -eq "y") {
                Write-Host "Starting service..."
                Start-Service -Name "VITWiFiLogin"
                Write-ColorOutput Green "✓ Service started successfully"
            }
        }
    } else {
        Write-ColorOutput Yellow "⚠ Service 'VITWiFiLogin' not found"
        Write-Host "Make sure to install the service first."
    }
    
} catch {
    Write-ColorOutput Red "ERROR: Failed to save configuration file"
    Write-ColorOutput Red $_.Exception.Message
    pause
    exit 1
}

Write-Host ""
Write-ColorOutput Cyan "==================================================="
Write-Host "Configuration complete!"
Write-ColorOutput Cyan "==================================================="
Write-Host ""

# Proceed with service setup 

Write-Host ""
Write-ColorOutput Cyan "==================================================="
Write-Host "Starting service creation"
Write-ColorOutput Cyan "==================================================="
Write-Host ""

$cppFile = "wifi_login_service.cpp"
$exeFile = "wifi_login_service.exe"
$exePath = Join-Path $PSScriptRoot $exeFile
$cppPath = Join-Path $PSScriptRoot $cppFile

# Check if source file exists
if (-not (Test-Path $cppPath)) {
    Write-ColorOutput Red "ERROR: Source file not found: $cppFile"
    Write-Host "Make sure wifi_login_service.cpp is in the same directory as this script."
    pause
    exit 1
}

$compilers = @(
    @{Name="g++"; Path="g++"},
    @{Name="cl"; Path="cl"}
)

$compiler = $null
foreach ($c in $compilers) {
    try {
        $null = Get-Command $c.Path -ErrorAction Stop
        $compiler = $c
        break
    } catch {
        continue
    }
}

if (-not $compiler) {
    Write-ColorOutput Red "ERROR: No C++ compiler found!"
    Write-Host ""
    Write-Host "Please install one of the following:"
    Write-Host "  1. MinGW-w64 (g++) - https://www.mingw-w64.org/"
    Write-Host "  2. Visual Studio Build Tools (cl)"
    Write-Host ""
    Write-Host "For MinGW, add it to PATH after installation."
    pause
    exit 1
}

Write-Host "Found compiler: $($compiler.Name)"
Write-Host "Compiling $cppFile..."
Write-Host ""

# Delete old exe if exists
if (Test-Path $exePath) {
    Write-Host "Removing old executable..."
    Remove-Item $exePath -Force
}

# Compile based on compiler type
$compileSuccess = $false

if ($compiler.Name -eq "g++") {
    # MinGW/g++ compilation
    $compileCmd = "g++ -o `"$exePath`" `"$cppPath`" -lwlanapi -lwininet -ladvapi32 -static -std=c++17"
    Write-Host "Command: $compileCmd"
    Write-Host ""
    
    try {
        Invoke-Expression $compileCmd
        if ($LASTEXITCODE -eq 0 -and (Test-Path $exePath)) {
            $compileSuccess = $true
        }
    } catch {
        Write-ColorOutput Red "Compilation failed!"
        Write-ColorOutput Red $_.Exception.Message
    }
} elseif ($compiler.Name -eq "cl") {
    # MSVC compilation
    Write-Host "Using Visual Studio compiler..."
    $compileCmd = "cl /EHsc /Fe:`"$exePath`" `"$cppPath`" wlanapi.lib wininet.lib advapi32.lib"
    Write-Host "Command: $compileCmd"
    Write-Host ""
    
    try {
        Invoke-Expression $compileCmd
        if ($LASTEXITCODE -eq 0 -and (Test-Path $exePath)) {
            $compileSuccess = $true
            # Clean up MSVC artifacts
            Remove-Item "*.obj" -ErrorAction SilentlyContinue
        }
    } catch {
        Write-ColorOutput Red "Compilation failed!"
        Write-ColorOutput Red $_.Exception.Message
    }
}

if (-not $compileSuccess) {
    Write-ColorOutput Red "ERROR: Compilation failed!"
    Write-Host "Please check the error messages above and fix any issues in the source code."
    pause
    exit 1
}

Write-ColorOutput Green "✓ Compilation successful!"
Write-Host "Executable created: $exePath"
Write-Host ""

# Copy executable to install location
$installDir = "C:\Program Files\VITWiFiLogin"
$installedExe = "$installDir\$exeFile"

Write-Host "Installing service executable..."
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

Copy-Item $exePath $installedExe -Force
Write-ColorOutput Green "✓ Executable installed to: $installedExe"
Write-Host ""

$existingService = Get-Service -Name "VITWiFiLogin" -ErrorAction SilentlyContinue
if ($existingService) {
    Write-ColorOutput Yellow "⚠ Service already exists"
    Write-Host "Stopping existing service..."
    
    if ($existingService.Status -eq "Running") {
        Stop-Service -Name "VITWiFiLogin" -Force
        Start-Sleep -Seconds 2
    }
    
    Write-Host "Deleting existing service..."
    sc.exe delete VITWiFiLogin | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "Creating Windows service..."
$createResult = sc.exe create VITWiFiLogin binPath= "`"$installedExe`"" start= auto DisplayName= "VIT WiFi Auto Login"

if ($LASTEXITCODE -ne 0) {
    Write-ColorOutput Red "ERROR: Failed to create service"
    Write-Host $createResult
    pause
    exit 1
}

# Set service description
sc.exe description VITWiFiLogin "Automatically logs into VIT WiFi network when connected" | Out-Null

# Set service to restart on failure
sc.exe failure VITWiFiLogin reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

Write-ColorOutput Green "✓ Service created successfully"
Write-Host ""

# Create scheduled task for log cleanup
Write-Host ""
Write-Host "Setting up automatic log rotation..."

$taskName = "VITWiFiLogin-LogCleanup"
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($existingTask) {
    Write-Host "Removing existing log cleanup task..."
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

# PowerShell script for log rotation
$logCleanupScript = @'
$logFile = "C:\ProgramData\VITWiFiLogin\service.log"
$maxSizeMB = 10
$keepBackups = 3

if (Test-Path $logFile) {
    $sizeInMB = (Get-Item $logFile).Length / 1MB
    
    if ($sizeInMB -gt $maxSizeMB) {
        # Rotate logs
        for ($i = $keepBackups; $i -gt 0; $i--) {
            $oldLog = "$logFile.$i"
            $newLog = "$logFile.$($i + 1)"
            if (Test-Path $oldLog) {
                if ($i -eq $keepBackups) {
                    Remove-Item $oldLog -Force
                } else {
                    Move-Item $oldLog $newLog -Force
                }
            }
        }
        
        # Move current log to .1
        Move-Item $logFile "$logFile.1" -Force
        New-Item $logFile -ItemType File -Force
    }
}
'@

$scriptPath = "$configDir\cleanup_logs.ps1"
Set-Content -Path $scriptPath -Value $logCleanupScript -Encoding UTF8

# Create scheduled task (runs daily at 3 AM)
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Rotates VIT WiFi Login service logs when they exceed 10MB" | Out-Null

Write-ColorOutput Green "✓ Log rotation scheduled (daily at 3 AM)"
Write-Host "  - Max log size: 10 MB"
Write-Host "  - Keeps 3 backup files"
Write-Host ""

# Start the service
Write-Host "Starting service..."
Start-Service -Name "VITWiFiLogin"

if ((Get-Service -Name "VITWiFiLogin").Status -eq "Running") {
    Write-ColorOutput Green "✓ Service started successfully!"
} else {
    Write-ColorOutput Red "⚠ Service failed to start. Check the logs at:"
    Write-Host "   C:\ProgramData\VITWiFiLogin\service.log"
}

Write-Host ""
Write-ColorOutput Cyan "==================================================="
Write-ColorOutput Green "Setup Complete!"
Write-ColorOutput Cyan "==================================================="
Write-Host ""
Write-Host "Service Name: VITWiFiLogin"
Write-Host "Display Name: VIT WiFi Auto Login"
Write-Host "Executable: $installedExe"
Write-Host "Config File: $configFile"
Write-Host "Log File: C:\ProgramData\VITWiFiLogin\service.log"
Write-Host ""
Write-Host "Useful commands:"
Write-Host "  Check status:   Get-Service VITWiFiLogin"
Write-Host "  Stop service:   Stop-Service VITWiFiLogin"
Write-Host "  Start service:  Start-Service VITWiFiLogin"
Write-Host "  Restart:        Restart-Service VITWiFiLogin"
Write-Host "  View logs:      Get-Content 'C:\ProgramData\VITWiFiLogin\service.log' -Tail 50"
Write-Host ""
pause