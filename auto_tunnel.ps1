# VPN Detection and SSH Tunnel Script with Credential Manager

Write-Host "Debug: Script started. Current directory: $(Get-Location)" -ForegroundColor Cyan

if (-not (Get-Module -Name CredentialManager)) {
    Write-Host "CredentialManager module not found. Installing..."
    Install-Module -Name CredentialManager -Force -Scope CurrentUser
    Import-Module CredentialManager
}

Import-Module CredentialManager

# Add these variables at the beginning of the script
$global:sshProcess = $null
$global:tempPasswordFile = $null
$global:logFile = Join-Path $PSScriptRoot "auto_tunnel.log"
$global:configFile = Join-Path $PSScriptRoot "auto_tunnel_config.json"
$global:logLevels = @{
    "DEBUG" = 0
    "INFO" = 1
    "WARNING" = 2
    "ERROR" = 3
}

# Add this at the beginning of your script
$global:logLock = New-Object System.Threading.Mutex

# Add these variables at the beginning of the script
$global:logQueue = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
$global:loggerRunspace = $null
$global:loggerPowerShell = $null
$global:logFileBase = Join-Path $PSScriptRoot "auto_tunnel"
$global:maxLogFiles = 7 # Keep logs for the last 7 days
$global:maxLogSizeMB = 10 # Maximum size of a single log file in MB

# Add these variables at the beginning of the script
$global:lastLogMessage = ""
$global:lastLogCount = 0
$global:lastLogTime = [DateTime]::MinValue

# Set default error action to stop script execution on any error
# This helps catch and handle errors more explicitly
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Logging function
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("DEBUG", "INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $configLogLevel = $config.logLevel
    if (-not $configLogLevel -or -not $logLevels.ContainsKey($configLogLevel)) {
        $configLogLevel = "INFO"
    }
    
    if ($logLevels[$Level] -ge $logLevels[$configLogLevel]) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$Level] $Message"

        # Check for duplicate messages
        if ($logMessage -eq $global:lastLogMessage) {
            $global:lastLogCount++
            $timeSinceLastLog = (Get-Date) - $global:lastLogTime
            if ($timeSinceLastLog.TotalMinutes -ge 1) {
                $countMessage = "Previous message repeated $global:lastLogCount times in the last $($timeSinceLastLog.TotalMinutes.ToString("F2")) minutes"
                $global:logQueue.Enqueue("[$timestamp] [INFO] $countMessage")
                $global:lastLogCount = 0
                $global:lastLogTime = Get-Date
            }
        } else {
            if ($global:lastLogCount -gt 0) {
                $countMessage = "Previous message repeated $global:lastLogCount times"
                $global:logQueue.Enqueue("[$timestamp] [INFO] $countMessage")
            }
            $global:logQueue.Enqueue($logMessage)
            $global:lastLogMessage = $logMessage
            $global:lastLogCount = 0
            $global:lastLogTime = Get-Date
        }
    }
}

# Function to read configuration
function Get-Config {
    if (Test-Path $global:configFile) {
        $config = Get-Content $global:configFile | ConvertFrom-Json
        Write-Log "Configuration loaded successfully."
        return $config
    } else {
        Write-Log "Configuration file not found. Using default values." -Level "WARNING"
        return $null
    }
}

# Load configuration
$config = Get-Config

# Function to check if VPN is connected by looking for the Ivanti process
function Test-IvantiProcess {
    $processName = $config.vpnProcessName
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    Write-Log "Ivanti process status: $($null -ne $process)" -Level "DEBUG"
    return $null -ne $process
}

# Function to check for specific IP routes
function Test-VPNRoute {
    $vpnRoute = Get-NetRoute | Where-Object { $_.DestinationPrefix -like "$($config.vpnRoutePrefix)*" }
    Write-Log "VPN route status: $($null -ne $vpnRoute)" -Level "DEBUG"
    return $null -ne $vpnRoute
}

# This is the main function to check VPN status
function Test-VPNConnection {
    $isProcessRunning = Test-IvantiProcess
    $isRoutePresent = Test-VPNRoute
    Write-Log "VPN Process Detected: $isProcessRunning" -Level "DEBUG"
    Write-Log "VPN Route Detected: $isRoutePresent" -Level "DEBUG"
    return ($isProcessRunning -and $isRoutePresent)
}

# Function to establish SSH tunnel
function Start-SSHTunnel {
    $remoteHost = $config.remoteHost
    $sshUser = $config.sshUser
    $sshKeyPath = $config.sshKeyPath
    $localPort = $config.localPort
    $wslDistribution = $config.wslDistribution
    $wslUser = $config.wslUser
    $credentialTarget = $config.credentialTarget
    
    Write-Log "Getting stored credential..." -Level "DEBUG"
    $cred = Get-StoredCredential -Target $credentialTarget
    Write-Log "Credential retrieved, proceeding..." -Level "DEBUG"
    
    Write-Log "Preparing SSH command..." -Level "DEBUG"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    
    $global:tempPasswordFile = "~/ssh_password_$(Get-Random)"
    $wslCommand = "echo -n '$plainPassword' > $global:tempPasswordFile && chmod 600 $global:tempPasswordFile"
    wsl -d $wslDistribution -u $wslUser zsh -c $wslCommand

    $sshCommandWithPassword = "ssh -N -D $localPort -i $sshKeyPath -o StrictHostKeyChecking=no -tt $sshUser@$remoteHost < $global:tempPasswordFile 2>&1"
    $cleanupCommand = "rm -f $global:tempPasswordFile"
    $sshCommandWithPassword += "; $cleanupCommand"
    Write-Log "SSH command prepared (password hidden)" -Level "DEBUG"
    
    try {
        Write-Log "Attempting to start SSH process..." -Level "INFO"
        $sshLogFile = Join-Path $PSScriptRoot "ssh_tunnel.log"
        Write-Log "SSH output is being logged to: $sshLogFile" -Level "DEBUG"
        $global:sshProcess = Start-Process wsl -ArgumentList "-d $wslDistribution -u $wslUser zsh -c `"($sshCommandWithPassword) 2>&1`"" -PassThru -NoNewWindow -RedirectStandardOutput $sshLogFile
        if ($null -ne $global:sshProcess) {
            Write-Log "SSH tunnel process started. Process ID: $($global:sshProcess.Id)" -Level "INFO"
            return $true
        } else {
            Write-Log "Failed to start the SSH process." -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error starting SSH tunnel: $_" -Level "ERROR"
        Write-Log "Debug: Full error details: $($_ | Format-List -Force | Out-String)" -Level "ERROR"
        return $false
    }
}

# Function to check the tunnel health
function Test-SSHTunnelHealth {
    Write-Log "Testing SSH tunnel health..." -Level "DEBUG"
    $proxyHost = "127.0.0.1"
    $proxyPort = $config.localPort
    $maxAttempts = 2
    $attempt = 0
    $overallTimeout = 10  # Reduced overall timeout to 10 seconds

    $startTime = Get-Date
    while ($attempt -lt $maxAttempts -and ((Get-Date) - $startTime).TotalSeconds -lt $overallTimeout) {
        try {
            Write-Log "Attempting to connect to ${proxyHost}:${proxyPort}" -Level "DEBUG"
            
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connectionTask = $tcpClient.ConnectAsync($proxyHost, $proxyPort)
            
            if ($connectionTask.Wait(2000)) {  # Reduced timeout to 2 seconds
                if ($tcpClient.Connected) {
                    Write-Log "SSH tunnel health check successful. Connected to ${proxyHost}:${proxyPort}" -Level "DEBUG"
                    $tcpClient.Close()
                    return $true
                }
            } else {
                throw New-Object System.TimeoutException("Connection attempt timed out")
            }
        }
        catch [System.TimeoutException] {
            $attempt++
            Write-Log "SSH tunnel health check failed (Attempt $attempt of $maxAttempts): Connection timed out" -Level "WARNING"
        }
        catch {
            $attempt++
            $errorMessage = $_.Exception.Message
            Write-Log "SSH tunnel health check failed (Attempt $attempt of $maxAttempts): $errorMessage" -Level "WARNING"
            Write-Log "Exception Type: $($_.Exception.GetType().FullName)" -Level "DEBUG"
            Write-Log "Stack Trace: $($_.Exception.StackTrace)" -Level "DEBUG"
        }
        finally {
            if ($null -ne $tcpClient) {
                $tcpClient.Close()
            }
            
            if ($attempt -lt $maxAttempts) {
                Start-Sleep -Seconds 1  # Fixed 1-second delay between attempts
            }
        }
    }

    Write-Log "SSH tunnel health check failed after $attempt attempts or timed out after $overallTimeout seconds" -Level "ERROR"
    return $false
}

function Test-SSHTunnelActive {
    $tunnelProcess = wsl -d $config.wslDistribution -u $config.wslUser zsh -c $config.sshTunnelCheckCommand
    $processActive = $null -ne $tunnelProcess
    Write-Log "SSH tunnel process status: $processActive" -Level "DEBUG"
    
    if ($processActive) {
        $tunnelHealthy = Test-SSHTunnelHealth
        Write-Log "SSH tunnel health status: $tunnelHealthy" -Level "DEBUG"
        return $tunnelHealthy
    }
    
    return $false
}

# Add this new function for graceful shutdown
function Stop-SSHTunnel {
    Write-Log "Stopping SSH tunnel..." -Level "INFO"
    if ($null -ne $global:sshProcess) {
        $global:sshProcess | Stop-Process -Force
        $global:sshProcess = $null
        Write-Log "SSH process stopped." -Level "INFO"
    }

    if ($global:tempPasswordFile) {
        wsl -d $config.wslDistribution -u $config.wslUser zsh -c "rm -f $global:tempPasswordFile"
        $global:tempPasswordFile = $null
        Write-Log "Temporary password file removed." -Level "INFO"
    }
}

# Function to update logs
function Update-Logs {
    param($logFileBase)
    Write-Host "Debug: Starting log rotation..." -ForegroundColor Cyan
    $logFiles = Get-ChildItem -Path "$logFileBase-*.log" | Sort-Object LastWriteTime -Descending
    $totalSize = 0
    $filesToDelete = @()

    foreach ($file in $logFiles) {
        $age = (Get-Date) - $file.LastWriteTime
        $totalSize += $file.Length

        if ($age.Days -gt 7 -or $totalSize -gt 100MB) {
            $filesToDelete += $file
        }
    }

    foreach ($file in $filesToDelete) {
        Remove-Item $file.FullName -Force
        Write-Host "Debug: Deleted old log file: $($file.FullName)" -ForegroundColor Yellow
    }

    Write-Host "Debug: Log rotation completed." -ForegroundColor Cyan
}


function Get-CurrentLogFileName($logFileBase) {
    $date = Get-Date -Format "yyyy-MM-dd"
    $fileName = "$logFileBase-$date.log"
    Write-Host "Debug: Attempting to create/use log file: $fileName" -ForegroundColor Cyan
    if (-not (Test-Path $fileName)) {
        try {
            New-Item -Path $fileName -ItemType File -Force | Out-Null
            Write-Host "Debug: New log file created: $fileName" -ForegroundColor Green
        } catch {
            Write-Host "Error creating log file: $_" -ForegroundColor Red
        }
    }
    return $fileName
}


# Modify the function to process the log queue
function Start-LoggerRunspace {
    Write-Host "Debug: Starting logger runspace..." -ForegroundColor Cyan
    Write-Host "Debug: LogFileBase: $global:logFileBase" -ForegroundColor Cyan

    $scriptBlock = {
        param($logQueue, $logFileBase, $logLevels, $maxLogFiles, $maxLogSizeMB, $GetCurrentLogFileName, $UpdateLogs)
        $lastLogDate = $null
        $currentLogFile = $null
        $lastRotationCheck = [DateTime]::MinValue
        $rotationCheckInterval = [TimeSpan]::FromHours(1)

        while ($true) {
            try {
                $currentDate = Get-Date
                if ($lastLogDate -ne $currentDate.Date -or $null -eq $currentLogFile) {
                    $lastLogDate = $currentDate.Date
                    $currentLogFile = & $GetCurrentLogFileName $logFileBase
                }

                if (-not $logQueue.IsEmpty) {
                    $logMessage = $null
                    if ($logQueue.TryDequeue([ref]$logMessage)) {
                        Add-Content -Path $currentLogFile -Value $logMessage -ErrorAction Stop
                    }
                } 
                # Check if it's time to rotate logs
                if ((Get-Date) - $lastRotationCheck -gt $rotationCheckInterval) {
                    & $UpdateLogs $logFileBase
                    $lastRotationCheck = Get-Date
                }
            } catch {
                Write-Host "Error in logger runspace: $_" -ForegroundColor Red
                Write-Host "Error details: $($_ | Format-List -Force | Out-String)" -ForegroundColor Red
            }
            Start-Sleep -Milliseconds 100
        }
    }

    $global:loggerRunspace = [runspacefactory]::CreateRunspace()
    $global:loggerRunspace.Open()
    $global:loggerPowerShell = [powershell]::Create().AddScript($scriptBlock).AddArgument($global:logQueue).AddArgument($global:logFileBase).AddArgument($global:logLevels).AddArgument($global:maxLogFiles).AddArgument($global:maxLogSizeMB).AddArgument(${function:Get-CurrentLogFileName}).AddArgument(${function:Update-Logs})
    $global:loggerPowerShell.Runspace = $global:loggerRunspace
    $global:loggerPowerShell.BeginInvoke()
}

# Add this function near the top of your script, after other function definitions
function Stop-LoggerRunspace {
    Write-Host "Debug: Stopping logger runspace..." -ForegroundColor Cyan
    if ($null -ne $global:loggerPowerShell) {
        $global:loggerPowerShell.Stop()
        $global:loggerPowerShell.Dispose()
        $global:loggerPowerShell = $null
        Write-Host "Debug: Logger PowerShell instance stopped and disposed." -ForegroundColor Cyan
    }
    if ($null -ne $global:loggerRunspace) {
        $global:loggerRunspace.Close()
        $global:loggerRunspace.Dispose()
        $global:loggerRunspace = $null
        Write-Host "Debug: Logger runspace closed and disposed." -ForegroundColor Cyan
    }
    Write-Host "Debug: Logger runspace stopped." -ForegroundColor Cyan
}

# Add this function to compress old logs
function Compress-OldLogs {
    $logCompressOlderThan = Parse-TimeSpan $config.logCompressOlderThan
    $logFiles = Get-ChildItem -Path "$global:logFileBase-*.log" | Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).Subtract($logCompressOlderThan) }
    foreach ($file in $logFiles) {
        $compressedFile = "$($file.FullName).gz"
        try {
            Compress-Archive -Path $file.FullName -DestinationPath $compressedFile -CompressionLevel Optimal -Force
            Remove-Item $file.FullName
            Write-Host "Compressed and removed old log file: $($file.Name)"
        } catch {
            Write-Host "Failed to compress log file $($file.Name): $_"
        }
    }
}

# Add this function near the top of your script, after other function definitions
function Parse-TimeSpan {
    param (
        [string]$value
    )
    
    if ($value -match '^\d+[smhdw]$') {
        $number = [int]($value.Substring(0, $value.Length - 1))
        $unit = $value.Substring($value.Length - 1)
        
        switch ($unit) {
            's' { return [TimeSpan]::FromSeconds($number) }
            'm' { return [TimeSpan]::FromMinutes($number) }
            'h' { return [TimeSpan]::FromHours($number) }
            'd' { return [TimeSpan]::FromDays($number) }
            'w' { return [TimeSpan]::FromDays($number * 7) }
        }
    }
    
    throw "Invalid TimeSpan format: $value"
}

function Main {
    Start-LoggerRunspace
    # Wait a moment for the logger runspace to initialize
    Start-Sleep -Seconds 2
    
    $checkInterval = $config.checkIntervalSeconds
    $lastCompressionTime = [DateTime]::MinValue
    $compressionInterval = Parse-TimeSpan $config.logCompressionInterval

    try {
        while ($true) {
            if (Test-VPNConnection) {
                Write-Log "VPN is connected. Checking SSH tunnel..." -Level "DEBUG"
                if (-not (Test-SSHTunnelActive)) {
                    Write-Log "SSH tunnel is not active. Starting SSH tunnel..." -Level "INFO"
                    $tunnelStarted = Start-SSHTunnel
                    if (-not $tunnelStarted) {
                        Write-Log "Failed to start SSH tunnel." -Level "ERROR"
                    }
                } else {
                    Write-Log "SSH tunnel is active." -Level "DEBUG"
                }
            } else {
                Write-Log "Waiting for VPN connection..." -Level "INFO"
            }

            # Check if it's time to compress logs
            if ((Get-Date) - $lastCompressionTime -gt $compressionInterval) {
                Compress-OldLogs
                $lastCompressionTime = Get-Date
            }

            Start-Sleep -Seconds $checkInterval
        }
    }
    catch {
        Write-Log "An error occurred in the main loop: $_" -Level "ERROR"
        Write-Log "Error details: $($_ | Format-List -Force | Out-String)" -Level "DEBUG"
    }
    finally {
        Write-Host "Debug: Entering finally block for graceful shutdown." -ForegroundColor Cyan
    
        Write-Log "Beginning graceful shutdown..." -Level "INFO"
    
        Stop-SSHTunnel
        Write-Log "SSH tunnel stopped." -Level "INFO"
    
        # Ensure all remaining log messages are processed
        Write-Host "Debug: Waiting for log queue to empty..." -ForegroundColor Cyan
        $timeout = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $global:logQueue.IsEmpty -and $timeout.Elapsed.TotalSeconds -lt 10) {
            Start-Sleep -Milliseconds 100
        }
        if (-not $global:logQueue.IsEmpty) {
            Write-Host "Warning: Log queue not empty after 10 seconds. Some messages may be lost." -ForegroundColor Yellow
        }
    
        Write-Log "Script terminating gracefully." -Level "INFO"
    
        # Stop the logger runspace
        Stop-LoggerRunspace
    
        Write-Host "Debug: Graceful shutdown completed." -ForegroundColor Cyan
    }
}

Main