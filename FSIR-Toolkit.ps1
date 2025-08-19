<#
.SYNOPSIS
    Forensic Security Incident Response (FSIR) Toolkit - A comprehensive GUI-based tool for Microsoft 365 security incident response.

.DESCRIPTION
    The FSIR Toolkit provides a graphical interface for conducting security incident response activities
    in Microsoft 365 environments. It automates critical tasks including user account lockdown, 
    forensic data collection, audit log extraction, and comprehensive security analysis.

.FEATURES
    - Connect to Microsoft 365 services (Azure AD, Exchange Online, Microsoft Graph)
    - User account lockdown and remediation
    - Forensic data collection and analysis
    - Audit log extraction and processing
    - Dark/Light mode interface
    - Real-time progress monitoring
    - Comprehensive logging and reporting

.MODES
    - Lockdown with Forensics: Complete incident response including user lockdown and forensic collection
    - Forensics Only: Extract forensic data without affecting user access
    - Lockdown Only: Secure user account without forensic collection

.REQUIREMENTS
    - PowerShell 5.1 or later
    - Microsoft 365 tenant with appropriate administrative permissions
    - Required PowerShell modules: ExchangeOnlineManagement, MSOnline, AzureAD, Microsoft.Graph.*

.NOTES
    Version: 1.0.2
    Author: FSIR Team
    Created: August 2025
    
.EXAMPLE
    .\FSIR-Toolkit.ps1
    
    Launches the FSIR Toolkit GUI interface.

.LINK
    https://github.com/yourusername/FSIR-Toolkit
#>

[CmdletBinding()]
param()

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Web, System.Threading
# Light Green: #09ca44
# Dark Green: #008000

#region Script Variables
$script:ScriptVersion = "1.0.2" 
$script:isConnected = $false
$script:aboutWindow = $null
$script:mdapWindow = $null
$script:AuditLogWindow = $null
$script:IsDarkMode = $false
$script:scriptPath = "C:\temp\FSIR"
$script:currentRemediationRunspace = $null
$script:remediationCancellationSource = $null
$script:logfile = "FSIR-Remediation-$(Get-Date -Format 'MMddyy_hhmmtt').log"
$script:logpath = "c:\temp\FSIR\Output\Transcripts\"
# Initialize UPN as empty string - will be set when user provides input
$script:TargetUPN = ""
$script:ForensicsFolder = ""  # Will be set dynamically based on UPN
$script:abortRemediation = $false
$script:welcomeTypingTimer = $null
$script:ConnectionState = @{
    IsConnecting = $false
    IsAuthenticated = $false
    ConnectionTasks = @{}
    LastConnectionTime = $null
}
$script:SharedSessionState = @{
    ExchangeSession = $null
}

# Additional logging variable for compatibility
$logfile = "FSIR-Remediation-$(Get-Date -Format 'MMddyy_hhmmtt').log"

function Initialize-ForensicsFolder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UPN
    )
    
    if ([string]::IsNullOrWhiteSpace($UPN)) {
        Write-Warning "UPN is null or empty. Cannot initialize forensics folder."
        return $false
    }
    
    $script:ForensicsFolder = "C:\temp\FSIR\Output\Forensics\$UPN"
    
    if (-not (Test-Path -Path $script:ForensicsFolder)) {
        try {
            New-Item -Path $script:ForensicsFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Created forensics folder: $($script:ForensicsFolder)"
            return $true
        }
        catch {
            Write-Error "Error creating forensics folder: $_"
            return $false
        }
    }
    else {
        Write-Verbose "Forensics folder already exists: $($script:ForensicsFolder)"
        return $true
    }
}

# Initialize log directory
if (-not (Test-Path -Path $script:logpath)) {
    try {
        New-Item -Path $script:logpath -ItemType Directory -Force -ErrorAction Stop
        Write-Verbose "Created transcript directory: $($script:logpath)"
    }
    catch {
        Write-Error "Error creating transcript directory: $_"
        throw "Failed to initialize logging directory. Script cannot continue."
    }
}

#region Helper Functions
function Test-UPNFormat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UPN
    )
    
    # Basic email format validation
    $emailRegex = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if ([string]::IsNullOrWhiteSpace($UPN)) {
        return $false
    }
    
    if ($UPN -notmatch $emailRegex) {
        return $false
    }
    
    # Additional Microsoft 365 specific checks
    if ($UPN.Length -gt 113) {  # Microsoft 365 UPN length limit
        return $false
    }
    
    return $true
}

function Write-EnhancedLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG", "SUCCESS")]
        [string]$Category = "INFO",
        
        [Parameter()]
        [switch]$WriteToFile
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Category] $Message"
    
    # Color coding for console output
    $color = switch ($Category) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "DEBUG" { "Cyan" }
        default { "White" }
    }
    
    Write-Host $logEntry -ForegroundColor $color
    
    if ($WriteToFile -and $script:logpath) {
        $logFile = Join-Path $script:logpath "FSIR-Enhanced-$(Get-Date -Format 'yyyyMMdd').log"
        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
}

function Test-Prerequisites {
    [CmdletBinding()]
    param()
    
    Write-EnhancedLog -Message "Checking system prerequisites..." -Category "INFO"
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-EnhancedLog -Message "PowerShell 5.1 or later is required. Current version: $($PSVersionTable.PSVersion)" -Category "ERROR"
        return $false
    }
    
    # Check for required modules
    $requiredModules = @(
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Authentication', 
        'Microsoft.Graph.Identity.SignIns',
        'ExchangeOnlineManagement',
        'MSOnline',
        'AzureAD'
    )
    
    $missingModules = @()
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-EnhancedLog -Message "Missing required modules: $($missingModules -join ', ')" -Category "WARNING"
        Write-EnhancedLog -Message "These modules will be installed automatically when needed." -Category "INFO"
    }
    
    # Check if running as administrator (recommended)
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-EnhancedLog -Message "Not running as administrator. Some operations may require elevated privileges." -Category "WARNING"
    }
    
    Write-EnhancedLog -Message "Prerequisites check completed." -Category "SUCCESS"
    return $true
}

function Test-InputSafety {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputText,
        
        [Parameter()]
        [ValidateSet("UPN", "Path", "General")]
        [string]$InputType = "General"
    )
    
    if ([string]::IsNullOrWhiteSpace($InputText)) {
        return $false
    }
    
    # Check for common injection patterns
    $dangerousPatterns = @(
        '(script|javascript|vbscript)',
        '(<.*>.*</.*>)',
        '(eval|exec|system|shell)',
        '(\||\;|\&|\$\()',
        '(\.\.[\\/])',
        '(DROP|SELECT|INSERT|UPDATE|DELETE)\s',
        '(\-\-|\#|\/\*)'
    )
    
    foreach ($pattern in $dangerousPatterns) {
        if ($InputText -match $pattern) {
            Write-EnhancedLog -Message "Potentially dangerous input detected: $pattern" -Category "ERROR"
            return $false
        }
    }
    
    # Type-specific validation
    switch ($InputType) {
        "UPN" {
            return Test-UPNFormat -UPN $InputText
        }
        "Path" {
            # Validate path doesn't contain dangerous characters
            $invalidChars = [IO.Path]::GetInvalidPathChars() + [IO.Path]::GetInvalidFileNameChars()
            foreach ($char in $invalidChars) {
                if ($InputText.Contains($char)) {
                    return $false
                }
            }
        }
    }
    
    return $true
}

function Set-SecureCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Store", "Retrieve", "Remove")]
        [string]$Action,
        
        [Parameter(Mandatory = $true)]
        [string]$TargetName,
        
        [Parameter()]
        [PSCredential]$Credential
    )
    
    $targetName = "FSIR_$TargetName"
    
    try {
        switch ($Action) {
            "Store" {
                if (-not $Credential) {
                    throw "Credential parameter is required for Store action"
                }
                
                # Store credential securely using Windows Credential Manager
                $username = $Credential.UserName
                $password = $Credential.GetNetworkCredential().Password
                
                # Use cmdkey to store credential
                $result = & cmdkey /generic:$targetName /user:$username /pass:$password 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-EnhancedLog -Message "Credential stored successfully for $TargetName" -Category "SUCCESS"
                    return $true
                } else {
                    throw "Failed to store credential: $result"
                }
            }
            
            "Retrieve" {
                # Retrieve stored credential
                $result = & cmdkey /list:$targetName 2>&1
                if ($LASTEXITCODE -eq 0 -and $result -match "User: (.+)") {
                    $username = $matches[1]
                    Write-EnhancedLog -Message "Retrieved credential for $username" -Category "SUCCESS"
                    return $username
                } else {
                    Write-EnhancedLog -Message "No stored credential found for $TargetName" -Category "WARNING"
                    return $null
                }
            }
            
            "Remove" {
                # Remove stored credential
                $result = & cmdkey /delete:$targetName 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-EnhancedLog -Message "Credential removed successfully for $TargetName" -Category "SUCCESS"
                    return $true
                } else {
                    Write-EnhancedLog -Message "Failed to remove credential or credential not found" -Category "WARNING"
                    return $false
                }
            }
        }
    }
    catch {
        Write-EnhancedLog -Message "Error managing credential: $_" -Category "ERROR"
        return $false
    }
}

function Connect-M365Service {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("AzureAD", "ExchangeOnline", "MsGraph")]
        [string]$ServiceType,
        
        [Parameter()]
        [switch]$ForceReconnect
    )
    
    Write-EnhancedLog -Message "Connecting to $ServiceType..." -Category "INFO"
    
    try {
        switch ($ServiceType) {
            "AzureAD" {
                if ($ForceReconnect -or -not (Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue)) {
                    Connect-AzureAD -ErrorAction Stop
                    Write-EnhancedLog -Message "Successfully connected to Azure AD" -Category "SUCCESS"
                } else {
                    Write-EnhancedLog -Message "Using existing Azure AD connection" -Category "INFO"
                }
            }
            
            "ExchangeOnline" {
                if ($ForceReconnect -or -not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
                    Connect-ExchangeOnline -ShowProgress $false -ErrorAction Stop
                    Write-EnhancedLog -Message "Successfully connected to Exchange Online" -Category "SUCCESS"
                } else {
                    Write-EnhancedLog -Message "Using existing Exchange Online connection" -Category "INFO"
                }
            }
            
            "MsGraph" {
                $context = Get-MgContext -ErrorAction SilentlyContinue
                if ($ForceReconnect -or -not $context) {
                    $scopes = @(
                        "User.ReadWrite.All",
                        "Directory.ReadWrite.All", 
                        "AuditLog.Read.All",
                        "SecurityEvents.ReadWrite.All"
                    )
                    Connect-MgGraph -Scopes $scopes -ErrorAction Stop
                    Write-EnhancedLog -Message "Successfully connected to Microsoft Graph" -Category "SUCCESS"
                } else {
                    Write-EnhancedLog -Message "Using existing Microsoft Graph connection" -Category "INFO"
                }
            }
        }
        
        return $true
    }
    catch {
        Write-EnhancedLog -Message "Failed to connect to $ServiceType`: $_" -Category "ERROR"
        return $false
    }
}



function Get-IncidentResponseRecommendations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ThreatHuntingResults,
        
        [Parameter(Mandatory = $true)]
        [string]$UPN
    )
    
    $recommendations = @()
    
    switch ($ThreatHuntingResults.ThreatLevel) {
        "Critical" {
            $recommendations += "IMMEDIATE: Disable user account pending investigation"
            $recommendations += "IMMEDIATE: Reset user password and revoke all sessions"
            $recommendations += "IMMEDIATE: Contact security team and management"
            $recommendations += "Review all administrative actions performed by this user"
            $recommendations += "Check for lateral movement to other accounts"
            $recommendations += "Consider forensic imaging of user's devices"
        }
        
        "High" {
            $recommendations += "Reset user password and revoke active sessions"
            $recommendations += "Enable additional monitoring for this user"
            $recommendations += "Review and validate all recent user activities"
            $recommendations += "Consider temporary access restrictions"
            $recommendations += "Notify security team for further investigation"
        }
        
        "Medium" {
            $recommendations += "Schedule security awareness training for user"
            $recommendations += "Review and update user permissions"
            $recommendations += "Monitor user activities for next 30 days"
            $recommendations += "Consider multi-factor authentication enforcement"
        }
        
        "Low" {
            $recommendations += "Document findings for future reference"
            $recommendations += "Consider periodic security check-ins"
            $recommendations += "Review general security policies"
        }
        
        default {
            $recommendations += "Continue normal monitoring procedures"
            $recommendations += "No immediate action required"
        }
    }
    
    return $recommendations
}

#endregion

function Show-SplashScreen {
    param (
        [string]$ImagePath,
        [int]$Duration = 3000,
        [int]$ImageWidth = 300,
        [int]$ImageHeight = 300,
        [System.Windows.Window]$MainWindow
    )
  
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName System.Windows.Forms
  
    # Convert relative path to absolute path
    $fullPath = Convert-Path $ImagePath -ErrorAction SilentlyContinue
    if (-not $fullPath) {
        Write-Warning "Image not found at path: $ImagePath"
        return
    }

    # Create proper URI from file path
    $imageUri = [System.Uri]::new($fullPath, [System.UriKind]::Absolute)
  
    $window = New-Object System.Windows.Window
    $window.WindowStyle = 'None'
    $window.AllowsTransparency = $true
    $window.Background = [System.Windows.Media.Brushes]::Transparent
    $window.Topmost = $true
  
    $image = New-Object System.Windows.Controls.Image
    try {
        $image.Source = [System.Windows.Media.Imaging.BitmapImage]::new($imageUri)
    }
    catch {
        Write-Warning "Failed to load image: $_"
        return
    }
    
    $image.Stretch = 'Uniform'
    $image.Width = $ImageWidth
    $image.Height = $ImageHeight
  
    $window.Content = $image
    $window.SizeToContent = 'WidthAndHeight'
  
    if ($MainWindow) {
        # If MainWindow is provided, center on that window
        $window.Owner = $MainWindow
        $window.WindowStartupLocation = 'CenterOwner'
    } else {
        # Get the primary screen's working area
        $primaryScreen = [System.Windows.Forms.Screen]::PrimaryScreen
        $workingArea = $primaryScreen.WorkingArea
        
        # Set window position to center on primary screen
        $window.WindowStartupLocation = 'Manual'
        
        # Calculate center position
        $window.Left = $workingArea.Left + ($workingArea.Width - $ImageWidth) / 3
        $window.Top = $workingArea.Top + ($workingArea.Height - $ImageHeight) / 3
    }
  
    $window.Show()
    Start-Sleep -Milliseconds $Duration
    $window.Close()
}

function Write-Output {
    param([string]$Message)
    $OutputBox.Dispatcher.Invoke([Action]{
        $OutputBox.AppendText("$Message`n")
        $OutputBox.ScrollToEnd()
    })
}

  function Write-Log {
param (
    [string]$Message
)
Add-Content -Path $logfile -Value "$(Get-Date) - $Message"
}

function Write-RemediationLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info'
    )
    
    # Create timestamp
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    
    # Format the log message
    $formattedMessage = "[$timestamp] [$Level] $Message"
    
    # Determine log file path
    $logDirectory = "C:\temp\FSIR\Output"
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
    }
    
    $logFile = Join-Path $logDirectory "FSIR-Remediation_$(Get-Date -Format 'yyyyMMdd').log"
    
    # Write to log file
    Add-Content -Path $logFile -Value $formattedMessage
}

function Start-RemediationTranscript {
    param(
        [string]$UserPrincipalName,
        [string]$RemediationType
    )
    
    $transcriptDirectory = "C:\temp\FSIR\output\transcripts"
    if (-not (Test-Path -Path $transcriptDirectory)) {
        New-Item -Path $transcriptDirectory -ItemType Directory -Force | Out-Null
    }
    
    $transcriptFile = Join-Path $transcriptDirectory "FSIR-Remediation_${UserPrincipalName}_${RemediationType}_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    try {
        Start-Transcript -Path $transcriptFile -Append
        Write-RemediationLog "Started transcript at $transcriptFile" -Level Info
        return $transcriptFile
    }
    catch {
        Write-RemediationLog "Failed to start transcript: $_" -Level Error
        return $null
    }
}

function Stop-RemediationTranscript {
    try {
        Stop-Transcript
        Write-RemediationLog "Stopped transcript" -Level Info
    }
    catch {
        Write-RemediationLog "Failed to stop transcript: $_" -Level Error
    }
}

$iconUrls = @{
    "Clear" = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/clear.ico"
    "Exit" = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/exit.ico"
    "Audit" = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/audit.ico"
    "About" = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/help.ico"
    "Abort" = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/abort.ico"
    "Terminate" = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/terminate.ico"
    "SearchPurge" = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/search.ico"
    "Dev" = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/dev.ico"
    "DarkMode" = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/dark2.ico"
    "EnableDevice" = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/mobile.ico"
    "SplashScreen" = "https://axcientrestore.blob.core.windows.net/win11/resources/fsir.png"
}

#region Resource Population Functions
function Get-ImageFromUrl($url) {
    try {
        $webClient = New-Object System.Net.WebClient
        $imageBytes = $webClient.DownloadData($url)
        $memoryStream = New-Object System.IO.MemoryStream($imageBytes, 0, $imageBytes.Length)
        
        $iconImage = [System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::FromStream($memoryStream)).GetHicon())
        $imageSource = [System.Windows.Interop.Imaging]::CreateBitmapSourceFromHIcon(
            $iconImage.Handle,
            [System.Windows.Int32Rect]::Empty,
            [System.Windows.Media.Imaging.BitmapSizeOptions]::FromEmptyOptions()
        )
        $imageSource.Freeze()
        return $imageSource
    } catch {
        Write-Host "Failed to load image from URL: $url. Error: $_"
        Write-Host "Stack Trace: $($_.ScriptStackTrace)"
        return $null
    }
}

function Get-ImageFromFile($filePath) {
    try {
        if (-not (Test-Path $filePath)) {
            Write-Host "Image file not found: $filePath"
            return $null
        }

        $extension = [System.IO.Path]::GetExtension($filePath).ToLower()
        
        if ($extension -eq ".ico") {
            # Handle .ico files
            $iconImage = [System.Drawing.Icon]::new($filePath)
            $imageSource = [System.Windows.Interop.Imaging]::CreateBitmapSourceFromHIcon(
                $iconImage.Handle,
                [System.Windows.Int32Rect]::Empty,
                [System.Windows.Media.Imaging.BitmapSizeOptions]::FromEmptyOptions()
            )
            $imageSource.Freeze()
            return $imageSource
        } else {
            # Handle other image formats (png, jpg, etc.)
            $uri = [System.Uri]::new($filePath, [System.UriKind]::Absolute)
            $imageSource = [System.Windows.Media.Imaging.BitmapImage]::new($uri)
            $imageSource.Freeze()
            return $imageSource
        }
    } catch {
        Write-Host "Failed to load image from file: $filePath. Error: $_"
        Write-Host "Stack Trace: $($_.ScriptStackTrace)"
        return $null
    }
}

function Get-IconImage($iconName) {
    <#
    .SYNOPSIS
    Loads an icon image from local files first, with URL fallback
    
    .DESCRIPTION
    This function attempts to load an icon from the local icons directory first.
    If the local file doesn't exist, it falls back to downloading from the URL.
    
    .PARAMETER iconName
    The name of the icon (key from $iconUrls hashtable)
    
    .EXAMPLE
    Get-IconImage "Audit"
    #>
    
    try {
        $iconFolder = "C:\temp\FSIR\icons"
        Write-Host "Get-IconImage called for: $iconName"
        
        if (-not $iconUrls.ContainsKey($iconName)) {
            Write-Host "Icon name '$iconName' not found in iconUrls"
            return $null
        }
        
        # Determine file extension from original URL
        $extension = [System.IO.Path]::GetExtension($iconUrls[$iconName])
        $localIconPath = Join-Path $iconFolder ($iconName + $extension)
        Write-Host "Looking for local file: $localIconPath"
        
        # Try to load from local file first
        if (Test-Path $localIconPath) {
            Write-Host "Local file found, loading: $localIconPath"
            return Get-ImageFromFile $localIconPath
        } else {
            Write-Host "Local file not found, using URL: $($iconUrls[$iconName])"
            # Fallback to URL
            return Get-ImageFromUrl $iconUrls[$iconName]
        }
    } catch {
        Write-Host "Failed to load icon '$iconName'. Error: $_"
        return $null
    }
}

function Update-UI {
    param([bool]$IsConnected)
    
    $DisconnectButton.IsEnabled = $IsConnected
    $QueryButton.IsEnabled = $IsConnected
    $SecureButton.IsEnabled = $IsConnected
    
    if ($IsConnected) {
        $ConnectButton.Content = "Connected"
        $ProgressBar.Value = 100
        $ProgressTextBlock.Text = "Connected"
    } else {
        $ConnectButton.Content = "Connect"
        $ConnectButton.IsEnabled = $true
        $ProgressBar.Value = 0
        $ProgressTextBlock.Text = "Not Connected"
    }
    
    $ProgressBar.Visibility = "Visible"
    $ProgressTextBlock.Visibility = "Visible"
}

function Update-ToggleSwitches {
    param (
        [System.Windows.Controls.CheckBox]$ChangedSwitch
    )
    
    $switches = @($LockDownWForensicsToggleSwitch, $ForensicsOnlyToggleSwitch, $LockdownOnlyToggleSwitch)
    
    # If a switch other than LockDownWForensics is being enabled
    if ($ChangedSwitch -ne $LockDownWForensicsToggleSwitch -and $ChangedSwitch.IsChecked) {
        # First uncheck LockDownWForensics
        $LockDownWForensicsToggleSwitch.IsChecked = $false
    }
    
    # If any switch is being checked, uncheck all others
    if ($ChangedSwitch.IsChecked) {
        $switches | Where-Object { $_ -ne $ChangedSwitch } | ForEach-Object {
            $_.IsChecked = $false
        }
    }
}

function Set-ToggleSwitchHandlers {
    $LockDownWForensicsToggleSwitch.Add_Checked({ Update-ToggleSwitches -ChangedSwitch $LockDownWForensicsToggleSwitch })
    $LockDownWForensicsToggleSwitch.Add_Unchecked({ Update-ToggleSwitches -ChangedSwitch $LockDownWForensicsToggleSwitch })

    $ForensicsOnlyToggleSwitch.Add_Checked({ Update-ToggleSwitches -ChangedSwitch $ForensicsOnlyToggleSwitch })
    $ForensicsOnlyToggleSwitch.Add_Unchecked({ Update-ToggleSwitches -ChangedSwitch $ForensicsOnlyToggleSwitch })

    $LockdownOnlyToggleSwitch.Add_Checked({ Update-ToggleSwitches -ChangedSwitch $LockdownOnlyToggleSwitch })
    $LockdownOnlyToggleSwitch.Add_Unchecked({ Update-ToggleSwitches -ChangedSwitch $LockdownOnlyToggleSwitch })
}

$script:UpdateToggleSwitchStyle = {
    param($toggleSwitch, $isDarkMode)
    $toggleSwitchTemplate = $toggleSwitch.Template
    if ($null -ne $toggleSwitchTemplate) {
        $border = $toggleSwitchTemplate.FindName("Border", $toggleSwitch)
        if ($null -ne $border) {
            if ($toggleSwitch.IsChecked) {
                $border.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#09ca44')
            } else {
                $border.Background = if ($isDarkMode) { [System.Windows.Media.Brushes]::DarkGray } else { [System.Windows.Media.Brushes]::LightGray }
            }
        }
    }
}

function PopulateAboutTextBox {
    param (
        [System.Windows.Controls.TextBox]$AboutTextBox,
        [System.Windows.Window]$AboutWindow
    )

    try {
        
        if ($null -eq $AboutTextBox) {
            throw "AboutTextBox is null"
        }

        $aboutText = @"
  This tool is designed for use during the Incident Response (IR) process and automates the following critical tasks:

 - Sets up the environment and connects to all three M365 services.
 - Enables auditing for the specified user.
 - Resets the password for the user.
 - Revokes all active session tokens for the user.
 - Exports forensic data, including mailbox configuration details for the user.
 - Extracts a 10-day message trace log for the user.
 - Retrieves a 30-day audit log for the user.
 - Converts the audit log into a format optimized for creating pivot tables.

  Notes:

  All actions are logged, and results are saved in the 'FSIR\output' folder.
"@

        # Show the window immediately
        $AboutWindow.Show()

        
        $script:typingCancellationTokenSource = New-Object System.Threading.CancellationTokenSource
        $typingCancellationToken = $script:typingCancellationTokenSource.Token

        $typingScriptBlock = {
            param($AboutTextBox, $aboutText, $typingCancellationToken)

            $AboutTextBox.Dispatcher.Invoke([action] {
                $AboutTextBox.Text = ""
                foreach ($line in $aboutText -split "`n") {
                    foreach ($char in $line.ToCharArray()) {
                        if ($typingCancellationToken.IsCancellationRequested) {
                            return
                        }
                        $AboutTextBox.AppendText($char)
                        $AboutTextBox.ScrollToEnd()
                        [System.Windows.Forms.Application]::DoEvents()
                        Start-Sleep -Milliseconds 10
                    }
                    if ($typingCancellationToken.IsCancellationRequested) {
                        return
                    }
                    $AboutTextBox.AppendText("`n")
                    $AboutTextBox.ScrollToEnd()
                }
            })
        }

        $typingPowerShell = [powershell]::Create().AddScript($typingScriptBlock)
        $typingPowerShell.AddArgument($AboutTextBox)
        $typingPowerShell.AddArgument($aboutText)
        $typingPowerShell.AddArgument($typingCancellationToken)

        $typingTask = $typingPowerShell.BeginInvoke()

    }
    catch {
        $errorMessage = "Error in PopulateAboutTextBox: $_`nStack Trace:`n$($_.ScriptStackTrace)"
        Write-Host $errorMessage
    }
}

function TypeOutputBoxMessage {
    param (
        [System.Windows.Controls.TextBox]$OutputBox,
        [string]$Message
    )

    try {
        if ($null -eq $OutputBox) {
            throw "OutputBox is null"
        }

        $script:typingIndex = 0
        $script:typingMessage = $Message

        $script:typingTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:typingTimer.Interval = [TimeSpan]::FromMilliseconds(15)
        $script:typingTimer.Add_Tick({
            if ($script:typingIndex -lt $script:typingMessage.Length) {
                $OutputBox.AppendText($script:typingMessage[$script:typingIndex])
                $OutputBox.ScrollToEnd()
                $script:typingIndex++
            } else {
                $script:typingTimer.Stop()
            }
        })
        $script:typingTimer.Start()
    }
    catch {
        $errorMessage = "Error in TypeOutputBoxMessage: $_`nStack Trace:`n$($_.ScriptStackTrace)"
        Write-Host $errorMessage
    }
}

$script:MDAPViewModel = New-Object PSObject -Property @{
    TargetUPN = ""
    MDAPLabelColor = [System.Windows.Media.Brushes]::Black
}

# Add a script method to update the TargetUPN
$script:MDAPViewModel | Add-Member -MemberType ScriptMethod -Name UpdateTargetUPN -Value {
    param($newValue)
    $this.TargetUPN = $newValue
    # Raise property changed event if you're implementing INotifyPropertyChanged
}

function Write-AuditLog {
    param ([string]$Message)
    $auditLogWindow.Dispatcher.Invoke([Action]{
        $auditLogTextBox.AppendText("$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message`r`n")
        $auditLogTextBox.ScrollToEnd()
    })
}

function Set-ButtonHoverStyle {
    param ([System.Windows.Controls.Button]$Button)
    $Button.Style = $Button.FindResource("CommonButtonStyle")
  
    # Define the hover color
    $hoverBackground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#09ca44')
    $originalBackground = $Button.Background
  
        # Attach mouse enter event (hover over)
    $Button.AddHandler([System.Windows.Input.MouseEventArgs]::MouseEnterEvent, {
        param ($senderObj, $eventArgsObj)
        $Button.Background = $hoverBackground
    })

    # Attach mouse leave event (hover out)
    $Button.AddHandler([System.Windows.Input.MouseEventArgs]::MouseLeaveEvent, {
        param ($senderObj, $eventArgsObj)
        $Button.Background = $originalBackground
    })
}
#endregion


#region Connection Functions
function Clear-AllM365Connections {
    try {
        $cleanupTasks = @(
            @{
                Name = 'Microsoft Graph'
                Action = {
                    Disconnect-MgGraph -ErrorAction SilentlyContinue
                    [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthContext.TokenCache.Clear()
                }
            },
            @{
                Name = 'Exchange Online'
                Action = {
                    Get-PSSession | Where-Object { 
                        $_.ConfigurationName -eq "Microsoft.Exchange" -or 
                        $_.ComputerName -like "*.outlook.com" 
                    } | Remove-PSSession -ErrorAction SilentlyContinue
                }
            },
            @{
                Name = 'Azure AD'
                Action = {
                    Disconnect-AzureAD -ErrorAction SilentlyContinue
                }
            }
        )

        # Run cleanup tasks in parallel
        $jobs = $cleanupTasks | ForEach-Object {
            $task = $_
            Start-Job -ScriptBlock { 
                param($Action)
                & $Action
            } -ArgumentList $task.Action
        }

        # Wait for all jobs to complete with timeout
        $null = Wait-Job -Job $jobs -Timeout 30
        Remove-Job -Job $jobs -Force

        # Force garbage collection
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        return $true
    }
    catch {
        Write-Error "Error clearing connections: $_"
        return $false
    }
}

function Update-UIState {
    param(
        [System.Windows.Controls.TextBox]$OutputBox,
        [System.Windows.Controls.ProgressBar]$ProgressBar,
        [System.Windows.Controls.TextBlock]$ProgressTextBlock,
        [string]$Message,
        [int]$Progress,
        [bool]$IsError = $false
    )

    if ($null -eq $OutputBox -or $null -eq $ProgressBar -or $null -eq $ProgressTextBlock) {
        return
    }

    $ProgressBar.Dispatcher.Invoke([action] {
        $ProgressBar.Value = $Progress
        $ProgressBar.IsIndeterminate = $Progress -eq 0

        $ProgressTextBlock.Inlines.Clear()
        $boldText = New-Object System.Windows.Documents.Run
        $boldText.Text = $Message
        $boldText.FontWeight = [System.Windows.FontWeights]::Bold
        $ProgressTextBlock.Inlines.Add($boldText)
        $ProgressTextBlock.Foreground = if ($IsError) { [System.Windows.Media.Brushes]::Green } else { [System.Windows.Media.Brushes]::Black }
    }, [System.Windows.Threading.DispatcherPriority]::Send)
}

function Update-ButtonStates {
    param(
        [System.Windows.Controls.Button]$ConnectButton,
        [System.Windows.Controls.Button]$QueryButton,
        [System.Windows.Controls.Button]$SecureButton,
        [System.Windows.Controls.Button]$DisconnectButton,
        [bool]$IsConnected
    )

    $ConnectButton.Dispatcher.Invoke([action] {
        $ConnectButton.Content = if ($IsConnected) { "Connected" } else { "Connect" }
        $ConnectButton.IsEnabled = -not $IsConnected
        $ConnectButton.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
        $ConnectButton.Foreground = [System.Windows.Media.Brushes]::White

        @($QueryButton, $SecureButton, $DisconnectButton) | ForEach-Object {
            $_.IsEnabled = $IsConnected
            $_.Opacity = if ($IsConnected) { 1 } else { 0.5 }
            $_.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
            $_.Foreground = [System.Windows.Media.Brushes]::White
            if ($IsConnected) {
                $_.Style = $_.FindResource("PressableButtonStyle")
            }
        }
    }, [System.Windows.Threading.DispatcherPriority]::Send)
}

function Show-TenantInfo {
    param(
        [System.Windows.Controls.TextBox]$OutputBox,
        $TenantInfo,
        $AADConfig
    )

    $OutputBox.Dispatcher.Invoke([action] {
        $OutputBox.Clear()
        $outputText = @"
Tenant Details:
• Display Name: $($TenantInfo.DisplayName)
  ◦ Tenant ID: $($TenantInfo.Id)
  ◦ Domain Name: $($TenantInfo.VerifiedDomains[0].Name)
  ◦ Country: $($TenantInfo.CountryLetterCode)
  ◦ Technical Contact: $($TenantInfo.TechnicalNotificationMails -join ', ')
  ◦ Created Date: $($TenantInfo.CreatedDateTime)

Azure AD Configuration:
• Default User Role Permissions:
  ◦ Allow User Create Apps: $($AADConfig.DefaultUserRolePermissions.AllowedToCreateApps)
  ◦ Allow User Create Security Groups: $($AADConfig.DefaultUserRolePermissions.AllowedToCreateSecurityGroups)
  ◦ Allow User Read Other Users: $($AADConfig.DefaultUserRolePermissions.AllowedToReadOtherUsers)
"@
        $OutputBox.AppendText($outputText)

        # Check AD Sync status
        if ($TenantInfo.OnPremisesSyncEnabled) {
            $syncText = @"

• Azure AD Connect Status:
  ◦ Sync Enabled: True
  ◦ Last Sync Time: $($TenantInfo.OnPremisesLastSyncDateTime)
"@
            $OutputBox.AppendText($syncText)

            # Show warning popup
            [System.Windows.MessageBox]::Show(
                "Warning: Directory synchronization is enabled for this tenant. You must disable the user account in the local Active Directory and AzureAD immediately to prevent unauthorized access.",
                "Directory Sync Warning",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning
            )
        }
        else {
            $OutputBox.AppendText("`n• Azure AD Connect Status:`n  ◦ Sync Enabled: False")
        }
    }, [System.Windows.Threading.DispatcherPriority]::Send)
}

function Connect-ServicesAsync2 {
    param (
        [System.Windows.Controls.TextBox]$OutputBox,
        [System.Windows.Controls.Button]$QueryButton,
        [System.Windows.Controls.Button]$SecureButton,
        [System.Windows.Controls.Button]$DisconnectButton,
        [System.Windows.Controls.Button]$ConnectButton,
        [System.Windows.Controls.ProgressBar]$ProgressBar,
        [System.Windows.Controls.TextBlock]$ProgressTextBlock
    )

    $script:isConnecting = $true
    
    # Force stop the welcome timer and clear its reference
    if ($null -ne $script:welcomeTypingTimer) {
        $OutputBox.Dispatcher.Invoke([action] {
            $script:welcomeTypingTimer.Stop()
            $script:welcomeTypingTimer = $null
            $OutputBox.Clear()
        }, [System.Windows.Threading.DispatcherPriority]::Send)
    }


    $OutputBox.Dispatcher.Invoke([action] {
        $OutputBox.Clear()
    })

    Start-Sleep -Milliseconds 100

    $originalBackground = $ConnectButton.Background
    $originalContent = $ConnectButton.Content
        
    $ProgressBar.Dispatcher.Invoke([action] {
        $ProgressBar.Visibility = 'Visible'
        $ProgressBar.IsIndeterminate = $true
        $ProgressTextBlock.Visibility = 'Visible'
        $ProgressTextBlock.Inlines.Clear()
        $boldText = New-Object System.Windows.Documents.Run
        $boldText.Text = "Invoking Authentication..."
        $boldText.FontWeight = [System.Windows.FontWeights]::Bold
        $ProgressTextBlock.Inlines.Add($boldText)
        $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
    })
    
    $writeOutputBox = {
        param([string]$text)
        $OutputBox.Dispatcher.Invoke([action] {
            $OutputBox.AppendText("$text`r`n")
        })
    }

    $TerminateMenuItem.Dispatcher.Invoke([Action]{
        $TerminateMenuItem.IsEnabled = $true
        $TerminateMenuItem.Visibility = 'Visible' # Make sure it's visible too
    })

    #TypeOutputBoxMessage -OutputBox $OutputBox -Message "                                  Processing authentication request, Please wait...`r`n"    
    #Start-Sleep -Milliseconds 1300
    $runspace = [powershell]::Create().AddScript({
        param (
            $OutputBox, $QueryButton, $SecureButton, $DisconnectButton, $ConnectButton, 
            $ProgressBar, $ProgressTextBlock, $originalBackground, $originalContent, 
            $writeOutputBox
        )
        $checkmark = [char]0x221A
        function TypeOutputBoxMessage {
            param (
                [System.Windows.Controls.TextBox]$OutputBox,
                [string]$Message
            )
        
            try {
                if ($null -eq $OutputBox) {
                    throw "OutputBox is null"
                }
        
                $script:typingIndex = 0
                $script:typingMessage = $Message
                
                $script:typingTimer = New-Object System.Windows.Threading.DispatcherTimer
                $script:typingTimer.Interval = [TimeSpan]::FromMilliseconds(15)
                $script:typingTimer.Add_Tick({
                    if ($script:typingIndex -lt $script:typingMessage.Length) {
                        $OutputBox.AppendText($script:typingMessage[$script:typingIndex])
                        $OutputBox.ScrollToEnd()
                        $script:typingIndex++
                    } else {
                        $script:typingTimer.Stop()
                    }
                })
                $script:typingTimer.Start()
            }
            catch {
                $errorMessage = "Error in TypeOutputBoxMessage: $_`nStack Trace:`n$($_.ScriptStackTrace)"
                Write-Host $errorMessage
            }
        }

        function HandleAuthError {
            param ([string]$errorMessage)
            & $writeOutputBox $errorMessage
            
            # Check if the error is due to cancellation
            $isCancelled = $errorMessage -like "*cancelled*" -or $errorMessage -like "*canceled*"
            
            $ProgressTextBlock.Dispatcher.Invoke([action] { 
                $ProgressTextBlock.Inlines.Clear()
                $boldText = New-Object System.Windows.Documents.Run
                $boldText.Text = if ($isCancelled) { "Authentication cancelled" } else { "Connection Failed" }
                $boldText.FontWeight = [System.Windows.FontWeights]::Bold
                $ProgressTextBlock.Inlines.Add($boldText)
                $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
            })
            
            # Reset progress bar
            $ProgressBar.Dispatcher.Invoke([action] {
                $ProgressBar.IsIndeterminate = $false
                $ProgressBar.Value = 0
            })
            
            # Reset Connect button
            $ConnectButton.Dispatcher.Invoke([action] { 
                $ConnectButton.Content = "Connect"
                $ConnectButton.IsEnabled = $true
                $ConnectButton.Style = $ConnectButton.FindResource("PressableButtonStyle")
                $ConnectButton.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
                $ConnectButton.Foreground = [System.Windows.Media.Brushes]::White
            })
        }
    
        function Invoke-WithRetry {
            param (
                [ScriptBlock]$ScriptBlock,
                [int]$MaxAttempts = 5,
                [int]$InitialDelay = 1,
                [int]$MaxDelay = 30,
                [string]$Operation = "Operation" # Add operation name parameter
            )
        
            $attempt = 1
            $delay = $InitialDelay
            $lastError = $null
        
            while ($attempt -le $MaxAttempts) {
                try {
                    return & $ScriptBlock
                }
                catch {
                    $lastError = $_
                    if ($attempt -eq $MaxAttempts) {
                        throw "Failed to complete $Operation after $MaxAttempts attempts. Last error: $($lastError.Exception.Message)"
                    }
                    
                    # Don't clear previous messages
                    & $writeOutputBox "`r`nAttempt $attempt of $MaxAttempts for $Operation failed."
                    & $writeOutputBox "Error: $($lastError.Exception.Message)"
                    & $writeOutputBox "Retrying in $delay seconds...`r`n"
                    
                    Start-Sleep -Seconds $delay
                    $attempt++
                    $delay = [Math]::Min($delay * 2, $MaxDelay)
                }
            }
        }
        try {

            $TerminateMenuItem.Dispatcher.Invoke([Action]{
                $TerminateMenuItem.IsEnabled = $true
                $TerminateMenuItem.Visibility = 'Visible' # Make sure it's visible too
            })
            
            # Force cleanup of any existing Graph sessions
            [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthContext.TokenCache.Clear()
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            
            # Clear any existing Exchange sessions
            Get-PSSession | Where-Object { 
                $_.ConfigurationName -eq "Microsoft.Exchange" -or 
                $_.ComputerName -like "*.outlook.com" 
            } | Remove-PSSession -ErrorAction SilentlyContinue
            
            # Clear Azure AD sessions
            Disconnect-AzureAD -ErrorAction SilentlyContinue
            
            # Force garbage collection
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        catch {
            # Silent cleanup - continue even if errors occur
        }
        try {
            # Initialize connection progress
            $totalServices = 3
            $currentService = 0

            # Check Exchange Online connection
            $currentService++
            $progress = [math]::Round(($currentService / $totalServices) * 33)
            $ProgressBar.Dispatcher.Invoke([action] {
                $ProgressBar.IsIndeterminate = $false
                $ProgressBar.Value = $progress
            })
            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressBar.Visibility = 'Visible'
                $ProgressBar.IsIndeterminate = $true  # This creates the animated effect
                $ProgressTextBlock.Visibility = 'Visible'            
                $ProgressTextBlock.Inlines.Clear()
                $boldText = New-Object System.Windows.Documents.Run
                $boldText.Text = "Connecting to Exchange Online..."
                $boldText.FontWeight = [System.Windows.FontWeights]::Bold
                $ProgressTextBlock.Inlines.Add($boldText)
                $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
            })

            try {
                $serviceName = "Exchange Online"
            
                $exchangeSession = Get-PSSession | Where-Object {$_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened"}
                
                if ($null -eq $exchangeSession) {
                    $exchangeParams = @{
                        ShowBanner = $false
                        UseMultithreading = $true
                    }
                    #& $writeOutputBox "  $([char]0x25E6) Connecting to $serviceName..." -NoNewline
                    # Redirect the output to $null to prevent console writing
                    $OutputBox.Dispatcher.Invoke([action] {
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                        $OutputBox.AppendText("`r`n`n`n`n  $([char]0x25E6) Connecting to $serviceName...")
                    })
                    Connect-ExchangeOnline @exchangeParams | Out-Null
                    
                    $OutputBox.Dispatcher.Invoke([action] {
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                        $OutputBox.AppendText("...Connected! $checkmark`r`n")
                    })
                } else {
                    $OutputBox.Dispatcher.Invoke([action] {
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                        $OutputBox.AppendText("...Connected! $checkmark`r`n")
                    })
                }
            }
            catch {
                $OutputBox.Dispatcher.Invoke([action] {
                    $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                    $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                    $OutputBox.AppendText("...Failed! ❌`r`n")
                })
                throw
            }

            # Check Azure AD connection
            $currentService++
            $progress = [math]::Round(($currentService / $totalServices) * 66)
            $ProgressBar.Dispatcher.Invoke([action] {
                $ProgressBar.Value = $progress
            })
            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressTextBlock.Inlines.Clear()
                $boldText = New-Object System.Windows.Documents.Run
                $boldText.Text = "Connecting to Azure AD..."
                $boldText.FontWeight = [System.Windows.FontWeights]::Bold
                $ProgressTextBlock.Inlines.Add($boldText)
            })


            try {
                $serviceName = "Azure AD"
            
                try {
                    $null = Get-AzureADTenantDetail -ErrorAction Stop
                    $OutputBox.Dispatcher.Invoke([action] {
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                        $OutputBox.AppendText("`r`n  $([char]0x25E6) Connected to $serviceName! $checkmark`r`n")
                    })
                } catch {
                    $OutputBox.Dispatcher.Invoke([action] {
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                        $OutputBox.AppendText("`r`n  $([char]0x25E6) Connecting to $serviceName...")
                    })
                    Connect-AzureAD | Out-Null
                    
                    $OutputBox.Dispatcher.Invoke([action] {
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                        $OutputBox.AppendText("...Connected! $checkmark`r`n")
                    })
                }
            }
            catch {
                $OutputBox.Dispatcher.Invoke([action] {
                    $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                    $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                    $OutputBox.AppendText("...Failed! ❌`r`n")
                })
                throw
            }
            
            # Check Microsoft Graph connection
            $currentService++
            $progress = [math]::Round(($currentService / $totalServices) * 100)
            $ProgressBar.Dispatcher.Invoke([action] {
                $ProgressBar.Value = $progress
            })
            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressTextBlock.Inlines.Clear()
                $boldText = New-Object System.Windows.Documents.Run
                $boldText.Text = "Connecting to Microsoft Graph..."
                $boldText.FontWeight = [System.Windows.FontWeights]::Bold
                $ProgressTextBlock.Inlines.Add($boldText)
            })

            try {
                $serviceName = "Microsoft Graph"
            
                try {
                    $context = Get-MgContext
                    if ($null -eq $context) {
                        throw "No existing Graph connection"
                    }
                    $OutputBox.Dispatcher.Invoke([action] {
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                        $OutputBox.AppendText("`r`n  $([char]0x25E6) Connected to $serviceName! $checkmark`r`n")
                    })
                } catch {
                    $OutputBox.Dispatcher.Invoke([action] {
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                        $OutputBox.AppendText("`r`n  $([char]0x25E6) Connecting to $serviceName...")
                    })
                    
                    Connect-MgGraph -Scopes @(
                        "User.ReadWrite.All",
                        "Directory.ReadWrite.All", 
                        "User.Read.All",
                        "Organization.Read.All",
                        "Policy.Read.All",
                        "Mail.Read",
                        "Mail.Read.Shared",
                        "Mail.ReadWrite",
                        "Mail.ReadWrite.Shared",
                        "Auditlog.Read.All",
                        "UserAuthenticationMethod.Read.All",
                        "MailboxSettings.Read",
                        "MailboxSettings.ReadWrite",
                        "Device.Read.All",
                        "Device.ReadWrite.All"
                    ) | Out-Null
                    
                    $OutputBox.Dispatcher.Invoke([action] {
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                        $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                        $OutputBox.AppendText("...Connected! $checkmark`r`n")
                    })
                }
            }
            catch {
                $OutputBox.Dispatcher.Invoke([action] {
                    $OutputBox.Text = $OutputBox.Text.TrimEnd(".")
                    $OutputBox.Text = $OutputBox.Text.TrimEnd(" ")
                    $OutputBox.AppendText("...Failed! ❌`r`n")
                })
                throw
            }

            $ProgressBar.Dispatcher.Invoke([action] {
                $ProgressBar.IsIndeterminate = $false
                $ProgressBar.Value = "$progress"  
            })

            # Show completion message
            #TypeOutputBoxMessage -OutputBox $OutputBox -Message "                               Successfully connected to all required services!"
            #Start-Sleep -Milliseconds 1450

            $OutputBox.Dispatcher.Invoke([action] { $OutputBox.Clear() })
            & $writeOutputBox "                                  Collecting tenant configuration details..."

           
            # Update ProgressBar and ProgressTextBlock for each step
            $steps = @(
                "Collecting Tenant Configuration Details...",
                "Collecting AzureAD Configuration Details..."
            )
            $totalSteps = $steps.Count
            $currentStep = 0
        
            foreach ($step in $steps) {
                $currentStep++
                $progress = [math]::Round(($currentStep / $totalSteps) * 100)
                $ProgressBar.Dispatcher.Invoke([action] {
                    $ProgressBar.IsIndeterminate = $true
                    $ProgressBar.Value = $progress
                })
                $ProgressTextBlock.Dispatcher.Invoke([action] {
                    $ProgressTextBlock.Inlines.Clear()
                    $boldText = New-Object System.Windows.Documents.Run
                    $boldText.Text = $step
                    $boldText.FontWeight = [System.Windows.FontWeights]::Bold
                    $ProgressTextBlock.Inlines.Add($boldText)
                    $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
                })
        
                switch ($step) {
                    "Collecting Tenant Configuration Details..." {
                        $tenantInfo = Invoke-WithRetry -ScriptBlock { Get-MgOrganization } -Operation "Get Tenant Info"
                    }
                    "Collecting AzureAD Configuration Details..." {
                        $aadConfig = Invoke-WithRetry { Get-MgPolicyAuthorizationPolicy }
                    }
                }
            }
        
            # Final update to ProgressBar and ProgressTextBlock
            $ProgressBar.Dispatcher.Invoke([action] {
                $ProgressBar.Value = 100
            })
            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressTextBlock.Inlines.Clear()
                $boldText = New-Object System.Windows.Documents.Run
                $boldText.Text = "Connected to M365"
                $boldText.FontWeight = [System.Windows.FontWeights]::Bold
                $ProgressTextBlock.Inlines.Add($boldText)
                $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
            })
            Start-Sleep -Milliseconds 1300
            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressTextBlock.Inlines.Clear()
                $boldText = New-Object System.Windows.Documents.Run
                $boldText.Text = "Ready for action!"
                $boldText.FontWeight = [System.Windows.FontWeights]::Bold
                $ProgressTextBlock.Inlines.Add($boldText)
                $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::White
            })
            $progress = [math]::Round(($currentStep / $totalSteps) * 100)
                $ProgressBar.Dispatcher.Invoke([action] {
                    $ProgressBar.IsIndeterminate = $false
                    $ProgressBar.Value = $progress
                })
            # Enable buttons and update ConnectButton
            $global:IsAuthenticated = $true
            $ConnectButton.Dispatcher.Invoke([action] {
                $ConnectButton.Content = "Connected"
                $ConnectButton.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#6d6d6d')
                $ConnectButton.Foreground = [System.Windows.Media.Brushes]::White
                $ConnectButton.IsEnabled = $false
            })
            
            $buttonsToUpdate = @($QueryButton, $SecureButton, $DisconnectButton)
            foreach ($button in $buttonsToUpdate) {
                $button.Dispatcher.Invoke([action] { 
                    $button.IsEnabled = $true 
                    $button.Opacity = 1
                    $button.Style = $button.FindResource("PressableButtonStyle")
                    $button.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#6d6d6d')
                    $button.Foreground = [System.Windows.Media.Brushes]::White
                })
            }
            
            # Display tenant information
            $OutputBox.Dispatcher.Invoke([action] { $OutputBox.Clear() })
            & $writeOutputBox "`nTenant Details:"
            & $writeOutputBox "$([char]0x2022) Display Name: $($tenantInfo.DisplayName)"
            & $writeOutputBox "  $([char]0x25E6) Tenant ID: $($tenantInfo.Id)"
            & $writeOutputBox "  $([char]0x25E6) Domain Name: $($tenantInfo.VerifiedDomains[0].Name)"
            & $writeOutputBox "  $([char]0x25E6) Country: $($tenantInfo.CountryLetterCode)"
            & $writeOutputBox "  $([char]0x25E6) Technical Contact: $($tenantInfo.TechnicalNotificationMails -join ', ')"
            & $writeOutputBox "  $([char]0x25E6) Created Date: $($tenantInfo.CreatedDateTime)"
            & $writeOutputBox "`rAzure AD Configuration:"
            & $writeOutputBox "$([char]0x2022) Default User Role Permissions:"
            & $writeOutputBox "  $([char]0x25E6) Allow User Create Apps: $($aadConfig.DefaultUserRolePermissions.AllowedToCreateApps)"
            & $writeOutputBox "  $([char]0x25E6) Allow User Create Security Groups: $($aadConfig.DefaultUserRolePermissions.AllowedToCreateSecurityGroups)"
            & $writeOutputBox "  $([char]0x25E6) Allow User Read Other Users: $($aadConfig.DefaultUserRolePermissions.AllowedToReadOtherUsers)"

            try {
                $orgInfo = Get-MgOrganization
                $syncEnabled = $orgInfo.OnPremisesSyncEnabled
                
                & $writeOutputBox "`r$([char]0x2022) Azure AD Connect Status:"
                & $writeOutputBox "  $([char]0x25E6) Sync Enabled: $(if ($syncEnabled) { 'True' } else { 'False' })"
                
                if ($syncEnabled) {
                    $lastSyncTime = $orgInfo.OnPremisesLastSyncDateTime
                    if ($lastSyncTime) {
                        & $writeOutputBox "  $([char]0x25E6) Last Sync Time: $($lastSyncTime)"
                    } else {
                        & $writeOutputBox "  $([char]0x25E6) Last Sync Time: Not Available"
                    }

                    # Show warning popup for sync enabled
                    $OutputBox.Dispatcher.Invoke([action] {
                        $messageBoxText = "Warning: Directory synchronization is enabled for this tenant. You must disable the user account in the local Active Directory and AzureAD immediately to prevent unauthorized access."
                        $caption = "Directory Sync Warning"
                        $button = [System.Windows.MessageBoxButton]::OK
                        $icon = [System.Windows.MessageBoxImage]::Warning
                        [System.Windows.MessageBox]::Show($messageBoxText, $caption, $button, $icon)
                    })
                }
            } catch {
                & $writeOutputBox "  $([char]0x25E6) Unable to determine AD Sync status: $($_.Exception.Message)"
            }
            
            #& $writeOutputBox "`r`nExchange Online Configuration:"
            #& $writeOutputBox "  $([char]0x2022) Auto Expand Archive: $($exchangeConfig.AutoExpandingArchive)"
            #& $writeOutputBox "  $([char]0x2022) DKIM Enabled: $($exchangeConfig.DkimSigningConfigurationEnabled)"
            #& $writeOutputBox "  $([char]0x2022) Modern Authentication Enabled: $($exchangeConfig.OAuth2ClientProfileEnabled)"

        } catch {
            HandleAuthError "`r`n`nFailed to connect to services: $_"
            $global:IsAuthenticated = $false
            $ConnectButton.Dispatcher.Invoke([action] {
                $ConnectButton.Content = "Connect"
                $ConnectButton.Background = $originalBackground
                $ConnectButton.IsEnabled = $true
            })
        }
    }).AddArgument($OutputBox).AddArgument($QueryButton).AddArgument($SecureButton).AddArgument($DisconnectButton).AddArgument($ConnectButton).AddArgument($ProgressBar).AddArgument($ProgressTextBlock).AddArgument($originalBackground).AddArgument($originalContent).AddArgument($writeOutputBox)
    
    $runspace.RunspacePool = $global:RunspacePool
    $runspace.BeginInvoke()
}

function Disconnect-AllSessions {
    param(
        [System.Windows.Controls.TextBox]$OutputBox,
        [System.Windows.Controls.Button]$ConnectButton,
        [System.Windows.Controls.Button]$QueryButton,
        [System.Windows.Controls.Button]$SecureButton,
        [System.Windows.Controls.Button]$DisconnectButton,
        [System.Windows.Controls.Button]$ExitButton,
        [System.Windows.Controls.ProgressBar]$ProgressBar,
        [System.Windows.Controls.TextBlock]$ProgressTextBlock
    )

    # Clear output box through dispatcher
    $OutputBox.Dispatcher.Invoke([action] { 
        $OutputBox.Clear()
        
        # Disable buttons through dispatcher
        $ConnectButton.IsEnabled = $false
        $QueryButton.IsEnabled = $false
        $SecureButton.IsEnabled = $false
        $DisconnectButton.IsEnabled = $false
        $ExitButton.IsEnabled = $false
    })
    
    $ProgressBar.Dispatcher.Invoke([action] {
        $ProgressBar.Visibility = 'Visible'
        $ProgressBar.IsIndeterminate = $true
        $ProgressTextBlock.Visibility = 'Visible'
    
        # Create a new Run with bold text
        $boldText = New-Object System.Windows.Documents.Run
        $boldText.Text = "Disconnecting from M365..."
        $boldText.FontWeight = [System.Windows.FontWeights]::Bold
    
        # Clear existing inlines and add the new bold text
        $ProgressTextBlock.Inlines.Clear()
        $ProgressTextBlock.Inlines.Add($boldText)
    
        $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
    })

    $writeOutputBox = {
        param([string]$text)
        $OutputBox.Dispatcher.Invoke([action] {
            $OutputBox.AppendText("$text`r`n")
            $OutputBox.ScrollToEnd()
        })
    }

    $runspace = [powershell]::Create().AddScript({
        param ($OutputBox, $ConnectButton, $QueryButton, $SecureButton, $DisconnectButton, $ExitButton, $ProgressBar, $ProgressTextBlock, $writeOutputBox)
    
        try {
            # Clear Microsoft Graph token cache and sessions
        [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthContext.TokenCache.Clear()
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        
        # Remove all Exchange Online sessions
        Get-PSSession | Where-Object {
            $_.ConfigurationName -eq "Microsoft.Exchange" -or 
            $_.ComputerName -like "*.outlook.com"
        } | Remove-PSSession -ErrorAction SilentlyContinue
        
        # Clear Azure AD connections
        try {
            Disconnect-AzureAD -ErrorAction SilentlyContinue
        } catch { }
        
        # Force cleanup of resources
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        
        # Clear any module-specific caches
        $modules = @(
            'Microsoft.Graph.Authentication',
            'ExchangeOnlineManagement',
            'AzureAD'
        )
        foreach ($module in $modules) {
            Remove-Module -Name $module -Force -ErrorAction SilentlyContinue
        }
    
            # Final success message
            TypeOutputBoxMessage -OutputBox $OutputBox -Message "                             All active sessions have been terminated successfully."
        }
        catch {
            # Existing error handling...
        }
        finally {
            # Update UI elements through dispatcher
            $OutputBox.Dispatcher.Invoke([action] {
                # Update progress bar and text
                $ProgressBar.IsIndeterminate = $false
                $ProgressBar.Value = 100
                
                $boldText = New-Object System.Windows.Documents.Run
                $boldText.Text = "Disconnected"
                $boldText.FontWeight = [System.Windows.FontWeights]::Bold
                
                $ProgressTextBlock.Inlines.Clear()
                $ProgressTextBlock.Inlines.Add($boldText)
                $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
    
                # Reset all button states in a single dispatcher call
                $ConnectButton.Content = "Connect"
                $ConnectButton.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
                $ConnectButton.Foreground = [System.Windows.Media.Brushes]::White
                $ConnectButton.IsEnabled = $true
    
                @($QueryButton, $SecureButton, $DisconnectButton) | ForEach-Object {
                    $_.IsEnabled = $false
                    $_.Opacity = 0.5
                    $_.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
                }
    
                $ExitButton.IsEnabled = $true
                $ExitButton.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
            })
    
            # Clean up
            [System.GC]::Collect()
        }
    }).AddArgument($OutputBox).AddArgument($ConnectButton).AddArgument($QueryButton).AddArgument($SecureButton).AddArgument($DisconnectButton).AddArgument($ExitButton).AddArgument($ProgressBar).AddArgument($ProgressTextBlock).AddArgument($writeOutputBox)
    
    $runspace.RunspacePool = $global:RunspacePool
    $runspace.BeginInvoke()
}

function Reset-Connections {
    # Disconnect existing sessions
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Disconnect-AzureAD -ErrorAction SilentlyContinue
        
        # Remove any existing Exchange Online sessions
        Get-PSSession | Where-Object {
            $_.ConfigurationName -eq "Microsoft.Exchange" -or 
            $_.ComputerName -like "*.outlook.com"
        } | Remove-PSSession
        
        # Clear connection variables
        [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens.Clear()
        [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokenCache.Clear()
    }
    catch {
        Write-Warning "Error during connection reset: $_"
    }
}

function Clear-Runspaces {
    if ($script:currentRemediationRunspace) {
        try {
            $script:currentRemediationRunspace.Stop()
            $script:currentRemediationRunspace.Dispose()
        }
        catch { }
        $script:currentRemediationRunspace = $null
    }
}

function Stop-AllConnections1 {
    param (
        [System.Windows.Controls.TextBox]$OutputBox,
        [System.Windows.Controls.Button]$ConnectButton,
        [System.Windows.Controls.Button]$QueryButton,
        [System.Windows.Controls.Button]$SecureButton,
        [System.Windows.Controls.Button]$DisconnectButton
    )
    
    # Clear output and disable buttons through dispatcher
    $OutputBox.Dispatcher.Invoke([action] { 
        $OutputBox.Clear()
        
        # Disable buttons through dispatcher
        $ConnectButton.IsEnabled = $false
        $QueryButton.IsEnabled = $false
        $SecureButton.IsEnabled = $false
        $DisconnectButton.IsEnabled = $false
    })

    TypeOutputBoxMessage -OutputBox $OutputBox -Message ("                                 Terminating all active connections...")

    $writeOutputBox = {
        param([string]$text)
        $OutputBox.Dispatcher.Invoke([action] {
            $OutputBox.AppendText("$text`r`n")
            $OutputBox.ScrollToEnd()
        })
    }
    
    #TypeOutputBoxMessage -OutputBox $OutputBox -Message "Terminating all active connections..."

    #& $writeOutputBox "Terminating all active connections..."
    try {
        # Terminate Microsoft Graph connections
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            #& $writeOutputBox "√ Microsoft Graph connections terminated"
        } catch {
            & $writeOutputBox "Failed to terminate Microsoft Graph connections: $_"
        }
        
        # Terminate Exchange Online sessions
        try {
            Get-PSSession | Where-Object {
                $_.ConfigurationName -eq "Microsoft.Exchange" -or 
                $_.ComputerName -like "*.outlook.com"
            } | Remove-PSSession -ErrorAction SilentlyContinue
            #& $writeOutputBox "Exchange Online sessions terminated"
        } catch {
            & $writeOutputBox "Failed to terminate Exchange Online sessions: $_"
        }
        
        # Terminate Azure AD connections
        try {
            $null = Disconnect-AzureAD
            #& $writeOutputBox "Azure AD connections terminated"
        } catch {
            #& $writeOutputBox "Failed to terminate Azure AD connections: $_"
        }
        
        # Clear any remaining sessions
        try {
            Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
            #& $writeOutputBox "All remaining sessions terminated"
        } catch {
            & $writeOutputBox "Failed to terminate remaining sessions: $_"
        }
        
        TypeOutputBoxMessage -OutputBox $OutputBox -Message "                                        All connections have been terminated successfully."
        
        # Update UI elements through dispatcher
        $OutputBox.Dispatcher.Invoke([action] {
            # Reset Connect button
            $ConnectButton.Content = "Connect"
            $ConnectButton.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
            $ConnectButton.Foreground = [System.Windows.Media.Brushes]::White
            $ConnectButton.IsEnabled = $true
            $ConnectButton.Style = $ConnectButton.FindResource("PressableButtonStyle")
            $ConnectButton.BorderThickness = New-Object System.Windows.Thickness(1)
            $ConnectButton.BorderBrush = [System.Windows.Media.Brushes]::DarkGray

            # Update other buttons
            @($QueryButton, $SecureButton, $DisconnectButton) | ForEach-Object {
                $_.IsEnabled = $false
                $_.Opacity = 0.5
                $_.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
                $_.Style = $_.FindResource("PressableButtonStyle")
                $_.BorderThickness = New-Object System.Windows.Thickness(1)
                $_.BorderBrush = [System.Windows.Media.Brushes]::DarkGray
            }
        })
        
    } catch {
        & $writeOutputBox "Error terminating connections: $_"
        & $writeOutputBox "Stack Trace: $($_.ScriptStackTrace)"
    }
}

function Stop-AllConnections {
    param (
        [System.Windows.Controls.TextBox]$OutputBox,
        [System.Windows.Controls.Button]$ConnectButton,
        [System.Windows.Controls.Button]$QueryButton,
        [System.Windows.Controls.Button]$SecureButton,
        [System.Windows.Controls.Button]$DisconnectButton
    )
    
    # Clear output and disable buttons through dispatcher
    $OutputBox.Dispatcher.Invoke([action] { 
        $OutputBox.Clear()
        
        # Disable buttons during disconnection
        $ConnectButton.IsEnabled = $false
        $QueryButton.IsEnabled = $false
        $SecureButton.IsEnabled = $false
        $DisconnectButton.IsEnabled = $false
    })
    
    try {
        # Show initial message
        $message = "Terminating all active connections..."
        $totalWidth = 100
        $padding = [Math]::Max(0, ($totalWidth - $message.Length) / 2)
        TypeOutputBoxMessage -OutputBox $OutputBox -Message ($message.PadLeft($message.Length + $padding).PadRight($totalWidth))
        
        Start-Sleep -Seconds 1

        # Silently terminate Microsoft Graph connection
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        } catch {}

        # Silently terminate Exchange Online sessions
        try {
            Get-PSSession | Where-Object {
                $_.ConfigurationName -eq "Microsoft.Exchange" -or 
                $_.ComputerName -like "*.outlook.com"
            } | Remove-PSSession -ErrorAction SilentlyContinue | Out-Null
        } catch {}

        # Silently terminate Azure AD connection
        try {
            Disconnect-AzureAD -ErrorAction SilentlyContinue | Out-Null
        } catch {}

        # Clear any remaining sessions
        try {
            Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue | Out-Null
        } catch {}

        # Clear any stored credentials or tokens
        try {
            Clear-Variable -Name "*token*" -Scope Script -ErrorAction SilentlyContinue
            [System.GC]::Collect()
        } catch {}

        Start-Sleep -Seconds 1

        # Show success message
        $message = "All connections have been terminated successfully."
        $padding = [Math]::Max(0, ($totalWidth - $message.Length) / 2)
        TypeOutputBoxMessage -OutputBox $OutputBox -Message ($message.PadLeft($message.Length + $padding).PadRight($totalWidth))

        # Reset global connection state
        $global:IsConnected = $false

        # Update UI elements through dispatcher
        $OutputBox.Dispatcher.Invoke([action] {
            # Reset Connect button
            $ConnectButton.Content = "Connect"
            $ConnectButton.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
            $ConnectButton.Foreground = [System.Windows.Media.Brushes]::White
            $ConnectButton.IsEnabled = $true
            $ConnectButton.Style = $ConnectButton.FindResource("PressableButtonStyle")
            $ConnectButton.BorderThickness = New-Object System.Windows.Thickness(1)
            $ConnectButton.BorderBrush = [System.Windows.Media.Brushes]::DarkGray

            # Update other buttons
            @($QueryButton, $SecureButton, $DisconnectButton) | ForEach-Object {
                $_.IsEnabled = $false
                $_.Opacity = 0.5
                $_.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
                $_.Style = $_.FindResource("PressableButtonStyle")
                $_.BorderThickness = New-Object System.Windows.Thickness(1)
                $_.BorderBrush = [System.Windows.Media.Brushes]::DarkGray
            }
        })
        
    } catch {
        # If any unexpected error occurs, log it silently and ensure buttons are re-enabled
        $OutputBox.Dispatcher.Invoke([action] {
            $ConnectButton.IsEnabled = $true
            $global:IsConnected = $false
        })
    }
}

function Test-ShouldContinueRemediation {
    # Check if abort was requested
    if ($script:abortRemediation) {
        Write-Host "Abort requested, stopping remediation..."
        return $false
    }

    # Check if cancellation was requested
    if ($script:remediationCancellationSource.Token.IsCancellationRequested) {
        Write-Host "Cancellation requested, stopping remediation..."
        return $false
    }

    return $true
}
#endregion

#region Window Config Functions
function Set-MutuallyExclusiveToggles {
  param (
      [System.Windows.Controls.Primitives.ToggleButton]$clickedToggle
  )
  
  $toggleSwitches = @($LockDownWForensicsToggleSwitch, $ForensicsOnlyToggleSwitch, $LockdownOnlyToggleSwitch)
  
  foreach ($toggle in $toggleSwitches) {
      if ($toggle -ne $clickedToggle) {
          $toggle.IsChecked = $false
      }
  }
}

function Set-DarkMode {
    param (
        [bool]$IsDarkMode
    )
    
    $script:IsDarkMode = $IsDarkMode
    
    $window.Dispatcher.Invoke([Action]{
        $toggleSwitches = @($LockDownWForensicsToggleSwitch, $ForensicsOnlyToggleSwitch, $LockdownOnlyToggleSwitch)
        $buttons = @($ConnectButton, $QueryButton, $SecureButton, $DisconnectButton, $ExitButton)
        $labelNames = @('LockdownWForensicsLabel', 'ForensicsOnlyLabel', 'LockdownOnlyLabel', 'RemediationModeLabel', 'upnLabel', 'PWResetLabel')
        
        # Set window and OutputBox colors
        $window.Background = if ($IsDarkMode) { [System.Windows.Media.Brushes]::Black } else { [System.Windows.Media.Brushes]::White }
        $window.Foreground = if ($IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
        $OutputBox.Background = if ($IsDarkMode) { [System.Windows.Media.Brushes]::Black } else { [System.Windows.Media.Brushes]::White }
        $OutputBox.Foreground = if ($IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
        
        $modeImage = $window.FindName("ModeImage")
        if ($null -ne $modeImage) {
            $imageUrl = if ($IsDarkMode) {
                "https://advancestuff.hostedrmm.com/share/Transfer/installers/easyjob/darka.png"
            } else {
                "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/redA.png"
            }
            $modeImage.Source = Get-ImageFromUrl $imageUrl
        }
    
        # Update AuditLogWindow if it's open
        if ($null -ne $script:AuditLogWindow -and $script:AuditLogWindow.IsLoaded) {
            Update-AuditLogWindowTheme
        }

        # Set TargetUPN colors
        if ($null -ne $TargetUPN) {
            $TargetUPN.Background = if ($IsDarkMode) { [System.Windows.Media.Brushes]::Black } else { [System.Windows.Media.Brushes]::White }
            $TargetUPN.Foreground = if ($IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
        }
        
        # Set label colors
        foreach ($labelName in $labelNames) {
            $label = $window.FindName($labelName)
            if ($null -ne $label) {
                $label.Foreground = if ($IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
            }
        }
        
        # Update button styles
        foreach ($button in $buttons) {
            if ($null -ne $button) {
                if ($button.IsEnabled) {
                    $button.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#6d6d6d')
                    $button.Foreground = [System.Windows.Media.Brushes]::White
                } else {
                    $button.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#d3d3d3')
                    $button.Foreground = [System.Windows.Media.Brushes]::Gray
                }
            }
        }

        foreach ($toggleSwitch in $toggleSwitches) {
            $toggleSwitch.Add_Checked({
                param($senderObj, $e)
                & $script:UpdateToggleSwitchStyle $senderObj $script:IsDarkMode
            })
            $toggleSwitch.Add_Unchecked({
                param($senderObj, $e)
                & $script:UpdateToggleSwitchStyle $senderObj $script:IsDarkMode
            })
            & $script:UpdateToggleSwitchStyle $toggleSwitch $IsDarkMode
        }
        
        function Global:UpdateToggleSwitchStyle {
            param($toggleSwitch, $isDarkMode)
            $toggleSwitchTemplate = $toggleSwitch.Template
            if ($null -ne $toggleSwitchTemplate) {
                $border = $toggleSwitchTemplate.FindName("Border", $toggleSwitch)
                if ($null -ne $border) {
                    if ($toggleSwitch.IsChecked) {
                        $border.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#09ca44')
                    } else {
                        $border.Background = if ($isDarkMode) { [System.Windows.Media.Brushes]::DarkGray } else { [System.Windows.Media.Brushes]::LightGray }
                    }
                }
            }
        }
        
        # Set toggle switch styles
        foreach ($toggleSwitch in $toggleSwitches) {
            $toggleSwitchTemplate = $toggleSwitch.Template
            if ($null -ne $toggleSwitchTemplate) {
                $knob = $toggleSwitchTemplate.FindName("Knob", $toggleSwitch)
                if ($null -ne $knob) {
                    $knob.Fill = if ($IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
                }
                $border = $toggleSwitchTemplate.FindName("Border", $toggleSwitch)
                if ($null -ne $border) {
                    if ($toggleSwitch.IsChecked) {
                        $border.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#09ca44')
                    } else {
                        $border.Background = if ($IsDarkMode) { [System.Windows.Media.Brushes]::DarkGray } else { [System.Windows.Media.Brushes]::LightGray }
                    }
                }
            }
        }

        # Update the DarkModeMenuItem
        $DarkModeMenuItem = $window.FindName("DarkModeMenuItem")
        if ($null -ne $DarkModeMenuItem) {
            $DarkModeMenuItem.Header = if ($IsDarkMode) { "Switch to Light Mode" } else { "Switch to Dark Mode" }
            
            $iconPath = if ($IsDarkMode) { "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/light.ico" } else { "https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/dark2.ico" }
            $icon = Get-ImageFromUrl $iconPath
            if ($null -ne $icon) {
                $image = New-Object System.Windows.Controls.Image
                $image.Source = $icon
                $image.Width = 16
                $image.Height = 16
                $DarkModeMenuItem.Icon = $image
            }
        }
        
        # Update Mobile Device Admin Panel if it's open
        if ($null -ne $script:mdapWindow -and $script:mdapWindow.IsLoaded) {
            Update-MDAPTheme
        }

        # Update About window if it's open
        if ($null -ne $script:aboutWindow -and $script:aboutWindow.IsLoaded) {
            Update-AboutWindowTheme
        }

        # Update ProgressBar and ProgressTextBlock colors
        $ProgressBar = $window.FindName("ProgressBar")
        $ProgressTextBlock = $window.FindName("ProgressTextBlock")
        if ($null -ne $ProgressBar) {
            $ProgressBar.Background = if ($IsDarkMode) { [System.Windows.Media.Brushes]::DarkGray } else { [System.Windows.Media.Brushes]::LightGray }
        }
        if ($null -ne $ProgressTextBlock) {
            $ProgressTextBlock.Foreground = if ($IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
        }

        # Update Mobile Device Admin Panel if it's open
        if ($null -ne $script:mdapWindow -and $script:mdapWindow.IsLoaded) {
            Update-MDAPTheme
        }

        # Update About window if it's open
        if ($null -ne $script:aboutWindow -and $script:aboutWindow.IsLoaded) {
            Update-AboutWindowTheme
        }

        # Save the dark mode preference
        $prefPath = Join-Path $env:APPDATA "M365BreachRemediationToolkit"
        if (-not (Test-Path $prefPath)) {
            New-Item -ItemType Directory -Path $prefPath -Force | Out-Null
        }
        $prefFile = Join-Path $prefPath "darkmode.pref"
        $IsDarkMode.ToString() | Out-File -FilePath $prefFile -Force
    })
}

function Update-MDAPTheme {
    if ($null -ne $script:mdapWindow -and $script:mdapWindow.IsLoaded) {
        $script:mdapWindow.Background = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::Black } else { [System.Windows.Media.Brushes]::White }
        $script:mdapWindow.Foreground = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }

        $mdapControls = @(
            @{Name="MobileDeviceAdminPanel"; Property="Foreground"},
            @{Name="TargetUPNTextBox"; Property="Foreground"},
            @{Name="TargetUPNTextBox"; Property="Background"},
            @{Name="GetDeviceDetailsButton"; Property="Foreground"},
            @{Name="GetDeviceDetailsButton"; Property="Background"},
            @{Name="EnableDeviceButton"; Property="Foreground"},
            @{Name="EnableDeviceButton"; Property="Background"},
            @{Name="DeviceListView"; Property="Background"},
            @{Name="DeviceListView"; Property="Foreground"},
            @{Name="AccountStatusLabel"; Property="Foreground"},
            @{Name="MDAPLabel"; Property="Foreground"}
        )

        foreach ($control in $mdapControls) {
            $element = $script:mdapWindow.FindName($control.Name)
            if ($null -ne $element) {
                if ($control.Name -eq "MobileDeviceAdminPanel" -or $control.Name -eq "AccountStatusLabel" -or $control.Name -eq "MDAPLabel") {
                    $element.Foreground = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
                }
                elseif ($control.Property -eq "Background") {
                    $element.$($control.Property) = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::Black } else { [System.Windows.Media.Brushes]::White }
                } 
                elseif ($control.Property -eq "Foreground") {
                    $element.$($control.Property) = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
                }
            }
        }

        # Handle the AccountStatusText and Enable button
        $accountStatusText = $script:mdapWindow.FindName("AccountStatusText")
        if ($null -ne $accountStatusText) {
            $accountStatusText.FontWeight = [System.Windows.FontWeights]::Bold
            
            switch ($accountStatusText.Text) {
                "Enabled" {
                    $accountStatusText.Foreground = [System.Windows.Media.Brushes]::Green
                    Remove-EnableButton
                }
                "Disabled" {
                    $accountStatusText.Foreground = [System.Windows.Media.Brushes]::Green
                    Add-EnableButton
                }
                default {
                    $accountStatusText.Foreground = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
                    Remove-EnableButton
                }
            }
        }

        # Handle the 'AboutA' image
        $aboutAImage = $script:mdapWindow.FindName("AboutA")
        if ($null -ne $aboutAImage) {
            $imageSource = if ($script:IsDarkMode) {
                "https://advancestuff.hostedrmm.com/share/Transfer/installers/easyjob/darka.png"
            } else {
                "https://advancestuff.hostedrmm.com/share/Transfer/installers/easyjob/redA.png"
            }
            $aboutAImage.Source = New-Object System.Windows.Media.Imaging.BitmapImage(New-Object Uri($imageSource))
        }
    }
}

function Add-EnableButton {
    $existingButton = $script:mdapWindow.FindName("EnableAccountButton")
    if ($existingButton -eq $null) {
        $enableButton = New-Object System.Windows.Controls.Button
        $enableButton.Name = "EnableAccountButton"
        $enableButton.Content = "Enable"
        $enableButton.Width = 80
        $enableButton.Height = 25
        $enableButton.Margin = New-Object System.Windows.Thickness(10, 0, 0, 0)
        $enableButton.VerticalAlignment = "Center"
        $enableButton.Add_Click({
            Enable-Account
        })

        $accountStatusText = $script:mdapWindow.FindName("AccountStatusText")
        $parentPanel = $accountStatusText.Parent

        if ($parentPanel -is [System.Windows.Controls.StackPanel]) {
            $parentPanel.Children.Add($enableButton)
        } else {
            $newPanel = New-Object System.Windows.Controls.StackPanel
            $newPanel.Orientation = "Horizontal"
            $parentPanel.Children.Remove($accountStatusText)
            $newPanel.Children.Add($accountStatusText)
            $newPanel.Children.Add($enableButton)
            $parentPanel.Children.Add($newPanel)
        }
    }
}

function Remove-EnableButton {
    $enableButton = $script:mdapWindow.FindName("EnableAccountButton")
    if ($null -ne $enableButton) {
        $parentPanel = $enableButton.Parent
        $parentPanel.Children.Remove($enableButton)
    }
}

function Enable-Account {
    $upn = $script:mdapWindow.FindName("TargetUPNTextBox").Text
    try {
        Update-MgUser -UserId $upn -AccountEnabled $true
        $accountStatusText = $script:mdapWindow.FindName("AccountStatusText")
        $accountStatusText.Text = "Enabled"
        Update-MDAPTheme
        [System.Windows.MessageBox]::Show("Account enabled successfully.", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    } catch {
        [System.Windows.MessageBox]::Show("Failed to enable account: $_", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Update-AboutWindowTheme {
    if ($script:aboutWindow -ne $null) {
        # Set window background and foreground
        $script:aboutWindow.Background = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::Black } else { [System.Windows.Media.Brushes]::White }
        $script:aboutWindow.Foreground = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }

        # Text controls with improved contrast
        $textColor = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
        $aboutControls = @(
            @{Name="AboutTextBox"; Property="Foreground"},
            @{Name="VersionTextBlock"; Property="Foreground"},
            @{Name="CopyrightTextBlock"; Property="Foreground"}
        )

        foreach ($control in $aboutControls) {
            $element = $script:aboutWindow.FindName($control.Name)
            if ($null -ne $element) {
                $element.$($control.Property) = $textColor
            }
        }

        # Style the AboutTextBox background for better readability
        $aboutTextBox = $script:aboutWindow.FindName("AboutTextBox")
        if ($null -ne $aboutTextBox) {
            $aboutTextBox.Background = if ($script:IsDarkMode) { 
                [System.Windows.Media.Brushes]::Transparent 
            } else { 
                [System.Windows.Media.Brushes]::Transparent 
            }
        }

        # Style the close button
        $closeButton = $script:aboutWindow.FindName("AboutClose")
        if ($null -ne $closeButton) {
            $closeButton.Background = if ($script:IsDarkMode) { 
                [System.Windows.Media.Brushes]::DarkGray 
            } else { 
                [System.Windows.Media.Brushes]::LightGray 
            }
            $closeButton.Foreground = if ($script:IsDarkMode) { 
                [System.Windows.Media.Brushes]::White 
            } else { 
                [System.Windows.Media.Brushes]::Black 
            }
        }
    }
}

function Get-DarkModePreference {
  $prefPath = Join-Path $env:APPDATA "M365BreachRemediationToolkit"
  $prefFile = Join-Path $prefPath "darkmode.pref"
  if (Test-Path $prefFile) {
      $pref = Get-Content $prefFile -Raw
      return [System.Convert]::ToBoolean($pref)
  }
  return $false  # Default to light mode if no preference is saved
}

function Get-MenuIcons {
    try {
        Write-Host "Starting Get-MenuIcons function..."
        $iconUrls.GetEnumerator() | ForEach-Object {
            $menuItemName = "$($_.Key)MenuItem"
            $menuItem = $window.FindName($menuItemName)
            if ($null -ne $menuItem) {
                $imageName = "$($_.Key)MenuItemIcon"
                $image = $window.FindName($imageName)
                if ($null -ne $image) {
                    Write-Host "Loading icon for $menuItemName (image: $imageName)"
                    $image.Source = Get-IconImage $_.Key
                    
                    if ($null -ne $image.Source) {
                        Write-Host "Icon loaded successfully for $menuItemName"
                    } else {
                        Write-Host "Failed to load icon for $menuItemName"
                    }
                } else {
                    Write-Host "Image not found: $imageName"
                }
            } else {
                Write-Host "Menu item not found: $menuItemName"
            }
        }
        Write-Host "Completed Get-MenuIcons function."
    } catch {
        Write-Host "Error loading menu icons: $_"
        Write-Host "Stack Trace: $($_.ScriptStackTrace)"
    }
}

function Update-AuditLogWindowTheme {
        if ($script:AuditLogWindow -ne $null -and $script:AuditLogWindow.IsLoaded) {
        $script:AuditLogWindow.Background = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::Black } else { [System.Windows.Media.Brushes]::White }
        $script:AuditLogWindow.Foreground = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }

        # Update specific controls
        $controls = @(
            @{Name="ExchAuditToolLabel"; Property="Foreground"},
            @{Name="ExportAuditLogLabel"; Property="Foreground"},
            @{Name="upnLabel"; Property="Foreground"},
            @{Name="TargetUPN"; Property="Background"},
            @{Name="TargetUPN"; Property="Foreground"},
            @{Name="AuditLogTextBox"; Property="Background"},
            @{Name="AuditLogTextBox"; Property="Foreground"},
            @{Name="ProgressStatusText"; Property="Foreground"}
        )

        foreach ($control in $controls) {
            $element = $script:AuditLogWindow.FindName($control.Name)
            if ($null -ne $element) {
                if ($control.Property -eq "Background") {
                    $element.$($control.Property) = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::Black } else { [System.Windows.Media.Brushes]::White }
                } elseif ($control.Property -eq "Foreground") {
                    $element.$($control.Property) = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
                }
            }
        }

        # Update buttons
        $buttons = @("ExportLogsButton", "ExitButton")
        foreach ($buttonName in $buttons) {
            $button = $script:AuditLogWindow.FindName($buttonName)
            if ($button -ne $null) {
                $button.Background = if ($script:IsDarkMode) { [System.Windows.Media.BrushConverter]::new().ConvertFrom('#6d6d6d') } else { [System.Windows.Media.Brushes]::LightGray }
                $button.Foreground = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
            }
        }

        # Update ProgressBar
        $progressBar = $script:AuditLogWindow.FindName("ExportProgressBar")
        if ($progressBar -ne $null) {
            $progressBar.Background = if ($script:IsDarkMode) { [System.Windows.Media.Brushes]::DarkGray } else { [System.Windows.Media.Brushes]::LightGray }
        }
    }
}

function UpdateAccountStatus {
    param([bool]$enabled)
    
    $upn = $targetUPNTextBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($upn)) {
        [System.Windows.MessageBox]::Show("Please enter a valid UPN.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return
    }

    try {
        Update-MgUser -UserId $upn -AccountEnabled $enabled
        $accountStatusText.Text = if ($enabled) { "Enabled" } else { "Disabled" }
        [System.Windows.MessageBox]::Show("Account status updated successfully.", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    }
    catch {
        Write-Host "Error updating account status: $_"
        [System.Windows.MessageBox]::Show("Error updating account status: $_", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        #$accountStatusToggle.IsChecked = !$enabled  # Revert the toggle if update fails
    }
}

function Export-SecurityAuditLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$UPN,
        [string]$LogPath = ".\output\forensics\$UPN",
        [int]$DaysBack = 30
    )

    Begin {
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'

        function Write-Log {
            param([string]$Message)
            Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
        }

        function Connect-ToExchangeOnline {
            if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
                throw "ExchangeOnlineManagement module is not installed."
            }
            Import-Module ExchangeOnlineManagement
            Connect-ExchangeOnline -ShowBanner:$false
        }
    }

    Process {
        try {
            Write-Log "Job started for UPN: $UPN"
            Connect-ToExchangeOnline
            
            $startDate = (Get-Date).AddDays(-$DaysBack)
            $endDate = Get-Date
            $userFolder = Join-Path $LogPath $UPN
            $outputFile = Join-Path $userFolder "$UPN-AuditLog-Last$($DaysBack)Days.csv"

            if (-not (Test-Path $userFolder)) {
                New-Item -Path $userFolder -ItemType Directory -Force | Out-Null
                Write-Log "Created user folder: $userFolder"
            }

            Write-Log "Starting audit log export for user: $UPN"
            Write-Log "Date range: $startDate to $endDate"

            $sessionId = [guid]::NewGuid().ToString()
            $resultSize = 5000
            $allResults = @()
            $page = 1

            do {
                Write-Log "Exporting audit log for user: $UPN (Page $page)"
                $results = Search-UnifiedAuditLog -UserIds $UPN -StartDate $startDate -EndDate $endDate `
                    -SessionId $sessionId -SessionCommand ReturnLargeSet -ResultSize $resultSize

                if ($null -eq $results -or $results.Count -eq 0) {
                    Write-Log "No results returned for this page. Ending search."
                    break
                }

                $allResults += $results
                $page++
                Start-Sleep -Milliseconds 500
            } while ($results.Count -eq $resultSize)

            $allResults | Export-Csv -Path $outputFile -NoTypeInformation

            Write-Log "Audit log export complete for user: $UPN"
            Write-Log "Total records exported: $($allResults.Count)"
            Write-Log "Output file: $outputFile"

            return $allResults
        }
        catch {
            Write-Error "Error in job: $_"
            Write-Error "Stack Trace: $($_.ScriptStackTrace)"
            throw
        }
        finally {
            Write-Log "Attempting to disconnect from Exchange Online..."
            try {
                Disconnect-ExchangeOnline -Confirm:$false
                Write-Log "Disconnected from Exchange Online successfully."
            }
            catch {
                Write-Error "Error disconnecting from Exchange Online: $_"
            }
        }
    }
}

function Export-AuditLog {
    param ([int]$DaysBack = 30)
    
    $StartDate = (Get-Date).AddDays(-$DaysBack)
    $EndDate = Get-Date
    $forensicsFolder = ".\output\Forensics\$UPN"
    $UserFolder = Join-Path $ForensicsFolder $UPN

    Write-JobLog "Starting audit log export for user: $UPN" -Category "Export"
    Write-JobLog "Date range: $StartDate to $EndDate" -Category "Export"

    if (-not (Test-Path $UserFolder)) {
        New-Item -Path $UserFolder -ItemType Directory -Force | Out-Null
        Write-JobLog "Created user folder: $UserFolder" -Category "Export"
    }

    $SessionId = [guid]::NewGuid().ToString()
    $ResultSize = 5000
    $AllResults = @()
    $Page = 1

    do {
        Write-JobLog "Exporting audit log for user: $UPN (Page $Page)" -Category "Export"
        $Results = Search-UnifiedAuditLog -UserIds $UPN -StartDate $StartDate -EndDate $EndDate -SessionId $SessionId -SessionCommand ReturnLargeSet -ResultSize $ResultSize
        
        if ($null -eq $Results) {
            Write-JobLog "No results returned for this page. Ending search." -Category "Export"
            break
        }

        $AllResults += $Results
        $Page++
        Start-Sleep -Seconds 2
    } while ($Results.Count -eq $ResultSize)

    $OutputFile = Join-Path $UserFolder "$UPN-AuditLog-Last$($DaysBack)Days.csv"
    $AllResults | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-JobLog "Audit log export complete for user: $UPN" -Category "Export"
    Write-JobLog "Total records exported: $($AllResults.Count)" -Category "Export"
    Write-JobLog "Output file: $OutputFile" -Category "Export"

    return $AllResults
}

function Test-ShouldContinueRemediation {
    try {
        # Check if there's a current remediation runspace
        if ($null -eq $script:currentRemediationRunspace) {
            return $true
        }

        # Check the state of the runspace
        $state = $script:currentRemediationRunspace.InvocationStateInfo.State
        
        # If the runspace is stopped, return false to abort
        if ($state -eq 'Stopped') {
            Write-Host "Remediation abort detected - Runspace state is Stopped"
            return $false
        }

        # Check if abort flag is set
        if ($script:abortRemediation -eq $true) {
            Write-Host "Remediation abort flag detected"
            return $false
        }

        return $true
    }
    catch {
        Write-Host "Error in Test-ShouldContinueRemediation: $_"
        # On error, return false to safely abort
        return $false
    }
}

function Open-AuditLogWindow {
    $reader = (New-Object System.Xml.XmlNodeReader ([xml]$exportAuditLogXaml))
    $script:AuditLogWindow = [Windows.Markup.XamlReader]::Load($reader)
    
    $script:AuditLogWindow.Add_Loaded({
        #$LockDownWForensicsToggleSwitch.IsChecked = $true
        #$ForensicsOnlyToggleSwitch.IsChecked = $false
        #$LockdownOnlyToggleSwitch.IsChecked = $false
        Update-AuditLogWindowTheme
    })

    # Set up event handlers for the new window
    $exportLogsButton = $auditLogWindow.FindName('ExportLogsButton')
    $exitButton = $auditLogWindow.FindName('ExitButton')
    $progressBar = $auditLogWindow.FindName('ExportProgressBar')
    $progressStatusText = $auditLogWindow.FindName('ProgressStatusText')
    $targetUPN = $auditLogWindow.FindName('TargetUPN')
    $auditLogTextBox = $auditLogWindow.FindName('AuditLogTextBox')

    # Declare variables at the function level
    $script:job = $null
    $script:jobCompleted = $false
    $timer = $null
    $lastStatus = @{}
    
    function Write-AuditLog {
        param ([string]$Message, [string]$Category = "General")
        
        $auditLogWindow.Dispatcher.Invoke([Action]{
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            
            if ($lastStatus[$Category] -ne $Message) {
                $auditLogTextBox.AppendText("$timestamp - $Message`r`n")
                $auditLogTextBox.ScrollToEnd()
                $lastStatus[$Category] = $Message
            }
        })
    }

    function Update-ProgressBar {
        param ([int]$Value)
        $auditLogWindow.Dispatcher.Invoke([Action]{
            $progressBar.Value = $Value
            $progressStatusText.Text = "$Value% Complete"
        })
    }

    function Stop-TimerSafely {
        if ($null -ne $timer -and $timer.IsEnabled) {
            $auditLogWindow.Dispatcher.Invoke([Action]{ $timer.Stop() })
        }
    }

    function Start-AuditLogExport {
        param ($UPN, $LogPath)
        
        $script:job = Start-Job -ScriptBlock {
            param($UPN, $LogPath)

            $moduleImported = $false

            function Write-JobLog {
                param ([string]$Message, [string]$Category = "General")
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                "$timestamp - $Message" | Out-File -FilePath ".\output\Forensics\$UPN\AuditLogExport.log" -Append
                Write-Output @{Message = $Message; Category = $Category; Timestamp = $timestamp}
            }

            function Export-AuditLog {
                param ([int]$DaysBack = 30)
                
                $StartDate = (Get-Date).AddDays(-$DaysBack)
                $EndDate = Get-Date
                $ForensicsFolder = ".\output\Forensics\"
                $UserFolder = Join-Path $ForensicsFolder $UPN

                Write-JobLog "Starting audit log export for user: $UPN" -Category "Export"
                Write-JobLog "Date range: $StartDate to $EndDate" -Category "Export"

                if (-not (Test-Path $UserFolder)) {
                    New-Item -Path $UserFolder -ItemType Directory -Force | Out-Null
                    Write-JobLog "Created user folder: $UserFolder" -Category "Export"
                }

                $SessionId = [guid]::NewGuid().ToString()
                $ResultSize = 5000
                $AllResults = @()
                $Page = 1

                do {
                    Write-JobLog "Exporting audit log for user: $UPN (Page $Page)" -Category "Export"
                    $Results = Search-UnifiedAuditLog -UserIds $UPN -StartDate $StartDate -EndDate $EndDate -SessionId $SessionId -SessionCommand ReturnLargeSet -ResultSize $ResultSize
                    
                    if ($null -eq $Results) {
                        Write-JobLog "No results returned for this page. Ending search." -Category "Export"
                        break
                    }

                    $AllResults += $Results
                    $Page++
                    Start-Sleep -Seconds 2
                } while ($Results.Count -eq $ResultSize)

                $OutputFile = Join-Path $UserFolder "$UPN-ManualAuditLog-Last$($DaysBack)Days.csv"
                $AllResults | Export-Csv -Path $OutputFile -NoTypeInformation
                Write-JobLog "Audit log export complete for user: $UPN" -Category "Export"
                Write-JobLog "Total records exported: $($AllResults.Count)" -Category "Export"
                Write-JobLog "Output file: $OutputFile" -Category "Export"

                return $AllResults
            }
                #Write-JobLog "Attempting to connect to Exchange Online..." -Category "Connection"
            try {
                #Write-JobLog "Job started for UPN: $UPN" -Category "Job"
                
                if (-not $moduleImported) {
                    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
                        throw "ExchangeOnlineManagement module is not installed."
                    }

                    #Write-JobLog "Importing ExchangeOnlineManagement module..." -Category "Module"
                    Import-Module ExchangeOnlineManagement -ErrorAction Stop
                    #Write-JobLog "ExchangeOnlineManagement module imported successfully." -Category "Module"
                    $moduleImported = $true
                }

                
                Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
                Write-JobLog "Connected to Exchange Online successfully." -Category "Connection"
                
                Write-JobLog "Starting audit log export..." -Category "Export"
                $results = Export-AuditLog
                Write-JobLog "Audit log export completed successfully." -Category "Export"

                #return $results
            }
            catch {
                Write-JobLog "Error in job: $_" -Category "Error"
                Write-JobLog "Stack Trace: $($_.ScriptStackTrace)" -Category "Error"
                throw
            }
            finally {
                #Write-JobLog "Attempting to disconnect from Exchange Online..." -Category "Connection"
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
                    Write-JobLog "Disconnected from Exchange Online successfully." -Category "Connection"
                }
                catch {
                    Write-JobLog "Error disconnecting from Exchange Online: $_" -Category "Error"
                }
            }
        } -ArgumentList $UPN, $LogPath
    }

    function Start-IndeterminateProgress {
        $auditLogWindow.Dispatcher.Invoke([Action]{
            $progressBar.IsIndeterminate = $true
            $progressBar.Foreground = [System.Windows.Media.Brushes]::Crimson
            $progressStatusText.Text = "Collecting Audit Logs..."
            $progressStatusText.FontWeight = 'Bold'
            $progressStatusText.Foreground = [System.Windows.Media.Brushes]::Black
        })
    }
    
    function Update-ProgressBar {
        param (
            [int]$Value,
            [string]$StatusText,
            [bool]$IsBold = $false,
            [bool]$IsIndeterminate = $true
        )
        $auditLogWindow.Dispatcher.Invoke([Action]{
            $progressBar.Value = $Value
            $progressBar.IsIndeterminate = $IsIndeterminate
            $progressStatusText.Text = $StatusText
            $progressStatusText.FontWeight = if ($IsBold) { 'Bold' } else { 'Normal' }
            $progressStatusText.Foreground = [System.Windows.Media.Brushes]::Black
        })
    }
    
    $exportLogsButton.Add_Click({
        $UPN = $targetUPN.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($UPN)) {
            [System.Windows.MessageBox]::Show("Please enter a valid UPN.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            return
        }
    
        Write-AuditLog "Initializing audit log export for $UPN" -Category "Job"
        $targetUPN.IsEnabled = $false
        $exportLogsButton.IsEnabled = $false
        
        # Start with indeterminate progress and centered text
        Start-IndeterminateProgress
        Update-ProgressBar -Value 0 -StatusText "Collecting Audit Logs..." -IsBold $true -IsIndeterminate $true
    
        try {
            #Write-AuditLog "Starting background job..." -Category "Job"
            Start-AuditLogExport -UPN $UPN -LogPath ".\output\forensics\$UPN"
    
            if ($null -eq $script:job) {
                throw "Job creation failed: Start-Job returned null"
            }
            #Write-AuditLog "Background job started successfully. Job ID: $($script:job.Id)" -Category "Job"
    
            $timer = New-Object System.Windows.Threading.DispatcherTimer
            $timer.Interval = [TimeSpan]::FromSeconds(1)
            $timer.Add_Tick({
                try {
                    if ($script:jobCompleted) {
                        Stop-TimerSafely
                        return
                    }
    
                    if ($null -eq $script:job) {
                        Write-AuditLog "Job is null. Stopping timer." -Category "Job"
                        Stop-TimerSafely
                        $script:jobCompleted = $true
                        Update-ProgressBar -Value 100 -StatusText "Export Complete!" -IsBold $true -IsIndeterminate $false
                        $targetUPN.IsEnabled = $true
                        $exportLogsButton.IsEnabled = $true
                        return
                    }
    
                    $jobState = $script:job.State
                    Write-AuditLog "Connecting to Exchange Online..."
    
                    switch ($jobState) {
                        'Running' {
                            $jobInfo = Receive-Job -Job $script:job -Keep
                            if ($jobInfo) {
                                $processedCategories = @{}
                                foreach ($info in $jobInfo) {
                                    if ($info -is [hashtable]) {
                                        $category = $info.Category
                                        $message = $info.Message
                                        $timestamp = $info.Timestamp
    
                                        if (-not $processedCategories.ContainsKey($category) -or 
                                            $processedCategories[$category] -ne $message) {
                                            Write-AuditLog $message -Category $category
                                            $processedCategories[$category] = $message
                                        }
                                    } else {
                                        Write-AuditLog $info -Category "General"
                                    }
                                }
                                
                                # Keep the indeterminate progress while running
                                Start-IndeterminateProgress
                            }
                        }
                        'Completed' {
                            Stop-TimerSafely
                            $script:jobCompleted = $true
                            Update-ProgressBar -Value 100 -StatusText "Export Complete!" -IsBold $true -IsIndeterminate $false
                            $targetUPN.IsEnabled = $true
                            $exportLogsButton.IsEnabled = $true

                            $results = Receive-Job -Job $script:job

                            if ($results -and $results -is [array]) {
                                # Uncomment if you want to display results
                                 Write-AuditLog "Export Results:" -Category "Results"
                                 Write-AuditLog ($results | Format-Table | Out-String) -Category "Results"
                            }
    
                            Remove-Job -Job $script:job
                            $script:job = $null
                            Write-AuditLog "Job completed and removed." -Category "Job"
                        }
                        'Failed' {
                            Stop-TimerSafely
                            $script:jobCompleted = $true
                            Update-ProgressBar -Value 0 -StatusText "Export Failed!"
                            $targetUPN.IsEnabled = $true
                            $exportLogsButton.IsEnabled = $true
                            $errorOutput = Receive-Job -Job $script:job -ErrorAction SilentlyContinue
                            Write-AuditLog "Job failed. Error output:" -Category "Error"
                            Write-AuditLog $errorOutput -Category "Error"
                            Remove-Job -Job $script:job
                            $script:job = $null
                        }
                        default {
                            Write-AuditLog "Unexpected job state: $jobState. Stopping timer." -Category "Error"
                            Stop-TimerSafely
                            $script:jobCompleted = $true
                            Update-ProgressBar -Value 0 -StatusText "Export Failed!"
                            $targetUPN.IsEnabled = $true
                            $exportLogsButton.IsEnabled = $true
                            if ($null -ne $script:job) {
                                Remove-Job -Job $script:job -Force
                                $script:job = $null
                            }
                        }
                    }
                }
                catch {
                    Write-AuditLog "Error in timer tick: $_" -Category "Error"
                    Write-AuditLog "Stack Trace: $($_.ScriptStackTrace)" -Category "Error"
                    Stop-TimerSafely
                    $script:jobCompleted = $true
                    Update-ProgressBar -Value 0 -StatusText "Export Failed!"
                    $targetUPN.IsEnabled = $true
                    $exportLogsButton.IsEnabled = $true
                    if ($null -ne $script:job) {
                        Remove-Job -Job $script:job -Force
                        $script:job = $null
                    }
                }
            })
            $timer.Start()
        }
        catch {
            Write-AuditLog "Error starting job or timer: $_" -Category "Error"
            Write-AuditLog "Stack Trace: $($_.ScriptStackTrace)" -Category "Error"
            Update-ProgressBar -Value 0 -StatusText "Export Failed!" -IsBold $true -IsIndeterminate $false
            $targetUPN.IsEnabled = $true
            $exportLogsButton.IsEnabled = $true
        }
    })

    $exitButton.Add_Click({ 
        if ($null -ne $script:job) {
            Stop-Job -Job $script:job
            Remove-Job -Job $script:job
        }
        Stop-TimerSafely
        $auditLogWindow.Close() 
    })
    Update-AuditLogWindowTheme
    # Show the window
    $script:AuditLogWindow.ShowDialog()
}
#endregion


#region Remediation Functions
function Stop-CurrentRemediation {
    if ($script:currentRemediationRunspace) {
        try {
            # Stop the runspace
            $script:currentRemediationRunspace.Stop()
            
            # Clean up the runspace
            $script:currentRemediationRunspace.Dispose()
            $script:currentRemediationRunspace = $null
            
            # Update UI to show stopped state
            $ProgressBar.Dispatcher.Invoke([action] {
                $ProgressBar.IsIndeterminate = $false
                $ProgressBar.Value = 0
                $ProgressTextBlock.Text = "Remediation aborted"
                $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
            })
            
            # Write to output box
            $OutputBox.Dispatcher.Invoke([action] {
                $OutputBox.AppendText("`r`n============================================================================================================`r`n")
                $OutputBox.AppendText("Remediation process aborted by user`r`n")
                $OutputBox.AppendText("============================================================================================================`r`n")
                $OutputBox.ScrollToEnd()
            })
            
            return $true
        }
        catch {
            Write-Error "Error stopping remediation: $_"
            return $false
        }
    }
    return $true
}

function Stop-Remediation {
    $script:abortRemediation = $true
    if ($script:currentRemediationRunspace) {
        $script:currentRemediationRunspace.Stop()
    }
}

function Start-ForensicsOnly {
    $UPN = $TargetUPN.Text.Trim()
    
    function Write-EnhancedLog {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Message,
            
            [Parameter()]
            [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG", "SUCCESS")]
            [string]$Category = "INFO",
            
            [Parameter()]
            [switch]$WriteToFile
        )
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Category] $Message"
        
        # Color coding for console output
        $color = switch ($Category) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            "DEBUG" { "Cyan" }
            default { "White" }
        }
        
        Write-Host $logEntry -ForegroundColor $color
        
        if ($WriteToFile -and $script:logpath) {
            $logFile = Join-Path $script:logpath "FSIR-Enhanced-$(Get-Date -Format 'yyyyMMdd').log"
            $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
        }
    }

    # Clear the output box first
    $OutputBox.Dispatcher.Invoke([action] { $OutputBox.Clear() })
    
    $AbortMenuItem.Dispatcher.Invoke([Action]{
        $AbortMenuItem.IsEnabled = $true
        $AbortMenuItem.Visibility = 'Visible' # Make sure it's visible too
    })

    # Enhanced UPN validation with security checks
    if ([string]::IsNullOrWhiteSpace($UPN)) {
        [System.Windows.MessageBox]::Show("Please enter a valid User Principal Name.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return
    }
    
    # Validate UPN format and security
    if (-not (Test-InputSafety -InputText $UPN -InputType "UPN")) {
        [System.Windows.MessageBox]::Show("Invalid or potentially unsafe UPN format. Please check the input.", "Security Warning", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        Write-EnhancedLog -Message "UPN validation failed for input: $UPN" -Category "WARNING" -WriteToFile
        return
    }
    
    Write-EnhancedLog -Message "UPN validation successful for: $UPN" -Category "SUCCESS" -WriteToFile

    $writeOutputBox = {
        param([string]$text)
        $OutputBox.Dispatcher.Invoke([action] {
            $OutputBox.AppendText("$text`r`n")
            $OutputBox.ScrollToEnd()
        })
        # Also writes to transcript
        Write-Host $text
    }

    
    # Initialize timestamps and create forensics folder
    $date = Get-Date
    $formattedDate = $date.ToString("MMMM") + $date.ToString(" d") + $date.ToString(" @ h:mmtt").ToLower()
    $startTime = Get-Date
    $transcriptDirectory = ".\output\transcripts"
    $logDirectory = ".\output\logs"
    $forensicsFolder = ".\output\Forensics\$UPN"
    $transcriptFile = Join-Path $transcriptDirectory "MITS-Remediate-$(Get-Date -Format 'MMddyy_hhmmtt')-$UPN-Lockdown-Forensics.log"
    $logFile = Join-Path $logDirectory "MITS-Remediate-$(Get-Date -Format 'MMddyy_hhmmtt')-$UPN-Forensics-Only.log"
    
    # Ensure directories exist
    @($transcriptDirectory, $logDirectory, $forensicsFolder) | ForEach-Object {
        if (-not (Test-Path -Path $_)) {
            New-Item -Path $_ -ItemType Directory -Force | Out-Null
        }
    }

    & $writeOutputBox "=============================================================================================================="
    # Calculate padding for centering
    $message = "Processing forensic data extraction for $UPN on $formattedDate"
    $totalWidth = 102  # Width of the separator line
    $padding = [math]::Max(0, [math]::Floor(($totalWidth - $message.Length) / 2))
    $centeredMessage = (" " * $padding) + $message
    & $writeOutputBox $centeredMessage
    & $writeOutputBox "=============================================================================================================="
    
    # Initialize progress bar
    $ProgressBar.Dispatcher.Invoke([action] {
        $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
        $ProgressTextBlock.FontWeight = [System.Windows.FontWeights]::Bold
        $ProgressBar.Visibility = 'Visible'
        $ProgressBar.IsIndeterminate = $true
        $ProgressTextBlock.Visibility = 'Visible'
        $ProgressTextBlock.Text = "Processing Forensics Only Request..."
    })

    $scriptBlock = {
        param($UPN, $OutputBox, $ProgressBar, $ProgressTextBlock, $writeOutputBox, $forensicsFolder, 
              $startTime, $transcriptFile, $cancellationToken, $syncHash, $StatusTextBlock, $logFile)
        
        # Define Write-EnhancedLog function within the script block scope
        function Write-EnhancedLog {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$Message,
                
                [Parameter()]
                [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG", "SUCCESS")]
                [string]$Category = "INFO",
                
                [Parameter()]
                [switch]$WriteToFile
            )
            
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logEntry = "[$timestamp] [$Category] $Message"
            
            # Color coding for console output
            $color = switch ($Category) {
                "ERROR" { "Red" }
                "WARNING" { "Yellow" }
                "SUCCESS" { "Green" }
                "DEBUG" { "Cyan" }
                default { "White" }
            }
            
            Write-Host $logEntry -ForegroundColor $color
            
            if ($WriteToFile) {
                $logpath = "C:\temp\FSIR\Output\logs"
                if (-not (Test-Path -Path $logpath)) {
                    New-Item -Path $logpath -ItemType Directory -Force | Out-Null
                }
                $logFile = Join-Path $logpath "FSIR-Enhanced-$(Get-Date -Format 'yyyyMMdd').log"
                $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
            }
        }
        
        # Define Get-IncidentResponseRecommendations function within the script block scope
        function Get-IncidentResponseRecommendations {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [hashtable]$ThreatHuntingResults,
                
                [Parameter(Mandatory = $true)]
                [string]$UPN
            )
            
            $recommendations = @()
            
            switch ($ThreatHuntingResults.ThreatLevel) {
                "Critical" {
                    $recommendations += "IMMEDIATE: Disable user account pending investigation"
                    $recommendations += "IMMEDIATE: Reset user password and revoke all sessions"
                    $recommendations += "IMMEDIATE: Contact security team and management"
                    $recommendations += "Review all administrative actions performed by this user"
                    $recommendations += "Check for lateral movement to other accounts"
                    $recommendations += "Consider forensic imaging of user's devices"
                }
                
                "High" {
                    $recommendations += "Reset user password and revoke active sessions"
                    $recommendations += "Enable additional monitoring for this user"
                    $recommendations += "Review and validate all recent user activities"
                    $recommendations += "Consider temporary access restrictions"
                    $recommendations += "Notify security team for further investigation"
                }
                
                "Medium" {
                    $recommendations += "Schedule security awareness training for user"
                    $recommendations += "Review and update user permissions"
                    $recommendations += "Monitor user activities for next 30 days"
                    $recommendations += "Consider multi-factor authentication enforcement"
                }
                
                "Low" {
                    $recommendations += "Document findings for future reference"
                    $recommendations += "Consider periodic security check-ins"
                    $recommendations += "Review general security policies"
                }
                
                default {
                    $recommendations += "Continue standard security monitoring"
                    $recommendations += "Maintain current security practices"
                }
            }
            
            return $recommendations
        }
        
        # Define the nested Invoke-ThreatHunting function
        function Invoke-ThreatHunting {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$ForensicsPath,
                
                [Parameter(Mandatory = $true)]
                [string]$UPN
            )
            
            Write-EnhancedLog -Message "Starting threat hunting analysis for $UPN..." -Category "INFO" -WriteToFile
            
            $findings = @()
            $threatScore = 0
            
            try {
                # IOC patterns to search for
                $iocPatterns = @{
                    "SuspiciousEmails" = @(
                        "urgent.*action.*required",
                        "verify.*account.*immediately", 
                        "click.*here.*now",
                        "suspicious.*activity.*detected",
                        "account.*will.*be.*suspended"
                    )
                    "MaliciousDomains" = @(
                        "bit\.ly",
                        "tinyurl\.com", 
                        "t\.co",
                        "goo\.gl",
                        ".*\.tk$",
                        ".*\.ml$"
                    )
                    "SuspiciousIPs" = @(
                        "^10\.",          # Private networks (could be tunneling)
                        "^172\.16\.",     # Private networks
                        "^192\.168\.",    # Private networks
                        "^127\.",         # Localhost (suspicious in logs)
                        "^169\.254\."     # APIPA addresses
                    )
                }
                
                # Analyze audit logs if available
                $auditFiles = Get-ChildItem -Path $ForensicsPath -Filter "*AuditLog*.csv" -ErrorAction SilentlyContinue
                foreach ($auditFile in $auditFiles) {
                    Write-EnhancedLog -Message "Analyzing audit log: $($auditFile.Name)" -Category "INFO"
                    
                    try {
                        $auditData = Import-Csv -Path $auditFile.FullName
                        
                        # Check for suspicious login patterns
                        $suspiciousLogins = $auditData | Where-Object {
                            $_.Operation -like "*Login*" -and (
                                $_.ClientIP -match "^(?!10\.|172\.16\.|192\.168\.)" -or  # External IPs
                                $_.ClientIP -match "TOR|Proxy" -or
                                $_.UserAgent -like "*bot*" -or
                                $_.ResultStatus -eq "Failed"
                            )
                        }
                        
                        if ($suspiciousLogins) {
                            $finding = [PSCustomObject]@{
                                Type = "Suspicious Login Attempts"
                                Severity = "Medium"
                                Count = $suspiciousLogins.Count
                                Details = $suspiciousLogins | Select-Object -First 5
                                Recommendation = "Review login attempts from external/suspicious IPs"
                            }
                            $findings += $finding
                            $threatScore += 25
                        }
                        
                        # Check for unusual administrative actions
                        $adminActions = $auditData | Where-Object {
                            $_.Operation -match "Add|Remove|Update|Delete" -and
                            $_.WorkLoad -eq "AzureActiveDirectory"
                        }
                        
                        if ($adminActions.Count -gt 10) {
                            $finding = [PSCustomObject]@{
                                Type = "High Volume Administrative Actions"
                                Severity = "High"
                                Count = $adminActions.Count
                                Details = $adminActions | Select-Object -First 5
                                Recommendation = "Review administrative changes for unauthorized modifications"
                            }
                            $findings += $finding
                            $threatScore += 50
                        }
                        
                    }
                    catch {
                        Write-EnhancedLog -Message "Error analyzing audit file $($auditFile.Name): $_" -Category "ERROR"
                    }
                }
                
                # Analyze message trace data
                $messageFiles = Get-ChildItem -Path $ForensicsPath -Filter "*MessageTrace*.csv" -ErrorAction SilentlyContinue
                foreach ($messageFile in $messageFiles) {
                    Write-EnhancedLog -Message "Analyzing message trace: $($messageFile.Name)" -Category "INFO"
                    
                    try {
                        $messageData = Import-Csv -Path $messageFile.FullName
                        
                        # Check for suspicious email patterns
                        $suspiciousEmails = $messageData | Where-Object {
                            $subject = $_.Subject
                            $iocPatterns["SuspiciousEmails"] | ForEach-Object {
                                if ($subject -match $_) { return $true }
                            }
                            return $false
                        }
                        
                        if ($suspiciousEmails) {
                            $finding = [PSCustomObject]@{
                                Type = "Suspicious Email Subjects"
                                Severity = "Medium"
                                Count = $suspiciousEmails.Count
                                Details = $suspiciousEmails | Select-Object Subject, SenderAddress -First 5
                                Recommendation = "Review emails with suspicious subject patterns"
                            }
                            $findings += $finding
                            $threatScore += 30
                        }
                        
                        # Check for high-volume external senders
                        $externalSenders = $messageData | Where-Object {
                            $_.SenderAddress -notlike "*$($UPN.Split('@')[1])*"
                        } | Group-Object SenderAddress | Where-Object { $_.Count -gt 50 }
                        
                        if ($externalSenders) {
                            $finding = [PSCustomObject]@{
                                Type = "High Volume External Senders"
                                Severity = "Low"
                                Count = $externalSenders.Count
                                Details = $externalSenders | Select-Object Name, Count -First 5
                                Recommendation = "Review high-volume external email sources"
                            }
                            $findings += $finding
                            $threatScore += 15
                        }
                        
                    }
                    catch {
                        Write-EnhancedLog -Message "Error analyzing message file $($messageFile.Name): $_" -Category "ERROR"
                    }
                }
                
                # Generate threat assessment report
                $threatLevel = switch ($threatScore) {
                    { $_ -gt 100 } { "Critical" }
                    { $_ -gt 60 } { "High" }
                    { $_ -gt 30 } { "Medium" }
                    { $_ -gt 10 } { "Low" }
                    default { "Minimal" }
                }
                
                $reportPath = Join-Path $ForensicsPath "ThreatHuntingReport.html"
                $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>FSIR Threat Hunting Report - $UPN</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 15px; border-radius: 5px; }
        .threat-level { padding: 10px; margin: 10px 0; border-radius: 5px; font-weight: bold; }
        .critical { background-color: #e74c3c; color: white; }
        .high { background-color: #f39c12; color: white; }
        .medium { background-color: #f1c40f; color: black; }
        .low { background-color: #27ae60; color: white; }
        .minimal { background-color: #95a5a6; color: white; }
        .finding { border: 1px solid #bdc3c7; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .severity-high { border-left: 5px solid #e74c3c; }
        .severity-medium { border-left: 5px solid #f39c12; }
        .severity-low { border-left: 5px solid #27ae60; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #bdc3c7; padding: 8px; text-align: left; }
        th { background-color: #ecf0f1; }
    </style>
</head>
<body>
    <div class="header">
        <h1>FSIR Threat Hunting Report</h1>
        <p>User: $UPN | Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Threat Score: $threatScore</p>
    </div>
    
    <div class="threat-level $($threatLevel.ToLower())">
        Overall Threat Level: $threatLevel
    </div>
    
    <h2>Executive Summary</h2>
    <p>This report contains the results of automated threat hunting analysis performed on forensic data for user $UPN. 
    A total of $($findings.Count) potential security findings were identified with an overall threat score of $threatScore.</p>
    
    <h2>Detailed Findings</h2>
"@
                
                if ($findings.Count -eq 0) {
                    $htmlReport += "<p>No significant security threats detected in the analyzed data.</p>"
                } else {
                    foreach ($finding in $findings) {
                        $severityClass = "severity-$($finding.Severity.ToLower())"
                        $htmlReport += @"
    <div class="finding $severityClass">
        <h3>$($finding.Type)</h3>
        <p><strong>Severity:</strong> $($finding.Severity)</p>
        <p><strong>Count:</strong> $($finding.Count)</p>
        <p><strong>Recommendation:</strong> $($finding.Recommendation)</p>
    </div>
"@
                    }
                }
                
                $htmlReport += @"
    
    <h2>Recommendations</h2>
    <ul>
        <li>Review all identified findings in detail</li>
        <li>Correlate findings with other security tools and logs</li>
        <li>Consider implementing additional monitoring for suspicious patterns</li>
        <li>Update security policies based on identified vulnerabilities</li>
    </ul>
    
    <p><em>Generated by FSIR Toolkit</em></p>
</body>
</html>
"@
                
                $htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
                Write-EnhancedLog -Message "Threat hunting report generated: $reportPath" -Category "SUCCESS" -WriteToFile
                Write-EnhancedLog -Message "Threat hunting analysis completed. Threat Level: $threatLevel (Score: $threatScore)" -Category "INFO" -WriteToFile
                
                return @{
                    ThreatLevel = $threatLevel
                    ThreatScore = $threatScore
                    FindingsCount = $findings.Count
                    ReportPath = $reportPath
                    Findings = $findings
                }
                
            }
            catch {
                Write-EnhancedLog -Message "Error during threat hunting analysis: $_" -Category "ERROR" -WriteToFile
                throw
            }
        }
                
        try {
            # Start transcript at the beginning of the runspace
            if (Test-Path $transcriptFile) {
                Remove-Item $transcriptFile -Force
            }
            Start-Transcript -Path $transcriptFile -Force
            Write-Host "=============================================================================================================="
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Processing forensic data extraction for $UPN on $formattedDate"
            Write-Host "=============================================================================================================="
        }
        catch {
            & $writeOutputBox "Error starting transcript: $_" $logFile
        }
       
        
        function Test-ShouldContinueRemediation {
            # Check both the sync hash and cancellation token
            if ($syncHash.abortFlag -or $cancellationToken.IsCancellationRequested) {
                # Add a small delay to ensure messages are written in order
                Start-Sleep -Milliseconds 500
                
                # Only write the message once when aborting
                if (-not $script:abortMessageDisplayed) {
                    #& $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                    & $writeOutputBox "`r`n  $([char]0x25E6) Remediation process aborted successfully!"
                    #& $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                    Write-RemediationLog "Remediation process aborted successfully!" -Level Info
                    $script:abortMessageDisplayed = $true
                }
                $ProgressTextBlock.Dispatcher.Invoke([action] {
                    $ProgressTextBlock.Text = "Remediation aborted"
                    $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
                    $ProgressBar.IsIndeterminate = $false
                    $ProgressBar.Value = 0
                })
                
                # Disable the Abort menu item
                $AbortMenuItem.Dispatcher.Invoke([Action]{
                    $AbortMenuItem.IsEnabled = $false
                })
        
                # Throw a terminating exception to immediately stop execution
                throw New-Object System.OperationCanceledException("Remediation aborted by user")
            }
            return $true
        }

        try {
            # Validate UPN in scriptblock
            if ([string]::IsNullOrWhiteSpace($UPN)) {
                throw "User Principal Name is null or empty"
            }
            & $writeOutputBox "`r  $([char]0x25E6) User Principal Name: $UPN"
            & $writeOutputBox "  $([char]0x25E6) Remediation Start: $(Get-Date -Format 'MM/dd/yyyy hh:mm tt')"
            & $writeOutputBox "  $([char]0x25E6) Remediation Mode: Forensics Only"
            & $writeOutputBox "  $([char]0x25E6) Forensics folder: $forensicsFolder"
            Start-Sleep -Milliseconds 1300
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [1] Loading required modules:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

            # Load required modules
            $requiredModules = @(
                'Microsoft.Graph.Users',
                'Microsoft.Graph.Authentication',
                'Microsoft.Graph.Identity.SignIns',
                'ExchangeOnlineManagement',
                'MSOnline',
                'AzureAD'
            )
    
            foreach ($module in $requiredModules) {
                if (!(Get-Module -Name $module -ListAvailable)) {
                    & $writeOutputBox "  $([char]0x25E6) Installing module: $module"
                    Install-Module -Name $module -Force -AllowClobber
                }
                Import-Module $module -ErrorAction Stop
                & $writeOutputBox "  $([char]0x25E6) Loaded module: $module"
            }
    
            # Initialize progress tracking
            $totalSteps = 3  # Graph, Exchange, Azure AD
            $currentStep = 0
            
            $UpdateProgress = {
                param($step, $total, $status)
                $percentage = ($step / $total) * 100
                $ProgressBar.Dispatcher.Invoke([action] {
                    $ProgressBar.Visibility = 'Visible'
                    $ProgressBar.IsIndeterminate = $true
                    $ProgressBar.Value = $percentage
                    $ProgressTextBlock.Text = $status
                    $ProgressTextBlock.Visibility = 'Visible'
                    $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
                    $ProgressTextBlock.FontWeight = [System.Windows.FontWeights]::Bold
                })
            }
    
            # 2. Verify M365 Services Connection
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [2] Verifying service connection:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

            try {
                $existingSession = Get-PSSession | Where-Object {$_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened"}
                if ($existingSession) {
                    Import-PSSession $existingSession -AllowClobber -DisableNameChecking | Out-Null
                    #& $writeOutputBox "  $([char]0x25E6) Using existing Exchange Online connection"
                } else {
                    #& $writeOutputBox "  $([char]0x25E6) Connecting to Exchange Online..."
                    Connect-ExchangeOnline -ShowBanner:$false -UseMultithreading:$true
                    & $writeOutputBox "  $([char]0x25E6) Connected to Exchange Online"
                }
            } catch {
                & $writeOutputBox "  $([char]0x25E6) Error connecting to Exchange Online: $_"
                throw
            }
    
            # Verify/Import Azure AD connection
            #& $UpdateProgress $currentStep $totalSteps "Connecting to Azure AD..."
            try {
                $null = Get-AzureADTenantDetail -ErrorAction Stop
                & $writeOutputBox "  $([char]0x25E6) Connected to AzureAD"
            } catch {
                & $writeOutputBox "  $([char]0x25E6) Connecting to Azure AD..."
                Connect-AzureAD
                & $writeOutputBox "  $([char]0x25E6) Connected to Azure AD"
            }
            $currentStep++
            & $UpdateProgress $currentStep $totalSteps "Azure AD connected"
    
            # Verify/Import Microsoft Graph connection
            if (-not (Get-MgContext)) {
                if (-not (Test-ShouldContinueRemediation)) { return }
                
                try {
                    & $writeOutputBox "  $([char]0x25E6) Connecting to Microsoft Graph..."
                    Connect-MgGraph -Scopes @(
                        "User.ReadWrite.All",
                        "Directory.ReadWrite.All",
                        "User.Read.All",
                        "Organization.Read.All",
                        "Policy.Read.All",
                        "Mail.ReadWrite",
                        "UserAuthenticationMethod.ReadWrite.All",
                        "MailboxSettings.Read.All"
                    )
                    & $writeOutputBox "  $([char]0x25E6) Connected to Microsoft Graph"
                    Start-Sleep -Seconds 2
                } catch {
                    # Check if this is a user cancellation
                    if ($_.Exception.Message -like "*User canceled authentication*" -or 
                        $_.Exception.Message -like "*canceled*" -or 
                        $_.Exception.Message -like "*cancelled*") {
                        
                        $syncHash.abortFlag = $true
                        $script:remediationCancellationSource.Cancel()
                        
                        if (-not (Test-ShouldContinueRemediation)) { return }
                    } else {
                        & $writeOutputBox "  $([char]0x25E6) Error connecting to Microsoft Graph: $_"
                        throw
                    }
                }
            } else {
                & $writeOutputBox "  $([char]0x25E6) Connected to Microsoft Graph"
                Start-Sleep -Seconds 2
            }
            
            if (-not (Test-ShouldContinueRemediation)) { return }
            
            $currentStep++
            & $UpdateProgress $currentStep $totalSteps "All services connected"
            
                Start-Sleep -Seconds 2
                function Convert-AuditLog {
                    param(
                        [Parameter(Mandatory=$true)]
                        [string]$UPN,
                        [string]$ForensicsFolder
                    )
                    
                    & $writeOutputBox "  $([char]0x25E6) Converting audit log: $ForensicsFolder\$UPN-AuditLog-Last30Days.csv"
                    $inputCsv = "$ForensicsFolder\$UPN-AuditLog-Last30Days.csv"
                    
                    if (-Not (Test-Path $inputCsv)) {
                        & $writeOutputBox "  $([char]0x25E6) Audit log file does not exist: $inputCsv"
                        return
                    }
                
                    # Extract directory and filename from the input path
                    $directory = Split-Path -Path $inputCsv -Parent
                    $filename = [System.IO.Path]::GetFileNameWithoutExtension($inputCsv)
                    $extension = [System.IO.Path]::GetExtension($inputCsv)
                
                    # Define the new filename with '-Processed' appended
                    $newFilename = "${filename}-Processed${extension}"
                    $outputCsv = Join-Path -Path $directory -ChildPath $newFilename
                
                    try {
                        # Read the CSV file
                        $data = Import-Csv -Path $inputCsv
                
                        # Initialize an array to store the extracted data
                        $extractedData = @()
                
                        # Loop through each row in the CSV file
                        foreach ($row in $data) {
                            # Parse the JSON data in the 'AuditData' column
                            $auditData = $row.AuditData | ConvertFrom-Json
                
                            # Extract the necessary fields
                            $extractedRow = [PSCustomObject]@{
                                CCreationTime = $auditData.CreationTime
                                Id = $auditData.Id
                                Operation = $auditData.Operation
                                OrganizationId = $auditData.OrganizationId
                                RecordType = $auditData.RecordType
                                ResultStatus = $auditData.ResultStatus
                                UserKey = $auditData.UserKey
                                UserType = $auditData.UserType
                                Version = $auditData.Version
                                Workload = $auditData.Workload
                                UserId = $auditData.UserId
                                AppId = $auditData.AppId
                                ClientAppId = $auditData.ClientAppId
                                ClientIPAddress = $auditData.ClientIPAddress
                                ClientInfoString = $auditData.ClientInfoString
                                ExternalAccess = $auditData.ExternalAccess
                                InternalLogonType = $auditData.InternalLogonType
                                LogonType = $auditData.LogonType
                                LogonUserSid = $auditData.LogonUserSid
                                MailboxGuid = $auditData.MailboxGuid
                                MailboxOwnerSid = $auditData.MailboxOwnerSid
                                MailboxOwnerUPN = $auditData.MailboxOwnerUPN
                                MailAccessType = ($auditData.OperationProperties | Where-Object { $_.Name -eq 'MailAccessType' }).Value
                                IsThrottled = ($auditData.OperationProperties | Where-Object { $_.Name -eq 'IsThrottled' }).Value
                                OrganizationName = $auditData.OrganizationName
                                OriginatingServer = $auditData.OriginatingServer
                                SessionId = $auditData.SessionId
                                FolderPath = $null
                                FolderItemsId = $null
                                FolderItemsInternetMessageId = $null
                                FolderItemsSizeInBytes = $null
                                OperationCount = $auditData.OperationCount
                            }
                
                            # Add the extracted row to the array
                            $extractedData += $extractedRow
                        }
                
                        # Export the extracted data to the new CSV file
                        $extractedData | Export-Csv -Path $outputCsv -NoTypeInformation
                        & $writeOutputBox "  $([char]0x25E6) Successfully converted audit log to: $newFilename"
                    }
                    catch {
                        & $writeOutputBox "  $([char]0x25E6) Error converting audit log: $_"
                    }
                }

                # Reset progress bar for the main operations
                $ProgressTextBlock.Dispatcher.Invoke([action] {
                    $ProgressBar.Visibility = 'Visible'
                    $ProgressBar.IsIndeterminate = $true
                    $ProgressTextBlock.Text = "Initiating Lockdown w/ Forensics..."
                    $ProgressTextBlock.Visibility = 'Visible'
                    $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
                    $ProgressTextBlock.FontWeight = [System.Windows.FontWeights]::Bold
                })          


                        # 3. Message Trace
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [3] Running message trace:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Running message trace..."
                        })
                        try {
                            $StartDate = (Get-Date).AddDays(-10)
                            $EndDate = Get-Date

                            # Get inbound messages
                            $inboundTrace = Get-MessageTrace -RecipientAddress $UPN -StartDate $StartDate -EndDate $EndDate
                            
                            # Get outbound messages
                            $outboundTrace = Get-MessageTrace -SenderAddress $UPN -StartDate $StartDate -EndDate $EndDate
                            
                            # Export inbound messages if found
                            if ($inboundTrace) {
                                $inboundTrace | Export-Csv -Path "$forensicsFolder\$UPN-InboundMessageTrace.csv" -NoTypeInformation
                                & $writeOutputBox "  $([char]0x25E6) Exported $(($inboundTrace | Measure-Object).Count) inbound message trace items"
                                
                                # Show top 5 senders
                                $topSenders = $inboundTrace | Group-Object SenderAddress | Sort-Object Count -Descending | Select-Object -First 5
                                & $writeOutputBox "`r  Top 5 message senders:"
                                foreach ($sender in $topSenders) {
                                    & $writeOutputBox "    - $($sender.Name): $($sender.Count) messages"
                                }
                            } else {
                                & $writeOutputBox "  $([char]0x25E6) No inbound message trace items found"
                            }
                            
                            # Export outbound messages if found
                            if ($outboundTrace) {
                                $outboundTrace | Export-Csv -Path "$forensicsFolder\$UPN-OutboundMessageTrace.csv" -NoTypeInformation
                                & $writeOutputBox "`r  $([char]0x25E6) Exported $(($outboundTrace | Measure-Object).Count) outbound message trace items"
                                
                                # Show top 5 recipients
                                $topRecipients = $outboundTrace | Group-Object RecipientAddress | Sort-Object Count -Descending | Select-Object -First 5
                                & $writeOutputBox "`r  Top 5 message recipients:"
                                foreach ($recipient in $topRecipients) {
                                    & $writeOutputBox "    - $($recipient.Name): $($recipient.Count) messages"
                                }
                            } else {
                                & $writeOutputBox "  $([char]0x25E6) No outbound message trace items found"
                            }
                            
                            # Calculate total message count
                            $totalMessages = ($inboundTrace | Measure-Object).Count + ($outboundTrace | Measure-Object).Count
                            & $writeOutputBox "`r  $([char]0x25E6) Total messages processed: $totalMessages"
                            
                        }
                        catch {
                            & $writeOutputBox "  $([char]0x25E6) Error running message trace: $_"
                            & $writeOutputBox "  $([char]0x25E6) Stack Trace: $($_.ScriptStackTrace)"
                        }

                        # 5. Export and Convert Audit Log
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [4] Exporting audit logs:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Exporting audit logs..."
                        })
                        try {
                            $SessionId = [guid]::NewGuid().ToString()
                            $ResultSize = 5000
                            $AllResults = @()
                            
                            do {
                                $Results = Search-UnifiedAuditLog -UserIds $UPN -StartDate $StartDate -EndDate $EndDate -SessionId $SessionId -SessionCommand ReturnLargeSet -ResultSize $ResultSize
                                if ($Results) {
                                    $AllResults += $Results
                                    & $writeOutputBox "  $([char]0x25E6) Retrieved $($Results.Count) audit log entries..."
                                }
                                Start-Sleep -Seconds 2
                            } while ($Results.Count -eq $ResultSize)
                            
                            # In the audit log export section:
                            if ($AllResults.Count -gt 0) {
                                $filename = "$UPN-AuditLog-Last30Days.csv"
                                $outputPath = Join-Path -Path $forensicsFolder -ChildPath "$filename"
                                $AllResults | Export-Csv -Path $outputPath -NoTypeInformation
                                & $writeOutputBox "  $([char]0x25E6) Exported $($AllResults.Count) total audit log entries"
                                Convert-AuditLog -UPN $UPN -ForensicsFolder $forensicsFolder
                            } else {
                                & $writeOutputBox "  $([char]0x25E6) No audit log entries found"
                            }
                        }
                        catch {
                            & $writeOutputBox "  $([char]0x25E6) Error exporting audit logs: $_"
                        }

                        # 6. Export Forensics Data
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [5] Collecting forensics data:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Collecting forensics data..."
                        })

                        $forensicsOperations = @(
                            @{ Name = "Mailbox settings"; Cmdlet = { Get-Mailbox -Identity $UPN }; File = "mailbox.xml" },
                            @{ Name = "Inbox rules"; Cmdlet = { Get-InboxRule -Mailbox $UPN }; File = "inboxrules.xml" },
                            @{ Name = "Calendar folder"; Cmdlet = { Get-MailboxCalendarFolder -Identity "$UPN`:\Calendar" }; File = "MailboxCalendarFolder.xml" },
                            @{ Name = "Mailbox delegates"; Cmdlet = { Get-MailboxPermission -Identity $UPN | Where-Object { ($_.IsInherited -ne $true) -and ($_.User -notlike "*SELF*") } }; File = "MailboxDelegates.xml" },
                            @{ Name = "Registered devices"; Cmdlet = { Get-MgUserRegisteredDevice -UserId $UPN }; File = "registeredDevices.xml" },
                            @{ Name = "Mail folders"; Cmdlet = { Get-MgUserMailFolder -UserId $UPN }; File = "mailFolders.xml" },
                            @{ Name = "Owned devices"; Cmdlet = { Get-MgUserOwnedDevice -UserId $UPN }; File = "ownedDevices.xml" },
                            @{ Name = "Group memberships"; Cmdlet = { Get-MgUserMemberOf -UserId $UPN }; File = "groupMemberships.xml" },
                            @{ Name = "App role assignments"; Cmdlet = { Get-MgUserAppRoleAssignment -UserId $UPN }; File = "appRoleAssignments.xml" },
                            @{ 
                                Name = "Mobile devices"; 
                                Cmdlet = { 
                                    try {
                                        $devices = Get-MobileDevice -Mailbox $UPN -ErrorAction Stop |
                                            Select-Object DeviceId, DeviceType, DeviceModel, DeviceOS, 
                                                FirstSyncTime, LastSyncTime, DeviceAccessState, 
                                                DeviceAccessStateReason, ClientType, UserDisplayName
                                        
                                        if ($devices) {
                                            return $devices
                                        }
                                        Write-Warning "No mobile devices found for $UPN"
                                        return $null
                                    } catch {
                                        Write-Warning "Error getting mobile devices: $_"
                                        return $null
                                    }
                                }; 
                                File = "mobileDevices.xml" 
                            }
                        )

                        foreach ($op in $forensicsOperations) {
                            try {
                                $data = & $op.Cmdlet
                                if ($null -ne $data) {
                                    $data | Export-Clixml -Path "$forensicsFolder\$UPN-$($op.File)" -Force
                                    & $writeOutputBox "  $([char]0x25E6) Exported $($op.Name)"
                                } else {
                                    & $writeOutputBox "  $([char]0x25E6) No data found for $($op.Name)"
                                }
                            }
                            catch {
                                & $writeOutputBox "  $([char]0x25E6) Error exporting $($op.Name): $_"
                            }
                        }


                        # Completion
                        & $writeOutputBox "`n"
                        & $writeOutputBox "=============================================================================================================="
                        & $writeOutputBox "                              Remediation of $UPN is complete!"
                        & $writeOutputBox "=============================================================================================================="
                        
                        $endTime = Get-Date
                        $executionTime = New-TimeSpan -Start $startTime -End $endTime
                        & $writeOutputBox "`r Completion Time: $(Get-Date -Format 'MM/dd/yyyy hh:mm:ss tt')"
                        & $writeOutputBox " Execution Time: $($executionTime.TotalSeconds) seconds"
                        & $writeOutputBox " Export Location: $forensicsFolder"
                        & $writeOutputBox "=============================================================================================================="
                        
                        # Perform automated threat hunting analysis
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [THREAT HUNTING] Analyzing collected data for indicators of compromise:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Performing threat hunting analysis..."
                        })
                        
                        try {
                            $threatResults = Invoke-ThreatHunting -ForensicsPath $forensicsFolder -UPN $UPN
                            & $writeOutputBox "  $([char]0x25E6) Threat Level: $($threatResults.ThreatLevel)"
                            & $writeOutputBox "  $([char]0x25E6) Threat Score: $($threatResults.ThreatScore)"
                            & $writeOutputBox "  $([char]0x25E6) Findings: $($threatResults.FindingsCount)"
                            & $writeOutputBox "  $([char]0x25E6) Report: $($threatResults.ReportPath)"
                            
                            # Get and display recommendations
                            $recommendations = Get-IncidentResponseRecommendations -ThreatHuntingResults $threatResults -UPN $UPN
                            & $writeOutputBox "`r  AUTOMATED RECOMMENDATIONS:"
                            foreach ($recommendation in $recommendations) {
                                & $writeOutputBox "  $([char]0x25E6) $recommendation"
                            }
                        }
                        catch {
                            & $writeOutputBox "  $([char]0x25E6) Error during threat hunting analysis: $_"
                        }

                        $ProgressBar.Dispatcher.Invoke([action] {
                            $ProgressBar.IsIndeterminate = $false
                            $ProgressBar.Value = 100
                            $ProgressTextBlock.Text = "Lockdown w/ Forensics remediation complete"
                            $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::White
                        })
                    } 
                    catch {
                        # Only show error if it's not an abort
                        if (-not ($syncHash.abortFlag -or $cancellationToken.IsCancellationRequested)) {
                            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                            & $writeOutputBox "ERROR: Lockdown process failed"
                            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                            & $writeOutputBox "Error details: $_"
                            & $writeOutputBox "Stack Trace: $($_.ScriptStackTrace)"                            

                            $ProgressBar.Dispatcher.Invoke([action] {
                                $ProgressBar.IsIndeterminate = $false
                                $ProgressBar.Value = 0
                                $ProgressTextBlock.Text = "Error during lockdown"
                                $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
                            })
                            
                            # Update status text for error
                            $syncHash.statusText = "Error during lockdown"
                            $StatusTextBlock.Dispatcher.Invoke([action] {
                                $StatusTextBlock.Text = "Error during lockdown"
                            })
                        }
                        
                        # Disable the Abort menu item
                        $AbortMenuItem.Dispatcher.Invoke([Action]{
                            $AbortMenuItem.IsEnabled = $false
                        })
                    }
                }
                
                $AbortMenuItem.Dispatcher.Invoke([Action]{
                    $AbortMenuItem.IsEnabled = $false
                    $AbortMenuItem.Visibility = 'Visible' # Make sure it's visible too
                })

                try {
                    Stop-Transcript
                }
                catch {
                }

                # Create and invoke the runspace
                $runspace = [powershell]::Create().AddScript($scriptBlock)
                $runspace.AddArgument($UPN)
                $runspace.AddArgument($OutputBox)
                $runspace.AddArgument($ProgressBar)
                $runspace.AddArgument($ProgressTextBlock)
                $runspace.AddArgument($writeOutputBox)
                $runspace.AddArgument($forensicsFolder)
                $runspace.AddArgument($startTime)
                $runspace.AddArgument($transcriptFile)
                $runspace.AddArgument($cancellationToken)
                $runspace.AddArgument($syncHash)
                $runspace.AddArgument($StatusTextBlock)
                $runspace.AddArgument($logFile)

                $runspace.RunspacePool = $global:RunspacePool
                $script:currentRemediationRunspace = @{
                    PowerShell = $runspace
                    Handle = $runspace.BeginInvoke()
                }
                
                return $script:currentRemediationRunspace
}

function Start-LockdownOnly {
    $OutputBox.Dispatcher.Invoke([action] { $OutputBox.Clear() })
    $writeOutputBox = {
        param([string]$text)
        $OutputBox.Dispatcher.Invoke([action] {
            $OutputBox.AppendText("$text`r`n")
            $OutputBox.ScrollToEnd()
        })
        # Add transcript logging
        Write-Host $text
    }
  
    $UPN = $TargetUPN.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($UPN) -or $UPN -eq "Enter target UPN") {
        [System.Windows.MessageBox]::Show("Please enter a valid User Principal Name.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return
    }
    
    #if (-not $global:IsConnected) {
    #    TypeOutputBoxMessage -OutputBox $OutputBox -Message "Please connect first before securing the account."
    #    return
    #}

    # Initialize cancellation token source
    $script:remediationCancellationSource = New-Object System.Threading.CancellationTokenSource
    
    # Reset abort flag before starting
    $script:abortRemediation = $false
    
    # Enable the Abort menu item when starting remediation
    $AbortMenuItem.Dispatcher.Invoke([Action]{
        $AbortMenuItem.IsEnabled = $true
    })
    
    # Capture the current timestamp for logging purposes
    $date = Get-Date
    $formattedDate = $date.ToString("MMMM") + $date.ToString(" d") + $date.ToString(" @ h:mmtt").ToLower()
    $startTime = Get-Date 
    $logDirectory = ".\output\transcripts"
    $logFile = Join-Path $logDirectory "MITS-Remediate-$(Get-Date -Format 'MMddyy_hhmmtt')-$UPN-Lockdown-Only.log"

    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
    }
        
    $ProgressBar.Dispatcher.Invoke([action] {
        $ProgressBar.Visibility = 'Visible'
        $ProgressBar.IsIndeterminate = $true
        $ProgressTextBlock.Visibility = 'Visible'
        $ProgressTextBlock.Text = "Processing lockdown request..."
        $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
    })
    
    # Create the UPN-specific folder before starting
    if (-not (Test-Path -Path $forensicsFolder)) {
        try {
            New-Item -Path $forensicsFolder -ItemType Directory -Force -ErrorAction Stop
            & $writeOutputBox "  $([char]0x25E6) Created forensics folder: $forensicsFolder"
        }
        catch {
            & $writeOutputBox "Error creating forensics folder: $_"
            & $writeOutputBox "Stack Trace: $($_.ScriptStackTrace)"
            return
        }
    }
    
    $runspace = [powershell]::Create().AddScript({
        param($UPN, $OutputBox, $ProgressBar, $ProgressTextBlock, $writeOutputBox, $startTime, $AbortMenuItem, $cancellationToken, $forensicsFolder, $logFile, $formattedDate)
        

        # Define the nested Invoke-ThreatHunting function
        function Invoke-ThreatHunting {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$ForensicsPath,
                
                [Parameter(Mandatory = $true)]
                [string]$UPN
            )
            
            Write-EnhancedLog -Message "Starting threat hunting analysis for $UPN..." -Category "INFO" -WriteToFile
            
            $findings = @()
            $threatScore = 0
            
            try {
                # IOC patterns to search for
                $iocPatterns = @{
                    "SuspiciousEmails" = @(
                        "urgent.*action.*required",
                        "verify.*account.*immediately", 
                        "click.*here.*now",
                        "suspicious.*activity.*detected",
                        "account.*will.*be.*suspended"
                    )
                    "MaliciousDomains" = @(
                        "bit\.ly",
                        "tinyurl\.com", 
                        "t\.co",
                        "goo\.gl",
                        ".*\.tk$",
                        ".*\.ml$"
                    )
                    "SuspiciousIPs" = @(
                        "^10\.",          # Private networks (could be tunneling)
                        "^172\.16\.",     # Private networks
                        "^192\.168\.",    # Private networks
                        "^127\.",         # Localhost (suspicious in logs)
                        "^169\.254\."     # APIPA addresses
                    )
                }
                
                # Analyze audit logs if available
                $auditFiles = Get-ChildItem -Path $ForensicsPath -Filter "*AuditLog*.csv" -ErrorAction SilentlyContinue
                foreach ($auditFile in $auditFiles) {
                    Write-EnhancedLog -Message "Analyzing audit log: $($auditFile.Name)" -Category "INFO"
                    
                    try {
                        $auditData = Import-Csv -Path $auditFile.FullName
                        
                        # Check for suspicious login patterns
                        $suspiciousLogins = $auditData | Where-Object {
                            $_.Operation -like "*Login*" -and (
                                $_.ClientIP -match "^(?!10\.|172\.16\.|192\.168\.)" -or  # External IPs
                                $_.ClientIP -match "TOR|Proxy" -or
                                $_.UserAgent -like "*bot*" -or
                                $_.ResultStatus -eq "Failed"
                            )
                        }
                        
                        if ($suspiciousLogins) {
                            $finding = [PSCustomObject]@{
                                Type = "Suspicious Login Attempts"
                                Severity = "Medium"
                                Count = $suspiciousLogins.Count
                                Details = $suspiciousLogins | Select-Object -First 5
                                Recommendation = "Review login attempts from external/suspicious IPs"
                            }
                            $findings += $finding
                            $threatScore += 25
                        }
                        
                        # Check for unusual administrative actions
                        $adminActions = $auditData | Where-Object {
                            $_.Operation -match "Add|Remove|Update|Delete" -and
                            $_.WorkLoad -eq "AzureActiveDirectory"
                        }
                        
                        if ($adminActions.Count -gt 10) {
                            $finding = [PSCustomObject]@{
                                Type = "High Volume Administrative Actions"
                                Severity = "High"
                                Count = $adminActions.Count
                                Details = $adminActions | Select-Object -First 5
                                Recommendation = "Review administrative changes for unauthorized modifications"
                            }
                            $findings += $finding
                            $threatScore += 50
                        }
                        
                    }
                    catch {
                        Write-EnhancedLog -Message "Error analyzing audit file $($auditFile.Name): $_" -Category "ERROR"
                    }
                }
                
                # Analyze message trace data
                $messageFiles = Get-ChildItem -Path $ForensicsPath -Filter "*MessageTrace*.csv" -ErrorAction SilentlyContinue
                foreach ($messageFile in $messageFiles) {
                    Write-EnhancedLog -Message "Analyzing message trace: $($messageFile.Name)" -Category "INFO"
                    
                    try {
                        $messageData = Import-Csv -Path $messageFile.FullName
                        
                        # Check for suspicious email patterns
                        $suspiciousEmails = $messageData | Where-Object {
                            $subject = $_.Subject
                            $iocPatterns["SuspiciousEmails"] | ForEach-Object {
                                if ($subject -match $_) { return $true }
                            }
                            return $false
                        }
                        
                        if ($suspiciousEmails) {
                            $finding = [PSCustomObject]@{
                                Type = "Suspicious Email Subjects"
                                Severity = "Medium"
                                Count = $suspiciousEmails.Count
                                Details = $suspiciousEmails | Select-Object Subject, SenderAddress -First 5
                                Recommendation = "Review emails with suspicious subject patterns"
                            }
                            $findings += $finding
                            $threatScore += 30
                        }
                        
                        # Check for high-volume external senders
                        $externalSenders = $messageData | Where-Object {
                            $_.SenderAddress -notlike "*$($UPN.Split('@')[1])*"
                        } | Group-Object SenderAddress | Where-Object { $_.Count -gt 50 }
                        
                        if ($externalSenders) {
                            $finding = [PSCustomObject]@{
                                Type = "High Volume External Senders"
                                Severity = "Low"
                                Count = $externalSenders.Count
                                Details = $externalSenders | Select-Object Name, Count -First 5
                                Recommendation = "Review high-volume external email sources"
                            }
                            $findings += $finding
                            $threatScore += 15
                        }
                        
                    }
                    catch {
                        Write-EnhancedLog -Message "Error analyzing message file $($messageFile.Name): $_" -Category "ERROR"
                    }
                }
                
                # Generate threat assessment report
                $threatLevel = switch ($threatScore) {
                    { $_ -gt 100 } { "Critical" }
                    { $_ -gt 60 } { "High" }
                    { $_ -gt 30 } { "Medium" }
                    { $_ -gt 10 } { "Low" }
                    default { "Minimal" }
                }
                
                $reportPath = Join-Path $ForensicsPath "ThreatHuntingReport.html"
                $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>FSIR Threat Hunting Report - $UPN</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 15px; border-radius: 5px; }
        .threat-level { padding: 10px; margin: 10px 0; border-radius: 5px; font-weight: bold; }
        .critical { background-color: #e74c3c; color: white; }
        .high { background-color: #f39c12; color: white; }
        .medium { background-color: #f1c40f; color: black; }
        .low { background-color: #27ae60; color: white; }
        .minimal { background-color: #95a5a6; color: white; }
        .finding { border: 1px solid #bdc3c7; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .severity-high { border-left: 5px solid #e74c3c; }
        .severity-medium { border-left: 5px solid #f39c12; }
        .severity-low { border-left: 5px solid #27ae60; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #bdc3c7; padding: 8px; text-align: left; }
        th { background-color: #ecf0f1; }
    </style>
</head>
<body>
    <div class="header">
        <h1>FSIR Threat Hunting Report</h1>
        <p>User: $UPN | Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Threat Score: $threatScore</p>
    </div>
    
    <div class="threat-level $($threatLevel.ToLower())">
        Overall Threat Level: $threatLevel
    </div>
    
    <h2>Executive Summary</h2>
    <p>This report contains the results of automated threat hunting analysis performed on forensic data for user $UPN. 
    A total of $($findings.Count) potential security findings were identified with an overall threat score of $threatScore.</p>
    
    <h2>Detailed Findings</h2>
"@
                
                if ($findings.Count -eq 0) {
                    $htmlReport += "<p>No significant security threats detected in the analyzed data.</p>"
                } else {
                    foreach ($finding in $findings) {
                        $severityClass = "severity-$($finding.Severity.ToLower())"
                        $htmlReport += @"
    <div class="finding $severityClass">
        <h3>$($finding.Type)</h3>
        <p><strong>Severity:</strong> $($finding.Severity)</p>
        <p><strong>Count:</strong> $($finding.Count)</p>
        <p><strong>Recommendation:</strong> $($finding.Recommendation)</p>
    </div>
"@
                    }
                }
                
                $htmlReport += @"
    
    <h2>Recommendations</h2>
    <ul>
        <li>Review all identified findings in detail</li>
        <li>Correlate findings with other security tools and logs</li>
        <li>Consider implementing additional monitoring for suspicious patterns</li>
        <li>Update security policies based on identified vulnerabilities</li>
    </ul>
    
    <p><em>Generated by FSIR Toolkit v$($script:ScriptVersion)</em></p>
</body>
</html>
"@
                
                $htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
                Write-EnhancedLog -Message "Threat hunting report generated: $reportPath" -Category "SUCCESS" -WriteToFile
                Write-EnhancedLog -Message "Threat hunting analysis completed. Threat Level: $threatLevel (Score: $threatScore)" -Category "INFO" -WriteToFile
                
                return @{
                    ThreatLevel = $threatLevel
                    ThreatScore = $threatScore
                    FindingsCount = $findings.Count
                    ReportPath = $reportPath
                    Findings = $findings
                }
                
            }
            catch {
                Write-EnhancedLog -Message "Error during threat hunting analysis: $_" -Category "ERROR" -WriteToFile
                throw
            }
        }

        # Initialize abort message flag
        $script:abortMessageDisplayed = $false

        try {
            & $writeOutputBox "`r=============================================================================================================="
            # Calculate padding for centering
            $message = "Processing lockdown steps for $UPN on $formattedDate"
            $totalWidth = 102  # Width of the separator line
            $padding = [math]::Max(0, [math]::Floor(($totalWidth - $message.Length) / 2))
            $centeredMessage = (" " * $padding) + $message
            & $writeOutputBox $centeredMessage
            & $writeOutputBox "=============================================================================================================="
            
            Start-Sleep -Seconds 2
            & $writeOutputBox "`r  $([char]0x25E6) User Principal Name: $UPN"
            & $writeOutputBox "  $([char]0x25E6) Remediation Start: $(Get-Date -Format 'MM/dd/yyyy hh:mm tt')"
            & $writeOutputBox "  $([char]0x25E6) Remediation Mode: Lockdown Only"
        }
        catch {
            Write-Host "Error starting transcript: $_"
        }
       

        function Test-ShouldContinueRemediation {
            # Check cancellation token
            if ($cancellationToken.IsCancellationRequested) {
                # Add a small delay to ensure messages are written in order
                Start-Sleep -Milliseconds 500
                
                # Only write the message once when aborting
                if (-not $script:abortMessageDisplayed) {
                    & $writeOutputBox "`r`n  $([char]0x25E6) Remediation process aborted successfully!"
                    #Write-RemediationLog "Remediation process aborted successfully!" -Level Info
                    $script:abortMessageDisplayed = $true
                }
                
                $ProgressTextBlock.Dispatcher.Invoke([action] {
                    $ProgressTextBlock.Text = "Remediation aborted"
                    $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
                    $ProgressBar.IsIndeterminate = $false
                    $ProgressBar.Value = 0
                })
                
                # Disable the Abort menu item
                $AbortMenuItem.Dispatcher.Invoke([Action]{
                    $AbortMenuItem.IsEnabled = $false
                })
        
                # Throw a terminating exception to immediately stop execution
                throw New-Object System.OperationCanceledException("Remediation aborted by user")
            }
            return $true
        }
        
        function Reset-Connections {
            # Disconnect existing sessions
            try {
                Disconnect-MgGraph -ErrorAction SilentlyContinue
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                Disconnect-AzureAD -ErrorAction SilentlyContinue
                
                # Remove any existing Exchange Online sessions
                Get-PSSession | Where-Object {
                    $_.ConfigurationName -eq "Microsoft.Exchange" -or 
                    $_.ComputerName -like "*.outlook.com"
                } | Remove-PSSession
                
                # Clear connection variables
                [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens.Clear()
                [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokenCache.Clear()
            }
            catch {
                Write-Warning "Error during connection reset: $_"
            }
        }

        try {
            # Validate UPN in scriptblock
            if ([string]::IsNullOrWhiteSpace($UPN)) {
                throw "User Principal Name is null or empty"
            }
            Start-Sleep -Milliseconds 1300
            # Import required modules and verify connections
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [1] Loading required modules:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
            #Write-RemediationLog "Loading required modules"
            # Load required modules
            $requiredModules = @(
                'Microsoft.Graph.Users',
                'Microsoft.Graph.Authentication',
                'Microsoft.Graph.Identity.SignIns',
                'ExchangeOnlineManagement',
                'MSOnline',
                'AzureAD'
            )
    
            foreach ($module in $requiredModules) {
                # Check for abort before each module load
                if ($cancellationToken.IsCancellationRequested) {
                    Test-ShouldContinueRemediation
                    return  # This line won't be reached due to the exception, but it's good practice
                }
                
                if (!(Get-Module -Name $module -ListAvailable)) {
                    & $writeOutputBox "  $([char]0x25E6) Installing module: $module"
                    Install-Module -Name $module -Force -AllowClobber
                }
                Import-Module $module -ErrorAction Stop
                & $writeOutputBox "  $([char]0x25E6) Loaded module: $module"
            }

            # Initialize progress tracking
            $totalSteps = 3  # Graph, Exchange, Azure AD
            $currentStep = 0
            
            $UpdateProgress = {
                param($step, $total, $status)
                $percentage = ($step / $total) * 100
                $ProgressBar.Dispatcher.Invoke([action] {
                    $ProgressBar.Visibility = 'Visible'
                    $ProgressBar.IsIndeterminate = $true
                    $ProgressBar.Value = $percentage
                    $ProgressTextBlock.Text = $status
                    $ProgressTextBlock.Visibility = 'Visible'
                    $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
                    $ProgressTextBlock.FontWeight = [System.Windows.FontWeights]::Bold
                })
            }
    
            # Reset progress bar for the main operations
            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressBar.Visibility = 'Visible'
                $ProgressBar.IsIndeterminate = $true
                $ProgressTextBlock.Text = "Initiating Lockdown Only..."
                $ProgressTextBlock.Visibility = 'Visible'
                $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
                $ProgressTextBlock.FontWeight = [System.Windows.FontWeights]::Bold
            })          
                    
            if (-not (Test-ShouldContinueRemediation)) { return }
            # 6. Remove Recent App Passwords
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [2] Checking for recently registered app passwords:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressTextBlock.Text = "Checking for recently registered app passwords..."
            })
            try {
                if (-not (Test-ShouldContinueRemediation)) { return }
                $user = Get-MgUser -UserId $UPN
                $appPasswords = Get-MgUserAuthenticationMethod -UserId $user.Id | Where-Object {$_.ODataType -eq "#microsoft.graph.passwordAuthenticationMethod"}
                $cutoffTime = (Get-Date).AddHours(-48)
                if (-not (Test-ShouldContinueRemediation)) {
                    return
                }
                if ($appPasswords) {
                    $recentAppPasswords = $appPasswords | Where-Object { $_.CreatedDateTime -ge $cutoffTime }
                    if (-not (Test-ShouldContinueRemediation)) { return }
                    if ($recentAppPasswords) {
                        foreach ($appPassword in $recentAppPasswords) {
                            Remove-MgUserAuthenticationMethod -UserId $user.Id -AuthenticationMethodId $appPassword.Id
                            & $writeOutputBox "  $([char]0x25E6) Deleted recent app password with ID $($appPassword.Id) (Created: $($appPassword.CreatedDateTime))"
                            #Write-RemediationLog "Deleted recent app password with ID $($appPassword.Id) (Created: $($appPassword.CreatedDateTime))"
                        }
                        if (-not (Test-ShouldContinueRemediation)) { return }
                        # Only export if we found app passwords
                        $exportPath = Join-Path $forensicsFolder "$UPN-AppPasswords.json"
                        $appPasswords | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportPath
                        & $writeOutputBox "  $([char]0x25E6) Exported app passwords data to: $exportPath"
                    } else {
                        & $writeOutputBox "  $([char]0x25E6) No app passwords found within the last 48 hours"
                    }
                } else {
                    & $writeOutputBox "  $([char]0x25E6) No app passwords found"
                }
            }
            catch {
                & $writeOutputBox "  $([char]0x25E6) Error removing app passwords: $_"
                throw
            }

            if (-not (Test-ShouldContinueRemediation)) { return }

            # 7. Disable Legacy Authentication Protocols
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [3] Disabling legacy authentication protocols:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
            #Write-RemediationLog "Disabling legacy authentication protocols"
            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressTextBlock.Text = "Disabling legacy protocols..."
            })
            # Replace the legacy protocol disabling section with this:
            try {
                # First, ensure we have an Exchange Online connection
                try {
                    $existingSession = Get-PSSession | Where-Object {$_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened"}
                    if (-not $existingSession) {
                        Connect-ExchangeOnline -ShowBanner:$false
                    }
                }
                catch {
                    & $writeOutputBox "  $([char]0x25E6) Error connecting to Exchange Online: $_"
                    throw
                }

                if (-not (Test-ShouldContinueRemediation)) { return }
                
                # Disable protocols using Exchange Online commands
                Set-CASMailbox -Identity $UPN `
                            -PopEnabled $false `
                            -ImapEnabled $false `
                            -ActiveSyncEnabled $false `
                            -MAPIEnabled $false `
                            -SmtpClientAuthenticationDisabled $true

                & $writeOutputBox "  $([char]0x25E6) Legacy protocols (POP, IMAP, MAPI, ActiveSync, SMTP) disabled"
            }
            catch {
                & $writeOutputBox "  $([char]0x25E6) Error disabling legacy protocols: $_"
                throw
            }

            if (-not (Test-ShouldContinueRemediation)) { return }
            # 8. Revoke OAuth App Permissions
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [4] Revoking OAuth app permissions:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressTextBlock.Text = "Revoking OAuth permissions..."
            })
            try {
                if (-not (Test-ShouldContinueRemediation)) { return }
                $recentOAuthGrants = Get-MgUserOauth2PermissionGrant -UserId $UPN
                if ($recentOAuthGrants) {
                    foreach ($grant in $recentOAuthGrants) {
                        $appName = (Get-MgApplication -ApplicationId $grant.ClientId).DisplayName
                        Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id
                        & $writeOutputBox "  $([char]0x25E6) Revoked permission for app: $appName"  
                    }
                } else {
                    & $writeOutputBox "  $([char]0x25E6) No OAuth permissions found"
                }
            }
            catch {
                & $writeOutputBox "  $([char]0x25E6) Error revoking OAuth permissions: $_"
                throw
            }

            if (-not (Test-ShouldContinueRemediation)) { return }

            # 9. Disable Recent Devices
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [5] Disabling recently registered devices:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressTextBlock.Text = "Disabling recent devices..."
            })
            try {
                $cutoffTime = (Get-Date).AddHours(-24)
                $recentDevices = Get-MgUserRegisteredDevice -UserId $UPN | Where-Object { $_.RegistrationDateTime -ge $cutoffTime }
                if (-not (Test-ShouldContinueRemediation)) { return }
                if ($recentDevices) {
                    foreach ($device in $recentDevices) {
                        Update-MgDevice -DeviceId $device.Id -AccountEnabled:$false
                        & $writeOutputBox "  $([char]0x25E6) Disabled recently registered device: $($device.DisplayName) (Registered: $($device.RegistrationDateTime))"
                    }

                    if (-not (Test-ShouldContinueRemediation)) { return }

                    # Export device data if found
                    $exportPath = Join-Path $forensicsFolder "$UPN-RecentDevices.json"
                    $recentDevices | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportPath
                    & $writeOutputBox "  $([char]0x25E6) Exported recent devices data to: $exportPath"  
                } else {
                    & $writeOutputBox "  $([char]0x25E6) No devices registered within the last 48 hours found"
                }
            }
            catch {
                & $writeOutputBox "  $([char]0x25E6) Error disabling recent devices: $_"
                throw
            }

            if (-not (Test-ShouldContinueRemediation)) { return }
            
            # 3. Block Sign-In
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [6] Blocking sign-in access:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressTextBlock.Text = "Blocking sign-in access..."
            })

            try {
                if (-not (Test-ShouldContinueRemediation)) { return }

                #Set-MsolUser -UserPrincipalName $UPN -BlockCredential $true -WarningAction SilentlyContinue
                Update-MgUser -UserId $UPN -AccountEnabled:$false
                & $writeOutputBox "  $([char]0x25E6) Sign-in blocked for $UPN"
            }
            catch {
                & $writeOutputBox "  $([char]0x25E6) Error blocking sign-in: $_"
                throw
            }
            if (-not (Test-ShouldContinueRemediation)) { return }
            # 5. Revoke Refresh Tokens
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [7] Revoking refresh tokens:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressTextBlock.Text = "Revoking tokens..."
            })

            try {
                if (-not (Test-ShouldContinueRemediation)) { return }
                
                # Updated to use correct cmdlet name
                Revoke-MgUserSignInSession -UserId $UPN
                & $writeOutputBox "  $([char]0x25E6) Successfully revoked refresh tokens"   
            }
            catch {
                & $writeOutputBox "  $([char]0x25E6) Error revoking refresh tokens: $_"
                throw
            }
            if (-not (Test-ShouldContinueRemediation)) { return }
            # 4. Reset Password
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [8] Resetting password:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

            $ProgressTextBlock.Dispatcher.Invoke([action] {
                $ProgressTextBlock.Text = "Resetting password..."
            })
            try {
                if (-not (Test-ShouldContinueRemediation)) { return } 
                # Generate a complex password (16 chars with at least 3 non-alphanumeric)
                $newPassword = [System.Web.Security.Membership]::GeneratePassword(16, 3)
                $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                
                # Try Azure AD cmdlet first
                try {
                    Set-AzureADUserPassword -ObjectId $UPN -Password $securePassword -ForceChangePasswordNextLogin $true
                }
                catch {
                    # Fallback to Microsoft Graph if Azure AD fails
                    $params = @{
                        "passwordProfile" = @{
                            "password" = $newPassword
                            "forceChangePasswordNextSignIn" = $true
                        }
                    }
                    Update-MgUser -UserId $UPN -BodyParameter $params -ErrorAction Stop
                }
                if (-not (Test-ShouldContinueRemediation)) { return }
                # Log success
                & $writeOutputBox "  $([char]0x25E6) Password reset successful"
                & $writeOutputBox "  $([char]0x25E6) New password: $newPassword"
            }
            catch {
                & $writeOutputBox "  $([char]0x25E6) Error resetting password: $_"
                throw
            }

            if (-not (Test-ShouldContinueRemediation)) { return }
            # Completion
            & $writeOutputBox "`n"
            & $writeOutputBox "=============================================================================================================="
            & $writeOutputBox "                              Remediation of $UPN is complete!"
            & $writeOutputBox "=============================================================================================================="
            $endTime = Get-Date
            $executionTime = New-TimeSpan -Start $startTime -End $endTime
            & $writeOutputBox "`r  $([char]0x25E6) Completion Time: $(Get-Date -Format 'MM/dd/yyyy hh:mm:ss tt')"
            & $writeOutputBox "  $([char]0x25E6) Execution Time: $($executionTime.TotalSeconds) seconds"
            & $writeOutputBox "=============================================================================================================="
            & $writeOutputBox " "
            Stop-Transcript | Out-Null

            $ProgressBar.Dispatcher.Invoke([action] {
                $ProgressBar.IsIndeterminate = $false
                $ProgressBar.Value = 100
                $ProgressTextBlock.Text = "Lockdown remediation complete"
                $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::White
            })
            
            # Disable the Abort menu item when remediation is complete
            $AbortMenuItem.Dispatcher.Invoke([Action]{
                $AbortMenuItem.IsEnabled = $false
            })
        }
        catch {
            if ($cancellationToken.IsCancellationRequested) {
                # Don't do anything here - let Test-ShouldContinueRemediation handle it
            } else {
                & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                & $writeOutputBox "ERROR: Lockdown process failed"
                & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                & $writeOutputBox "Error details: $_"
                & $writeOutputBox "Stack Trace: $($_.ScriptStackTrace)"
            }
            
            $ProgressBar.Dispatcher.Invoke([action] {
                $ProgressBar.IsIndeterminate = $false
                $ProgressBar.Value = 0
                $ProgressTextBlock.Text = if ($cancellationToken.IsCancellationRequested) { 
                    "Remediation aborted" 
                } else { 
                    "Error during lockdown" 
                }
                $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
            })
            
            # Disable the Abort menu item when remediation fails
            $AbortMenuItem.Dispatcher.Invoke([Action]{
                $AbortMenuItem.IsEnabled = $false
            })
        }
    }).AddArgument($UPN).AddArgument($OutputBox).AddArgument($ProgressBar).AddArgument($ProgressTextBlock).AddArgument($writeOutputBox).AddArgument($startTime).AddArgument($AbortMenuItem).AddArgument($script:remediationCancellationSource.Token).AddArgument($forensicsFolder).AddArgument($logFile).AddArgument($formattedDate)
  
    $runspace.RunspacePool = $global:RunspacePool
    
    $script:currentRemediationRunspace = @{
        PowerShell = $runspace
        Handle = $runspace.BeginInvoke()
    }
    
    return $script:currentRemediationRunspace
}

function Start-LockdownComprehensiveUser {
    $UPN = $TargetUPN.Text.Trim()
    
    function Write-EnhancedLog {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Message,
            
            [Parameter()]
            [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG", "SUCCESS")]
            [string]$Category = "INFO",
            
            [Parameter()]
            [switch]$WriteToFile
        )
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Category] $Message"
        
        # Color coding for console output
        $color = switch ($Category) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            "DEBUG" { "Cyan" }
            default { "White" }
        }
        
        Write-Host $logEntry -ForegroundColor $color
        
        if ($WriteToFile -and $script:logpath) {
            $logFile = Join-Path $script:logpath "FSIR-Enhanced-$(Get-Date -Format 'yyyyMMdd').log"
            $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
        }
    }
    
    # Clear the output box first
    $OutputBox.Dispatcher.Invoke([action] { $OutputBox.Clear() })
    
    $AbortMenuItem.Dispatcher.Invoke([Action]{
        $AbortMenuItem.IsEnabled = $true
        $AbortMenuItem.Visibility = 'Visible' # Make sure it's visible too
    })

    # Enhanced UPN validation with security checks
    if ([string]::IsNullOrWhiteSpace($UPN)) {
        [System.Windows.MessageBox]::Show("Please enter a valid User Principal Name.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return
    }
    
    # Validate UPN format and security
    if (-not (Test-InputSafety -InputText $UPN -InputType "UPN")) {
        [System.Windows.MessageBox]::Show("Invalid or potentially unsafe UPN format. Please check the input.", "Security Warning", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        Write-EnhancedLog -Message "UPN validation failed for input: $UPN" -Category "WARNING" -WriteToFile
        return
    }
    
    Write-EnhancedLog -Message "UPN validation successful for: $UPN" -Category "SUCCESS" -WriteToFile

    $writeOutputBox = {
        param([string]$text)
        $OutputBox.Dispatcher.Invoke([action] {
            $OutputBox.AppendText("$text`r`n")
            $OutputBox.ScrollToEnd()
        })
        # Also writes to transcript
        Write-Host $text
    }

    
    # Initialize timestamps and create forensics folder
    $date = Get-Date
    $formattedDate = $date.ToString("MMMM") + $date.ToString(" d") + $date.ToString(" @ h:mmtt").ToLower()
    $startTime = Get-Date
    $transcriptDirectory = ".\output\transcripts"
    $logDirectory = ".\output\logs"
    $forensicsFolder = ".\output\Forensics\$UPN"
    $transcriptFile = Join-Path $transcriptDirectory "MITS-Remediate-$(Get-Date -Format 'MMddyy_hhmmtt')-$UPN-Lockdown-Forensics.log"
    $logFile = Join-Path $logDirectory "MITS-Remediate-$(Get-Date -Format 'MMddyy_hhmmtt')-$UPN-Lockdown-Forensics.log"
    
    # Ensure directories exist
    @($transcriptDirectory, $logDirectory, $forensicsFolder) | ForEach-Object {
        if (-not (Test-Path -Path $_)) {
            New-Item -Path $_ -ItemType Directory -Force | Out-Null
        }
    }

    & $writeOutputBox "=============================================================================================================="
    # Calculate padding for centering
    $message = "Processing account lockdown and forensics for $UPN on $formattedDate"
    $totalWidth = 102  # Width of the separator line
    $padding = [math]::Max(0, [math]::Floor(($totalWidth - $message.Length) / 2))
    $centeredMessage = (" " * $padding) + $message
    & $writeOutputBox $centeredMessage
    & $writeOutputBox "=============================================================================================================="
    
    
    
    #& $writeOutputBox "`r User Principal Name: $UPN"
    #& $writeOutputBox " `r  Remediation Start: $(Get-Date -Format 'MM/dd/yyyy hh:mm tt')"
    #& $writeOutputBox "  Remediation Mode: Lockdown w/ Forensics"
    #& $writeOutputBox "  Target User: $UPN"
    
    #Write-RemediationLog "$([char]0x25E6) Starting Lockdown w/ Forensics remediation for $UPN on $formattedDate" -Level Info


    
    # Initialize progress bar
    $ProgressBar.Dispatcher.Invoke([action] {
        $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
        $ProgressTextBlock.FontWeight = [System.Windows.FontWeights]::Bold
        $ProgressBar.Visibility = 'Visible'
        $ProgressBar.IsIndeterminate = $true
        $ProgressTextBlock.Visibility = 'Visible'
        $ProgressTextBlock.Text = "Processing Lockdown w/ Forensics Request..."
    })

    $scriptBlock = {
        param($UPN, $OutputBox, $ProgressBar, $ProgressTextBlock, $writeOutputBox, $forensicsFolder, 
              $startTime, $transcriptFile, $cancellationToken, $syncHash, $StatusTextBlock, $logFile)
        
        # Define Write-EnhancedLog function within the script block scope
        function Write-EnhancedLog {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$Message,
                
                [Parameter()]
                [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG", "SUCCESS")]
                [string]$Category = "INFO",
                
                [Parameter()]
                [switch]$WriteToFile
            )
            
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logEntry = "[$timestamp] [$Category] $Message"
            
            # Color coding for console output
            $color = switch ($Category) {
                "ERROR" { "Red" }
                "WARNING" { "Yellow" }
                "SUCCESS" { "Green" }
                "DEBUG" { "Cyan" }
                default { "White" }
            }
            
            Write-Host $logEntry -ForegroundColor $color
            
            if ($WriteToFile) {
                $logpath = "C:\temp\FSIR\Output\logs"
                if (-not (Test-Path -Path $logpath)) {
                    New-Item -Path $logpath -ItemType Directory -Force | Out-Null
                }
                $logFile = Join-Path $logpath "FSIR-Enhanced-$(Get-Date -Format 'yyyyMMdd').log"
                $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
            }
        }
        
        # Define Get-IncidentResponseRecommendations function within the script block scope
        function Get-IncidentResponseRecommendations {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [hashtable]$ThreatHuntingResults,
                
                [Parameter(Mandatory = $true)]
                [string]$UPN
            )
            
            $recommendations = @()
            
            switch ($ThreatHuntingResults.ThreatLevel) {
                "Critical" {
                    $recommendations += "IMMEDIATE: Disable user account pending investigation"
                    $recommendations += "IMMEDIATE: Reset user password and revoke all sessions"
                    $recommendations += "IMMEDIATE: Contact security team and management"
                    $recommendations += "Review all administrative actions performed by this user"
                    $recommendations += "Check for lateral movement to other accounts"
                    $recommendations += "Consider forensic imaging of user's devices"
                }
                
                "High" {
                    $recommendations += "Reset user password and revoke active sessions"
                    $recommendations += "Enable additional monitoring for this user"
                    $recommendations += "Review and validate all recent user activities"
                    $recommendations += "Consider temporary access restrictions"
                    $recommendations += "Notify security team for further investigation"
                }
                
                "Medium" {
                    $recommendations += "Schedule security awareness training for user"
                    $recommendations += "Review and update user permissions"
                    $recommendations += "Monitor user activities for next 30 days"
                    $recommendations += "Consider multi-factor authentication enforcement"
                }
                
                "Low" {
                    $recommendations += "Document findings for future reference"
                    $recommendations += "Consider periodic security check-ins"
                    $recommendations += "Review general security policies"
                }
                
                default {
                    $recommendations += "Continue standard security monitoring"
                    $recommendations += "Maintain current security practices"
                }
            }
            
            return $recommendations
        }
        
        # Define the nested Invoke-ThreatHunting function
        function Invoke-ThreatHunting {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$ForensicsPath,
                
                [Parameter(Mandatory = $true)]
                [string]$UPN
            )
            
            Write-EnhancedLog -Message "Starting threat hunting analysis for $UPN..." -Category "INFO" -WriteToFile
            
            $findings = @()
            $threatScore = 0
            
            try {
                # IOC patterns to search for
                $iocPatterns = @{
                    "SuspiciousEmails" = @(
                        "urgent.*action.*required",
                        "verify.*account.*immediately", 
                        "click.*here.*now",
                        "suspicious.*activity.*detected",
                        "account.*will.*be.*suspended"
                    )
                    "MaliciousDomains" = @(
                        "bit\.ly",
                        "tinyurl\.com", 
                        "t\.co",
                        "goo\.gl",
                        ".*\.tk$",
                        ".*\.ml$"
                    )
                    "SuspiciousIPs" = @(
                        "^10\.",          # Private networks (could be tunneling)
                        "^172\.16\.",     # Private networks
                        "^192\.168\.",    # Private networks
                        "^127\.",         # Localhost (suspicious in logs)
                        "^169\.254\."     # APIPA addresses
                    )
                }
                
                # Analyze audit logs if available
                $auditFiles = Get-ChildItem -Path $ForensicsPath -Filter "*AuditLog*.csv" -ErrorAction SilentlyContinue
                foreach ($auditFile in $auditFiles) {
                    Write-EnhancedLog -Message "Analyzing audit log: $($auditFile.Name)" -Category "INFO"
                    
                    try {
                        $auditData = Import-Csv -Path $auditFile.FullName
                        
                        # Check for suspicious login patterns
                        $suspiciousLogins = $auditData | Where-Object {
                            $_.Operation -like "*Login*" -and (
                                $_.ClientIP -match "^(?!10\.|172\.16\.|192\.168\.)" -or  # External IPs
                                $_.ClientIP -match "TOR|Proxy" -or
                                $_.UserAgent -like "*bot*" -or
                                $_.ResultStatus -eq "Failed"
                            )
                        }
                        
                        if ($suspiciousLogins) {
                            $finding = [PSCustomObject]@{
                                Type = "Suspicious Login Attempts"
                                Severity = "Medium"
                                Count = $suspiciousLogins.Count
                                Details = $suspiciousLogins | Select-Object -First 5
                                Recommendation = "Review login attempts from external/suspicious IPs"
                            }
                            $findings += $finding
                            $threatScore += 25
                        }
                        
                        # Check for unusual administrative actions
                        $adminActions = $auditData | Where-Object {
                            $_.Operation -match "Add|Remove|Update|Delete" -and
                            $_.WorkLoad -eq "AzureActiveDirectory"
                        }
                        
                        if ($adminActions.Count -gt 10) {
                            $finding = [PSCustomObject]@{
                                Type = "High Volume Administrative Actions"
                                Severity = "High"
                                Count = $adminActions.Count
                                Details = $adminActions | Select-Object -First 5
                                Recommendation = "Review administrative changes for unauthorized modifications"
                            }
                            $findings += $finding
                            $threatScore += 50
                        }
                        
                    }
                    catch {
                        Write-EnhancedLog -Message "Error analyzing audit file $($auditFile.Name): $_" -Category "ERROR"
                    }
                }
                
                # Analyze message trace data
                $messageFiles = Get-ChildItem -Path $ForensicsPath -Filter "*MessageTrace*.csv" -ErrorAction SilentlyContinue
                foreach ($messageFile in $messageFiles) {
                    Write-EnhancedLog -Message "Analyzing message trace: $($messageFile.Name)" -Category "INFO"
                    
                    try {
                        $messageData = Import-Csv -Path $messageFile.FullName
                        
                        # Check for suspicious email patterns
                        $suspiciousEmails = $messageData | Where-Object {
                            $subject = $_.Subject
                            $iocPatterns["SuspiciousEmails"] | ForEach-Object {
                                if ($subject -match $_) { return $true }
                            }
                            return $false
                        }
                        
                        if ($suspiciousEmails) {
                            $finding = [PSCustomObject]@{
                                Type = "Suspicious Email Subjects"
                                Severity = "Medium"
                                Count = $suspiciousEmails.Count
                                Details = $suspiciousEmails | Select-Object Subject, SenderAddress -First 5
                                Recommendation = "Review emails with suspicious subject patterns"
                            }
                            $findings += $finding
                            $threatScore += 30
                        }
                        
                        # Check for high-volume external senders
                        $externalSenders = $messageData | Where-Object {
                            $_.SenderAddress -notlike "*$($UPN.Split('@')[1])*"
                        } | Group-Object SenderAddress | Where-Object { $_.Count -gt 50 }
                        
                        if ($externalSenders) {
                            $finding = [PSCustomObject]@{
                                Type = "High Volume External Senders"
                                Severity = "Low"
                                Count = $externalSenders.Count
                                Details = $externalSenders | Select-Object Name, Count -First 5
                                Recommendation = "Review high-volume external email sources"
                            }
                            $findings += $finding
                            $threatScore += 15
                        }
                        
                    }
                    catch {
                        Write-EnhancedLog -Message "Error analyzing message file $($messageFile.Name): $_" -Category "ERROR"
                    }
                }
                
                # Generate threat assessment report
                $threatLevel = switch ($threatScore) {
                    { $_ -gt 100 } { "Critical" }
                    { $_ -gt 60 } { "High" }
                    { $_ -gt 30 } { "Medium" }
                    { $_ -gt 10 } { "Low" }
                    default { "Minimal" }
                }
                
                $reportPath = Join-Path $ForensicsPath "ThreatHuntingReport.html"
                $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>FSIR Threat Hunting Report - $UPN</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 15px; border-radius: 5px; }
        .threat-level { padding: 10px; margin: 10px 0; border-radius: 5px; font-weight: bold; }
        .critical { background-color: #e74c3c; color: white; }
        .high { background-color: #f39c12; color: white; }
        .medium { background-color: #f1c40f; color: black; }
        .low { background-color: #27ae60; color: white; }
        .minimal { background-color: #95a5a6; color: white; }
        .finding { border: 1px solid #bdc3c7; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .severity-high { border-left: 5px solid #e74c3c; }
        .severity-medium { border-left: 5px solid #f39c12; }
        .severity-low { border-left: 5px solid #27ae60; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #bdc3c7; padding: 8px; text-align: left; }
        th { background-color: #ecf0f1; }
    </style>
</head>
<body>
    <div class="header">
        <h1>FSIR Threat Hunting Report</h1>
        <p>User: $UPN | Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Threat Score: $threatScore</p>
    </div>
    
    <div class="threat-level $($threatLevel.ToLower())">
        Overall Threat Level: $threatLevel
    </div>
    
    <h2>Executive Summary</h2>
    <p>This report contains the results of automated threat hunting analysis performed on forensic data for user $UPN. 
    A total of $($findings.Count) potential security findings were identified with an overall threat score of $threatScore.</p>
    
    <h2>Detailed Findings</h2>
"@
                
                if ($findings.Count -eq 0) {
                    $htmlReport += "<p>No significant security threats detected in the analyzed data.</p>"
                } else {
                    foreach ($finding in $findings) {
                        $severityClass = "severity-$($finding.Severity.ToLower())"
                        $htmlReport += @"
    <div class="finding $severityClass">
        <h3>$($finding.Type)</h3>
        <p><strong>Severity:</strong> $($finding.Severity)</p>
        <p><strong>Count:</strong> $($finding.Count)</p>
        <p><strong>Recommendation:</strong> $($finding.Recommendation)</p>
    </div>
"@
                    }
                }
                
                $htmlReport += @"
    
    <h2>Recommendations</h2>
    <ul>
        <li>Review all identified findings in detail</li>
        <li>Correlate findings with other security tools and logs</li>
        <li>Consider implementing additional monitoring for suspicious patterns</li>
        <li>Update security policies based on identified vulnerabilities</li>
    </ul>
    
    <p><em>Generated by FSIR Toolkit v$($script:ScriptVersion)</em></p>
</body>
</html>
"@
                
                $htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
                Write-EnhancedLog -Message "Threat hunting report generated: $reportPath" -Category "SUCCESS" -WriteToFile
                Write-EnhancedLog -Message "Threat hunting analysis completed. Threat Level: $threatLevel (Score: $threatScore)" -Category "INFO" -WriteToFile
                
                return @{
                    ThreatLevel = $threatLevel
                    ThreatScore = $threatScore
                    FindingsCount = $findings.Count
                    ReportPath = $reportPath
                    Findings = $findings
                }
                
            }
            catch {
                Write-EnhancedLog -Message "Error during threat hunting analysis: $_" -Category "ERROR" -WriteToFile
                throw
            }
        }
        try {
            # Start transcript at the beginning of the runspace
            if (Test-Path $transcriptFile) {
                Remove-Item $transcriptFile -Force
            }
            Start-Transcript -Path $transcriptFile -Force
            Write-Host "=============================================================================================================="
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting lockdown and forensic operations for $UPN"
            Write-Host "=============================================================================================================="
        }
        catch {
            & $writeOutputBox "Error starting transcript: $_" $logFile
        }
    
        function Write-RemediationLog {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory=$true)]
                [string]$Message,
                
                [Parameter(Mandatory=$false)]
                [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
                [string]$Level = 'Info'
            )
            
            # Create timestamp
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            
            # Format the log message
            $formattedMessage = "[$timestamp] [$Level] $Message"
            
            # Write to log file
            Add-Content -Path $logFile -Value $formattedMessage
            
            # Write to transcript based on level
            switch ($Level) {
                'Warning' { Write-Warning $Message }
                'Error'   { Write-Error $Message -ErrorAction Continue }
                'Debug'   { Write-Verbose $Message }
                default   { Write-Host $formattedMessage }
            }
        }
    
        
        function Test-ShouldContinueRemediation {
            # Check both the sync hash and cancellation token
            if ($syncHash.abortFlag -or $cancellationToken.IsCancellationRequested) {
                # Add a small delay to ensure messages are written in order
                Start-Sleep -Milliseconds 500
                
                # Only write the message once when aborting
                if (-not $script:abortMessageDisplayed) {
                    #& $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                    & $writeOutputBox "`r`n  $([char]0x25E6) Remediation process aborted successfully!"
                    #& $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                    Write-RemediationLog "Remediation process aborted successfully!" -Level Info
                    $script:abortMessageDisplayed = $true
                }
                $ProgressTextBlock.Dispatcher.Invoke([action] {
                    $ProgressTextBlock.Text = "Remediation aborted"
                    $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
                    $ProgressBar.IsIndeterminate = $false
                    $ProgressBar.Value = 0
                })
                
                # Disable the Abort menu item
                $AbortMenuItem.Dispatcher.Invoke([Action]{
                    $AbortMenuItem.IsEnabled = $false
                })
        
                # Throw a terminating exception to immediately stop execution
                throw New-Object System.OperationCanceledException("Remediation aborted by user")
            }
            return $true
        }

        try {
            # Validate UPN in scriptblock
            if ([string]::IsNullOrWhiteSpace($UPN)) {
                throw "User Principal Name is null or empty"
            }
            & $writeOutputBox "`r  $([char]0x25E6) User Principal Name: $UPN"
            & $writeOutputBox "  $([char]0x25E6) Remediation Start: $(Get-Date -Format 'MM/dd/yyyy hh:mm tt')"
            & $writeOutputBox "  $([char]0x25E6) Remediation Mode: Forensics Only"
            & $writeOutputBox "  $([char]0x25E6) Forensics folder: $forensicsFolder"
            Start-Sleep -Milliseconds 1300
            # 1. Import required modules and verify connections
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [1] Loading required modules:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

            # Load required modules
            $requiredModules = @(
                'Microsoft.Graph.Users',
                'Microsoft.Graph.Authentication',
                'Microsoft.Graph.Identity.SignIns',
                'ExchangeOnlineManagement',
                'MSOnline',
                'AzureAD'
            )
    
            foreach ($module in $requiredModules) {
                if (!(Get-Module -Name $module -ListAvailable)) {
                    & $writeOutputBox "  $([char]0x25E6) Installing module: $module"
                    Install-Module -Name $module -Force -AllowClobber
                }
                Import-Module $module -ErrorAction Stop
                & $writeOutputBox "  $([char]0x25E6) Loaded module: $module"
            }
    
            # Initialize progress tracking
            $totalSteps = 3  # Graph, Exchange, Azure AD
            $currentStep = 0
            
            $UpdateProgress = {
                param($step, $total, $status)
                $percentage = ($step / $total) * 100
                $ProgressBar.Dispatcher.Invoke([action] {
                    $ProgressBar.Visibility = 'Visible'
                    $ProgressBar.IsIndeterminate = $true
                    $ProgressBar.Value = $percentage
                    $ProgressTextBlock.Text = $status
                    $ProgressTextBlock.Visibility = 'Visible'
                    $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
                    $ProgressTextBlock.FontWeight = [System.Windows.FontWeights]::Bold
                })
            }
    
            # 2. Verify/Import Exchange Online connection
            #& $UpdateProgress $currentStep $totalSteps "Connecting to Exchange Online..."
            # Replace the Exchange Online connection check (around line 112) with:
            # At the start of the scriptblock in Lockdown-ComprehensiveUser2
        
            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
            & $writeOutputBox " [2] Verifying service connection:"
            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"

            try {
                $existingSession = Get-PSSession | Where-Object {$_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened"}
                if ($existingSession) {
                    Import-PSSession $existingSession -AllowClobber -DisableNameChecking | Out-Null
                    #& $writeOutputBox "  $([char]0x25E6) Using existing Exchange Online connection"
                } else {
                    #& $writeOutputBox "  $([char]0x25E6) Connecting to Exchange Online..."
                    Connect-ExchangeOnline -ShowBanner:$false -UseMultithreading:$true
                    & $writeOutputBox "  $([char]0x25E6) Connected to Exchange Online"
                }
            } catch {
                & $writeOutputBox "  $([char]0x25E6) Error connecting to Exchange Online: $_"
                throw
            }
    
            # Verify/Import Azure AD connection
            #& $UpdateProgress $currentStep $totalSteps "Connecting to Azure AD..."
            try {
                $null = Get-AzureADTenantDetail -ErrorAction Stop
                & $writeOutputBox "  $([char]0x25E6) Connected to AzureAD"
            } catch {
                & $writeOutputBox "  $([char]0x25E6) Connecting to Azure AD..."
                Connect-AzureAD
                & $writeOutputBox "  $([char]0x25E6) Connected to Azure AD"
            }
            $currentStep++
            & $UpdateProgress $currentStep $totalSteps "Azure AD connected"
    
            # Verify/Import Microsoft Graph connection
            if (-not (Get-MgContext)) {
                if (-not (Test-ShouldContinueRemediation)) { return }
                
                try {
                    & $writeOutputBox "  $([char]0x25E6) Connecting to Microsoft Graph..."
                    Connect-MgGraph -Scopes @(
                        "User.ReadWrite.All",
                        "Directory.ReadWrite.All",
                        "User.Read.All",
                        "Organization.Read.All",
                        "Policy.Read.All",
                        "Mail.ReadWrite",
                        "UserAuthenticationMethod.ReadWrite.All",
                        "MailboxSettings.Read.All"
                    )
                    & $writeOutputBox "  $([char]0x25E6) Connected to Microsoft Graph"
                } catch {
                    # Check if this is a user cancellation
                    if ($_.Exception.Message -like "*User canceled authentication*" -or 
                        $_.Exception.Message -like "*canceled*" -or 
                        $_.Exception.Message -like "*cancelled*") {
                        
                        $syncHash.abortFlag = $true
                        $script:remediationCancellationSource.Cancel()
                        
                        if (-not (Test-ShouldContinueRemediation)) { return }
                    } else {
                        & $writeOutputBox "  $([char]0x25E6) Error connecting to Microsoft Graph: $_"
                        throw
                    }
                }
            } else {
                & $writeOutputBox "  $([char]0x25E6) Connected to Microsoft Graph"
            }
            
            if (-not (Test-ShouldContinueRemediation)) { return }
            
            $currentStep++
            & $UpdateProgress $currentStep $totalSteps "All services connected"
            
                Start-Sleep -Seconds 1
                function Convert-AuditLog {
                    param(
                        [Parameter(Mandatory=$true)]
                        [string]$UPN,
                        [string]$ForensicsFolder
                    )
                    
                    & $writeOutputBox "  $([char]0x25E6) Converting audit log: $ForensicsFolder\$UPN-AuditLog-Last30Days.csv"
                    $inputCsv = "$ForensicsFolder\$UPN-AuditLog-Last30Days.csv"
                    
                    if (-Not (Test-Path $inputCsv)) {
                        & $writeOutputBox "  $([char]0x25E6) Audit log file does not exist: $inputCsv"
                        return
                    }
                
                    # Extract directory and filename from the input path
                    $directory = Split-Path -Path $inputCsv -Parent
                    $filename = [System.IO.Path]::GetFileNameWithoutExtension($inputCsv)
                    $extension = [System.IO.Path]::GetExtension($inputCsv)
                
                    # Define the new filename with '-Processed' appended
                    $newFilename = "${filename}-Processed${extension}"
                    $outputCsv = Join-Path -Path $directory -ChildPath $newFilename
                
                    try {
                        # Read the CSV file
                        $data = Import-Csv -Path $inputCsv
                
                        # Initialize an array to store the extracted data
                        $extractedData = @()
                
                        # Loop through each row in the CSV file
                        foreach ($row in $data) {
                            # Parse the JSON data in the 'AuditData' column
                            $auditData = $row.AuditData | ConvertFrom-Json
                
                            # Extract the necessary fields
                            $extractedRow = [PSCustomObject]@{
                                CCreationTime = $auditData.CreationTime
                                Id = $auditData.Id
                                Operation = $auditData.Operation
                                OrganizationId = $auditData.OrganizationId
                                RecordType = $auditData.RecordType
                                ResultStatus = $auditData.ResultStatus
                                UserKey = $auditData.UserKey
                                UserType = $auditData.UserType
                                Version = $auditData.Version
                                Workload = $auditData.Workload
                                UserId = $auditData.UserId
                                AppId = $auditData.AppId
                                ClientAppId = $auditData.ClientAppId
                                ClientIPAddress = $auditData.ClientIPAddress
                                ClientInfoString = $auditData.ClientInfoString
                                ExternalAccess = $auditData.ExternalAccess
                                InternalLogonType = $auditData.InternalLogonType
                                LogonType = $auditData.LogonType
                                LogonUserSid = $auditData.LogonUserSid
                                MailboxGuid = $auditData.MailboxGuid
                                MailboxOwnerSid = $auditData.MailboxOwnerSid
                                MailboxOwnerUPN = $auditData.MailboxOwnerUPN
                                MailAccessType = ($auditData.OperationProperties | Where-Object { $_.Name -eq 'MailAccessType' }).Value
                                IsThrottled = ($auditData.OperationProperties | Where-Object { $_.Name -eq 'IsThrottled' }).Value
                                OrganizationName = $auditData.OrganizationName
                                OriginatingServer = $auditData.OriginatingServer
                                SessionId = $auditData.SessionId
                                FolderPath = $null
                                FolderItemsId = $null
                                FolderItemsInternetMessageId = $null
                                FolderItemsSizeInBytes = $null
                                OperationCount = $auditData.OperationCount
                            }
                
                            # Add the extracted row to the array
                            $extractedData += $extractedRow
                        }
                
                        # Export the extracted data to the new CSV file
                        $extractedData | Export-Csv -Path $outputCsv -NoTypeInformation
                        & $writeOutputBox "  $([char]0x25E6) Successfully converted audit log to: $newFilename"
                    }
                    catch {
                        & $writeOutputBox "  $([char]0x25E6) Error converting audit log: $_"
                    }
                }

                # Reset progress bar for the main operations
                $ProgressTextBlock.Dispatcher.Invoke([action] {
                    $ProgressBar.Visibility = 'Visible'
                    $ProgressBar.IsIndeterminate = $true
                    $ProgressTextBlock.Text = "Initiating Lockdown w/ Forensics..."
                    $ProgressTextBlock.Visibility = 'Visible'
                    $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
                    $ProgressTextBlock.FontWeight = [System.Windows.FontWeights]::Bold
                })          

                        
            
                        # 3. Disable Forwarding Rules
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [3] Disabling mail forwarding rules:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                        #Write-RemediationLog "Disabling mail forwarding rules" -Level Info
                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Disabling forwarding rules..."
                        })
                        try {
                            $rules = Get-InboxRule -Mailbox $UPN | Where-Object {
                                (($_.Enabled -eq $true) -and 
                                ($null -ne $_.ForwardTo -or
                                $null -ne $_.ForwardAsAttachmentTo -or
                                $null -ne $_.RedirectTo -or
                                $null -ne $_.SendTextMessageNotificationTo))
                            }
                            if ($rules) {
                                $rules | Disable-InboxRule
                                & $writeOutputBox "  $([char]0x25E6) Disabled $(($rules | Measure-Object).Count) forwarding rules"
                                #Write-RemediationLog "Disabled $(($rules | Measure-Object).Count) forwarding rules" -Level Info
                                $rules | ForEach-Object {
                                    & $writeOutputBox "  $([char]0x25E6) Disabled rule: $($_.Name)"
                                }
                            } else {
                                & $writeOutputBox "  $([char]0x25E6) No active forwarding rules found"
                                #Write-RemediationLog "No active forwarding rules found" -Level Info
                            }
                        }
                        catch {
                            & $writeOutputBox "  $([char]0x25E6) Error disabling forwarding rules: $_"
                            #Write-RemediationLog "Error disabling forwarding rules: $_" -Level Error
                        }
                        
                        <# 3. Add MITS Admin Access
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [3] Adding admin access:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Adding admin access..."
                        })
                        try {
                            $Domain = (Get-AcceptedDomain | Where-Object {$_.Default -eq $true} | Select-Object -ExpandProperty DomainName)
                            $MITSAdmin = "mitsadmin@$Domain"
                            Add-MailboxPermission -Identity $UPN -User $MITSAdmin -AccessRights FullAccess -InheritanceType All -Confirm:$false -WarningAction SilentlyContinue
                            & $writeOutputBox "  $([char]0x25E6) Added full access for $MITSAdmin"
                        }
                        catch {
                            & $writeOutputBox "  $([char]0x25E6) Error adding admin access: $_"
                        }
                        #>

                        # 4. Message Trace
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [4] Running message trace:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Running message trace..."
                        })
                        try {
                            $StartDate = (Get-Date).AddDays(-10)
                            $EndDate = Get-Date

                            # Get inbound messages
                            $inboundTrace = Get-MessageTrace -RecipientAddress $UPN -StartDate $StartDate -EndDate $EndDate
                            
                            # Get outbound messages
                            $outboundTrace = Get-MessageTrace -SenderAddress $UPN -StartDate $StartDate -EndDate $EndDate
                            
                            # Export inbound messages if found
                            if ($inboundTrace) {
                                $inboundTrace | Export-Csv -Path "$forensicsFolder\$UPN-InboundMessageTrace.csv" -NoTypeInformation
                                & $writeOutputBox "  $([char]0x25E6) Exported $(($inboundTrace | Measure-Object).Count) inbound message trace items"
                                
                                # Show top 5 senders
                                $topSenders = $inboundTrace | Group-Object SenderAddress | Sort-Object Count -Descending | Select-Object -First 5
                                & $writeOutputBox "`r  Top 5 message senders:"
                                foreach ($sender in $topSenders) {
                                    & $writeOutputBox "    - $($sender.Name): $($sender.Count) messages"
                                }
                            } else {
                                & $writeOutputBox "  $([char]0x25E6) No inbound message trace items found"
                            }
                            
                            # Export outbound messages if found
                            if ($outboundTrace) {
                                $outboundTrace | Export-Csv -Path "$forensicsFolder\$UPN-OutboundMessageTrace.csv" -NoTypeInformation
                                & $writeOutputBox "`r  $([char]0x25E6) Exported $(($outboundTrace | Measure-Object).Count) outbound message trace items"
                                
                                # Show top 5 recipients
                                $topRecipients = $outboundTrace | Group-Object RecipientAddress | Sort-Object Count -Descending | Select-Object -First 5
                                & $writeOutputBox "`r  Top 5 message recipients:"
                                foreach ($recipient in $topRecipients) {
                                    & $writeOutputBox "    - $($recipient.Name): $($recipient.Count) messages"
                                }
                            } else {
                                & $writeOutputBox "  $([char]0x25E6) No outbound message trace items found"
                            }
                            
                            # Calculate total message count
                            $totalMessages = ($inboundTrace | Measure-Object).Count + ($outboundTrace | Measure-Object).Count
                            & $writeOutputBox "`r  $([char]0x25E6) Total messages processed: $totalMessages"
                            
                        }
                        catch {
                            & $writeOutputBox "  $([char]0x25E6) Error running message trace: $_"
                            & $writeOutputBox "  $([char]0x25E6) Stack Trace: $($_.ScriptStackTrace)"
                        }

                        # 5. Export and Convert Audit Log
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [5] Exporting audit logs:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                        #Write-RemediationLog "Exporting audit logs" -Level Info
                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Exporting audit logs..."
                        })
                        try {
                            $SessionId = [guid]::NewGuid().ToString()
                            $ResultSize = 5000
                            $AllResults = @()
                            
                            do {
                                $Results = Search-UnifiedAuditLog -UserIds $UPN -StartDate $StartDate -EndDate $EndDate -SessionId $SessionId -SessionCommand ReturnLargeSet -ResultSize $ResultSize
                                if ($Results) {
                                    $AllResults += $Results
                                    & $writeOutputBox "  $([char]0x25E6) Retrieved $($Results.Count) audit log entries..."
                                }
                                Start-Sleep -Seconds 2
                            } while ($Results.Count -eq $ResultSize)
                            
                            # In the audit log export section:
                            if ($AllResults.Count -gt 0) {
                                $filename = "$UPN-AuditLog-Last30Days.csv"
                                $outputPath = Join-Path -Path $forensicsFolder -ChildPath "$filename"
                                $AllResults | Export-Csv -Path $outputPath -NoTypeInformation
                                & $writeOutputBox "  $([char]0x25E6) Exported $($AllResults.Count) total audit log entries"
                                Convert-AuditLog -UPN $UPN -ForensicsFolder $forensicsFolder
                            } else {
                                & $writeOutputBox "  $([char]0x25E6) No audit log entries found"
                                #Write-RemediationLog "No audit log entries found" -Level Info
                            }
                        }
                        catch {
                            & $writeOutputBox "  $([char]0x25E6) Error exporting audit logs: $_"
                            #Write-RemediationLog "Error exporting audit logs: $_" -Level Error
                        }

                        # 6. Export Forensics Data
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [6] Collecting forensics data:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                        #Write-RemediationLog "Collecting forensics data" -Level Info
                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Collecting forensics data..."
                        })

                        $forensicsOperations = @(
                            @{ Name = "Mailbox settings"; Cmdlet = { Get-Mailbox -Identity $UPN }; File = "mailbox.xml" },
                            @{ Name = "Inbox rules"; Cmdlet = { Get-InboxRule -Mailbox $UPN }; File = "inboxrules.xml" },
                            @{ Name = "Calendar folder"; Cmdlet = { Get-MailboxCalendarFolder -Identity "$UPN`:\Calendar" }; File = "MailboxCalendarFolder.xml" },
                            @{ Name = "Mailbox delegates"; Cmdlet = { Get-MailboxPermission -Identity $UPN | Where-Object { ($_.IsInherited -ne $true) -and ($_.User -notlike "*SELF*") } }; File = "MailboxDelegates.xml" },
                            @{ Name = "Registered devices"; Cmdlet = { Get-MgUserRegisteredDevice -UserId $UPN }; File = "registeredDevices.xml" },
                            @{ Name = "Mail folders"; Cmdlet = { Get-MgUserMailFolder -UserId $UPN }; File = "mailFolders.xml" },
                            @{ Name = "Owned devices"; Cmdlet = { Get-MgUserOwnedDevice -UserId $UPN }; File = "ownedDevices.xml" },
                            @{ Name = "Group memberships"; Cmdlet = { Get-MgUserMemberOf -UserId $UPN }; File = "groupMemberships.xml" },
                            @{ Name = "App role assignments"; Cmdlet = { Get-MgUserAppRoleAssignment -UserId $UPN }; File = "appRoleAssignments.xml" },
                            @{ 
                                Name = "Mobile devices"; 
                                Cmdlet = { 
                                    try {
                                        $devices = Get-MobileDevice -Mailbox $UPN -ErrorAction Stop |
                                            Select-Object DeviceId, DeviceType, DeviceModel, DeviceOS, 
                                                FirstSyncTime, LastSyncTime, DeviceAccessState, 
                                                DeviceAccessStateReason, ClientType, UserDisplayName
                                        
                                        if ($devices) {
                                            return $devices
                                        }
                                        Write-Warning "No mobile devices found for $UPN"
                                        return $null
                                    } catch {
                                        Write-Warning "Error getting mobile devices: $_"
                                        return $null
                                    }
                                }; 
                                File = "mobileDevices.xml" 
                            }
                        )

                        foreach ($op in $forensicsOperations) {
                            try {
                                $data = & $op.Cmdlet
                                if ($null -ne $data) {
                                    $data | Export-Clixml -Path "$forensicsFolder\$UPN-$($op.File)" -Force
                                    & $writeOutputBox "  $([char]0x25E6) Exported $($op.Name)"
                                    #Write-RemediationLog "Exported $($op.Name)" -Level Info
                                } else {
                                    & $writeOutputBox "  $([char]0x25E6) No data found for $($op.Name)"
                                    #Write-RemediationLog "No data found for $($op.Name)" -Level Info
                                }
                            }
                            catch {
                                & $writeOutputBox "  $([char]0x25E6) Error exporting $($op.Name): $_"
                                #Write-RemediationLog "Error exporting $($op.Name): $_" -Level Error
                            }
                        }

                        # 7. Block Sign-In
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [7] Blocking sign-in access:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                        #Write-RemediationLog "Blocking sign-in access" -Level Info
                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Blocking sign-in access..."
                        })
                        try {
                            #Set-MsolUser -UserPrincipalName $UPN -BlockCredential $true -WarningAction SilentlyContinue
                            Update-MgUser -UserId $UPN -AccountEnabled:$false
                            & $writeOutputBox "  $([char]0x25E6) Sign-in blocked for $UPN"
                            Write-RemediationLog "  Sign-in blocked for $UPN" -Level Info
                        }
                        catch {
                            & $writeOutputBox "  $([char]0x25E6) Error blocking sign-in: $_"
                            Write-RemediationLog "Error blocking sign-in: $_" -Level Error
                            throw
                        }

                        # 8. Reset Password
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [8] Resetting password:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                        #Write-RemediationLog "Resetting password" -Level Info
                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Resetting password..."
                        })
                        try {
                            # Generate a complex password (16 chars with at least 3 non-alphanumeric)
                            $newPassword = [System.Web.Security.Membership]::GeneratePassword(16, 3)
                            $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                            
                            # Try Azure AD cmdlet first
                            try {
                                Set-AzureADUserPassword -ObjectId $UPN -Password $securePassword -ForceChangePasswordNextLogin $true
                            }
                            catch {
                                # Fallback to Microsoft Graph if Azure AD fails
                                $params = @{
                                    "passwordProfile" = @{
                                        "password" = $newPassword
                                        "forceChangePasswordNextSignIn" = $true
                                    }
                                }
                                Update-MgUser -UserId $UPN -BodyParameter $params -ErrorAction Stop
                            }
                            
                            # Log success
                            & $writeOutputBox "  $([char]0x25E6) Password reset successful"
                            & $writeOutputBox "  $([char]0x25E6) New password: $newPassword"
                            #Write-RemediationLog "Password reset successful" -Level Info
                            #Write-RemediationLog "New password: $newPassword" -Level Info
                        }
                        catch {
                            & $writeOutputBox "  $([char]0x25E6) Error resetting password: $_"
                            #Write-RemediationLog "Error resetting password: $_" -Level Error
                            throw
                        }

                        # 9. Revoke Refresh Tokens
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [9] Revoking refresh tokens:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                        #Write-RemediationLog "Revoking refresh tokens" -Level Info
                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Revoking tokens..."
                        })
                        try {
                            # Updated to use correct cmdlet name
                            Revoke-MgUserSignInSession -UserId $UPN
                            & $writeOutputBox "  $([char]0x25E6) Successfully revoked refresh tokens"
                            #Write-RemediationLog "Successfully revoked refresh tokens" -Level Info
                        }
                        catch {
                            & $writeOutputBox "  $([char]0x25E6) Error revoking refresh tokens: $_"
                            #Write-RemediationLog "Error revoking refresh tokens: $_" -Level Error
                            throw
                        }
            
                        # Completion
                        & $writeOutputBox "`n"
                        & $writeOutputBox "=============================================================================================================="
                        & $writeOutputBox "                              Remediation of $UPN is complete!"
                        & $writeOutputBox "=============================================================================================================="
                        #Write-RemediationLog "Remediation of $UPN is complete!" -Level Info
                        $endTime = Get-Date
                        $executionTime = New-TimeSpan -Start $startTime -End $endTime
                        & $writeOutputBox "`r Completion Time: $(Get-Date -Format 'MM/dd/yyyy hh:mm:ss tt')"
                        & $writeOutputBox " Execution Time: $($executionTime.TotalSeconds) seconds"
                        & $writeOutputBox " Export Location: $forensicsFolder"
                        & $writeOutputBox "=============================================================================================================="
                        
                        # Perform automated threat hunting analysis
                        & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                        & $writeOutputBox " [THREAT HUNTING] Analyzing collected data for indicators of compromise:"
                        & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                        $ProgressTextBlock.Dispatcher.Invoke([action] {
                            $ProgressTextBlock.Text = "Performing threat hunting analysis..."
                        })
                        
                        try {
                            $threatResults = Invoke-ThreatHunting -ForensicsPath $forensicsFolder -UPN $UPN
                            & $writeOutputBox "  $([char]0x25E6) Threat Level: $($threatResults.ThreatLevel)"
                            & $writeOutputBox "  $([char]0x25E6) Threat Score: $($threatResults.ThreatScore)"
                            & $writeOutputBox "  $([char]0x25E6) Findings: $($threatResults.FindingsCount)"
                            & $writeOutputBox "  $([char]0x25E6) Report: $($threatResults.ReportPath)"
                            
                            # Get and display recommendations
                            $recommendations = Get-IncidentResponseRecommendations -ThreatHuntingResults $threatResults -UPN $UPN
                            & $writeOutputBox "`r  AUTOMATED RECOMMENDATIONS:"
                            foreach ($recommendation in $recommendations) {
                                & $writeOutputBox "  $([char]0x25E6) $recommendation"
                            }
                        }
                        catch {
                            & $writeOutputBox "  $([char]0x25E6) Error during threat hunting analysis: $_"
                        }
                        
                        #Write-RemediationLog "Export Location: $forensicsFolder" -Level Info
                        $ProgressBar.Dispatcher.Invoke([action] {
                            $ProgressBar.IsIndeterminate = $false
                            $ProgressBar.Value = 100
                            $ProgressTextBlock.Text = "Forensics Only remediation complete"
                            $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::White
                        })
                    } 
                    catch {
                        # Only show error if it's not an abort
                        if (-not ($syncHash.abortFlag -or $cancellationToken.IsCancellationRequested)) {
                            & $writeOutputBox "`r--------------------------------------------------------------------------------------------------------------"
                            & $writeOutputBox "ERROR: Lockdown process failed"
                            & $writeOutputBox "--------------------------------------------------------------------------------------------------------------"
                            & $writeOutputBox "Error details: $_"
                            & $writeOutputBox "Stack Trace: $($_.ScriptStackTrace)"
                            #Write-RemediationLog "Error during lockdown: $_" -Level Error
                            #Write-RemediationLog "Stack Trace: $($_.ScriptStackTrace)" -Level Error
                            

                            $ProgressBar.Dispatcher.Invoke([action] {
                                $ProgressBar.IsIndeterminate = $false
                                $ProgressBar.Value = 0
                                $ProgressTextBlock.Text = "Error during lockdown"
                                $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
                            })
                            
                            # Update status text for error
                            $syncHash.statusText = "Error during lockdown"
                            $StatusTextBlock.Dispatcher.Invoke([action] {
                                $StatusTextBlock.Text = "Error during lockdown"
                            })
                        }
                        
                        # Disable the Abort menu item
                        $AbortMenuItem.Dispatcher.Invoke([Action]{
                            $AbortMenuItem.IsEnabled = $false
                        })
                    }
                }
                
                $AbortMenuItem.Dispatcher.Invoke([Action]{
                    $AbortMenuItem.IsEnabled = $false
                    $AbortMenuItem.Visibility = 'Visible' # Make sure it's visible too
                })

                try {
                    Stop-Transcript
                }
                catch {
                    #Write-RemediationLog "Error stopping transcript: $_" -Level Error
                }

                # Create and invoke the runspace
                $runspace = [powershell]::Create().AddScript($scriptBlock)
                $runspace.AddArgument($UPN)
                $runspace.AddArgument($OutputBox)
                $runspace.AddArgument($ProgressBar)
                $runspace.AddArgument($ProgressTextBlock)
                $runspace.AddArgument($writeOutputBox)
                $runspace.AddArgument($forensicsFolder)
                $runspace.AddArgument($startTime)
                $runspace.AddArgument($transcriptFile)
                $runspace.AddArgument($cancellationToken)
                $runspace.AddArgument($syncHash)
                $runspace.AddArgument($StatusTextBlock)
                $runspace.AddArgument($logFile)

                $runspace.RunspacePool = $global:RunspacePool
                $script:currentRemediationRunspace = @{
                    PowerShell = $runspace
                    Handle = $runspace.BeginInvoke()
                }
                
                return $script:currentRemediationRunspace
}

#endregion


$script:GetDeviceDetailsHandler = {
    try {
        # Get the progress bar and text controls
        $progressBar = $window.FindName("ExportProgressBar")
        $progressText = $window.FindName("ProgressStatusText")

        # Start the progress bar animation
        $progressBar.Dispatcher.Invoke([Action]{
            $progressBar.IsIndeterminate = $true
            $progressBar.Foreground = [System.Windows.Media.Brushes]::Crimson
            $progressText.Text = "Collecting Device Information..."
            $progressText.FontWeight = 'Bold'
            $progressText.Foreground = [System.Windows.Media.Brushes]::Black
        })

        # Get devices
        $devices = Get-MgDevice -All
        $deviceDetails = @()

        foreach ($device in $devices) {
            $deviceDetails += [PSCustomObject]@{
                DisplayName = $device.DisplayName
                Id = $device.Id
                OperatingSystem = $device.OperatingSystem
                OperatingSystemVersion = $device.OperatingSystemVersion
                TrustType = $device.TrustType
                ApproximateLastSignInDateTime = $device.ApproximateLastSignInDateTime
                IsCompliant = $device.IsCompliant
                IsManaged = $device.IsManaged
                AccountEnabled = $device.AccountEnabled
                DeviceType = if ($device.DeviceCategory) { $device.DeviceCategory } else { "Desktop" }
            }
        }

        # Update DataGrid and stop progress animation
        deviceGrid.Dispatcher.Invoke([Action]{
            $deviceGrid.ItemsSource = $deviceDetails
            
            # Stop progress bar animation and update text
            $progressBar.IsIndeterminate = $false
            $progressBar.Value = 100
            $progressText.Text = "Device Information Collected"
        })
    }
    catch {
        $writeOutputBox.Invoke("Error getting device details: $_")
        $writeOutputBox.Invoke("Stack Trace: $($_.ScriptStackTrace)")
        
        # Update progress bar on error
        $progressBar.Dispatcher.Invoke([Action]{
            $progressBar.IsIndeterminate = $false
            $progressBar.Value = 0
            $progressText.Text = "Error Collecting Device Information"
            $progressText.Foreground = [System.Windows.Media.Brushes]::Green
        })
    }
}

#region WPF XAML Code

# Main Window XAML
[xml]$xaml = @"
<Window x:Name="wpfWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="790"
        Height="580"
        Background="White"
        Title="Future State IR Toolkit v$script:ScriptVersion">
  <Window.Resources>
    <Style x:Key="PressableButtonStyle" TargetType="Button">
      <Setter Property="Background" Value="#008000" />
      <Setter Property="Foreground" Value="White" />
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="border"
                    Background="{TemplateBinding Background}"
                    BorderBrush="#008000"
                    BorderThickness="1"
                    CornerRadius="5">
              <ContentPresenter HorizontalAlignment="Center"
                                VerticalAlignment="Center" />
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter Property="Background"
                        TargetName="border"
                        Value="#09ca44" />
                <Setter Property="Foreground" Value="White" />
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter Property="RenderTransform" TargetName="border">
                  <Setter.Value>
                    <TranslateTransform Y="2" />
                  </Setter.Value>
                </Setter>
                <Setter Property="Effect">
                  <Setter.Value>
                    <DropShadowEffect Color="Black"
                                      BlurRadius="2"
                                      Opacity="0.3"
                                      ShadowDepth="1" />
                  </Setter.Value>
                </Setter>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Background" Value="LightGray" />
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <ControlTemplate x:Key="ToggleSwitchTemplate"
                     TargetType="CheckBox">
      <Grid>
        <Border x:Name="Border"
                Width="34"
                Height="16"
                Background="#E5E5E5"
                CornerRadius="8">
          <Ellipse x:Name="Knob"
                   Width="14"
                   Height="14"
                   Margin="1,1,0,0"
                   HorizontalAlignment="Left"
                   Fill="Black" />
        </Border>
      </Grid>
      <ControlTemplate.Triggers>
        <Trigger Property="IsChecked" Value="True">
          <Setter Property="HorizontalAlignment"
                  TargetName="Knob"
                  Value="Right" />
          <Setter Property="Background"
                  TargetName="Border"
                  Value="#09ca44" />
        </Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate>
    <Style x:Key="CustomScrollViewerStyle"
           TargetType="ScrollViewer">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollViewer">
            <Grid>
              <ScrollContentPresenter />
              <ScrollBar x:Name="PART_VerticalScrollBar"
                         Width="10"
                         HorizontalAlignment="Right"
                         Maximum="{TemplateBinding ScrollableHeight}"
                         Orientation="Vertical"
                         Value="{TemplateBinding VerticalOffset}"
                         ViewportSize="{TemplateBinding ViewportHeight}"
                         Visibility="{TemplateBinding ComputedVerticalScrollBarVisibility}">
                <ScrollBar.Style>
                  <Style TargetType="ScrollBar">
                    <Setter Property="Background" Value="#a6a6a6" />
                    <Style.Triggers>
                      <Trigger Property="IsMouseOver" Value="True">
                        <Setter Property="Background" Value="#6d6d6d" />
                      </Trigger>
                    </Style.Triggers>
                  </Style>
                </ScrollBar.Style>
              </ScrollBar>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto" />
      <RowDefinition Height="*" />
      <RowDefinition Height="Auto" />
    </Grid.RowDefinitions>
    <Menu Grid.Row="0">
      <MenuItem Header="_File">
        <MenuItem x:Name="ClearMenuItem" Header="_Clear">
          <MenuItem.Icon>
            <Image x:Name="ClearMenuItemIcon" />
          </MenuItem.Icon>
        </MenuItem>
        <MenuItem x:Name="ExitMenuItem" Header="E_xit">
          <MenuItem.Icon>
            <Image x:Name="ExitMenuItemIcon" />
          </MenuItem.Icon>
        </MenuItem>
      </MenuItem>
      <MenuItem Header="_Tools">
        <MenuItem x:Name="EnableDeviceMenuItem" Header="Enable Device">
          <MenuItem.Icon>
            <Image x:Name="EnableDeviceMenuItemIcon" />
          </MenuItem.Icon>
        </MenuItem>
        <MenuItem x:Name="ExportAuditLogMenuItem"
                  Header="Audit Log Export" />
        <MenuItem x:Name="SearchPurgeMenuItem" Header="Search/Purge">
          <MenuItem.Icon>
            <Image x:Name="SearchPurgeMenuItemIcon" />
          </MenuItem.Icon>
        </MenuItem>
      </MenuItem>
      <MenuItem Header="_Help">
        <MenuItem x:Name="DarkModeMenuItem" Header="Switch Theme">
          <MenuItem.Icon>
            <Image x:Name="DarkModeMenuItemIcon" />
          </MenuItem.Icon>
        </MenuItem>
        <MenuItem x:Name="TerminateMenuItem"
                  Header="Terminate Connection">
          <MenuItem.Icon>
            <Image x:Name="TerminateMenuItemIcon" />
          </MenuItem.Icon>
        </MenuItem>
        <MenuItem x:Name="AbortMenuItem" Header="Abort Remediation">
          <MenuItem.Icon>
            <Image Source="https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/abort.ico" />
          </MenuItem.Icon>
        </MenuItem>
        <MenuItem x:Name="AboutMenuItem" Header="_About">
          <MenuItem.Icon>
            <Image x:Name="AboutMenuItemIcon" />
          </MenuItem.Icon>
        </MenuItem>
      </MenuItem>
    </Menu>
    <Grid x:Name="ContentGrid" Grid.Row="1">
      <Canvas>
        <ScrollViewer Width="763"
                      Height="352"
                      HorizontalScrollBarVisibility="Auto"
                      Style="{StaticResource CustomScrollViewerStyle}"
                      VerticalScrollBarVisibility="Auto"
                      Canvas.Left="3"
                      Canvas.Top="86">
          <TextBox Name="OutputBox"
                   Width="752"
                   Height="353"
                   AcceptsReturn="True"
                   Background="{x:Null}"
                   BorderBrush="#FFCCCCCC"
                   BorderThickness="2"
                   FontFamily="Consolas"
                   Foreground="Black"
                   IsReadOnly="True"
                   TextWrapping="Wrap" />
        </ScrollViewer>
        <TextBox x:Name="TargetUPN"
                 Width="232"
                 Height="25"
                 VerticalContentAlignment="Center"
                 Canvas.Left="10"
                 Canvas.Top="29.199999999999989" />
        <StackPanel Orientation="Vertical"
                    Canvas.Left="3"
                    Canvas.Top="50">
          <StackPanel Margin="0,10,0,0" Orientation="Horizontal" />
        </StackPanel>
        <StackPanel Orientation="Horizontal"
                    Canvas.Left="151"
                    Canvas.Top="451">
          <Button x:Name="ConnectButton"
                  Content="Connect"
                  Width="84"
                  Height="28.4"
                  Margin="0,0,10,0"
                  Style="{StaticResource PressableButtonStyle}" />
          <Button x:Name="QueryButton"
                  Content="Query User"
                  Width="84"
                  Height="28.2"
                  Margin="0,0,10,0"
                  Style="{StaticResource PressableButtonStyle}" />
          <Button x:Name="SecureButton"
                  Content="Secure Account"
                  Width="87.2"
                  Height="28"
                  Margin="0,0,10,0"
                  Style="{StaticResource PressableButtonStyle}" />
          <Button x:Name="DisconnectButton"
                  Content="Disconnect"
                  Width="75"
                  Height="28.2"
                  Margin="0,0,10,0"
                  Style="{StaticResource PressableButtonStyle}" />
          <Button x:Name="ExitButton"
                  Content="Exit"
                  Width="84.4"
                  Height="28"
                  Style="{StaticResource PressableButtonStyle}" />
        </StackPanel>
        <Border Width="320"
                Height="72.600000000000023"
                Background="{x:Null}"
                BorderBrush="#008000"
                BorderThickness="1"
                Canvas.Left="445"
                Canvas.Top="7" />
        <Label x:Name="RemediationModeLabel"
               Content="Remediation Mode"
               Width="124.99999999999989"
               Height="25"
               FontWeight="Bold"
               Canvas.Left="556.2"
               Canvas.Top="3" />
        <Label x:Name="LockdownWForensicsLabel"
               Content="Lockdown w/ Forensics"
               Width="119"
               Height="18"
               FontSize="11"
               Foreground="Black"
               Padding="1"
               Canvas.Left="451.69999999999993"
               Canvas.Top="23.199999999999989" />
        <Label x:Name="ForensicsOnlyLabel"
               Content="Forensics Only"
               Width="75"
               Height="18"
               FontSize="11"
               Padding="1"
               Canvas.Left="580.99999999999977"
               Canvas.Top="23.199999999999989" />
        <Label x:Name="LockdownOnlyLabel"
               Content="Lockdown Only"
               Width="78"
               Height="18"
               FontSize="11"
               Foreground="Black"
               Padding="1"
               Canvas.Left="675.4"
               Canvas.Top="23.199999999999989" />
        <CheckBox x:Name="ForensicsOnlyToggleSwitch"
                  Content="Forensics Only"
                  Template="{StaticResource ToggleSwitchTemplate}"
                  Canvas.Left="596"
                  Canvas.Top="38" />
        <StackPanel Orientation="Horizontal"
                    Canvas.Left="493"
                    Canvas.Top="39">
          <CheckBox x:Name="LockDownWForensicsToggleSwitch"
                    Content="Lockdown w/ Forensics"
                    Margin="0,0,10,0"
                    Template="{StaticResource ToggleSwitchTemplate}" />
        </StackPanel>
        <StackPanel Orientation="Horizontal"
                    Canvas.Left="694"
                    Canvas.Top="39">
          <CheckBox x:Name="LockdownOnlyToggleSwitch"
                    Content="Lockdown Only"
                    Margin="0,0,10,0"
                    Template="{StaticResource ToggleSwitchTemplate}" />
        </StackPanel>
        <Label x:Name="upnLabel"
               Content="User Principal Name:"
               Width="141"
               Height="23"
               FontWeight="Bold"
               Canvas.Left="4.8999999999999773"
               Canvas.Top="4.1999999999999886" />
      </Canvas>
    </Grid>
    <Grid Margin="1,5.79999999999995,0.799999999999955,3.79999999999995"
          HorizontalAlignment="Stretch"
          VerticalAlignment="Stretch"
          Grid.Column="0"
          Grid.Row="2">
      <ProgressBar x:Name="ProgressBar"
                   Height="20"
                   VerticalAlignment="Center"
                   Foreground="Crimson"
                   Visibility="Hidden" />
      <TextBlock x:Name="ProgressTextBlock"
                 HorizontalAlignment="Center"
                 VerticalAlignment="Center"
                 Foreground="Black"
                 Text="" />
    </Grid>
  </Grid>
</Window>
"@

# About Window XAML
$aboutXaml = @"
<Window x:Name="AboutWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="500"
        Height="400"
        Background="White"
        Title="About FSIR Toolkit"
        WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize">
  <Grid Margin="20">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    
    <!-- Title and Version -->
    <TextBlock x:Name="VersionTextBlock" 
               Grid.Row="0"
               Text="Future State IR Toolkit v1.0.2"
               FontSize="18"
               FontWeight="Bold"
               HorizontalAlignment="Center"
               Margin="0,0,0,10"/>
    
    <!-- Copyright -->
    <TextBlock x:Name="CopyrightTextBlock"
               Grid.Row="1"
               Text="Copyright 2025 Future State Technologies"
               FontSize="12"
               HorizontalAlignment="Center"
               Margin="0,0,0,20"/>
    
    <!-- About Text -->
    <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
      <TextBox x:Name="AboutTextBox"
               IsReadOnly="True"
               TextWrapping="Wrap"
               Background="Transparent"
               BorderThickness="0"
               FontFamily="Segoe UI"
               FontSize="11"
               Padding="5"/>
    </ScrollViewer>
    
    <!-- Close Button -->
    <Button x:Name="AboutClose"
            Grid.Row="3"
            Content="Close"
            Width="80"
            Height="30"
            HorizontalAlignment="Center"
            Margin="0,20,0,0"/>
  </Grid>
</Window>
"@

#endregion


$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Set window icon to local fsir.ico file
$iconPath = Join-Path $PSScriptRoot "fsir.ico"
if (-not (Test-Path $iconPath)) {
    # Try icons folder if not in root
    $iconPath = Join-Path $PSScriptRoot "icons\fsir.ico"
}

if (Test-Path $iconPath) {
    try {
        # Use the simplest method - direct file path with BitmapImage
        $iconBitmap = New-Object System.Windows.Media.Imaging.BitmapImage
        $iconBitmap.BeginInit()
        $iconBitmap.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $iconBitmap.UriSource = New-Object System.Uri($iconPath, [System.UriKind]::RelativeOrAbsolute)
        $iconBitmap.EndInit()
        $iconBitmap.Freeze()
        $window.Icon = $iconBitmap
    }
    catch {
        try {
            # Alternative method using pack URI
            $window.Icon = New-Object System.Windows.Media.Imaging.BitmapImage([System.Uri]::new($iconPath))
        }
        catch {
            # Silent fallback - continue with default icon
        }
    }
}

#region Window Controls
$LockDownWForensicsToggleSwitch = $window.FindName("LockDownWForensicsToggleSwitch")
$ForensicsOnlyToggleSwitch = $window.FindName("ForensicsOnlyToggleSwitch")
$LockdownOnlyToggleSwitch = $window.FindName("LockdownOnlyToggleSwitch")

Set-ToggleSwitchHandlers

$LockDownWForensicsToggleSwitch.IsChecked = $true
$LockDownWForensicsToggleSwitch.IsEnabled = $true
$ForensicsOnlyToggleSwitch.IsChecked = $false
$ForensicsOnlyToggleSwitch.IsEnabled = $false
$LockdownOnlyToggleSwitch.IsChecked = $false
$LockdownOnlyToggleSwitch.IsEnabled = $false

$controls = @("OutputBox", "TargetUPN", "ConnectButton", "QueryButton", "SecureButton", "DisconnectButton", "ExitButton", "ProgressBar", "ProgressTextBlock")
$controls | ForEach-Object { Set-Variable -Name $_ -Value $window.FindName($_) }

$menuControls = @("ClearMenuItem", "ExitMenuItem", "DarkModeMenuItem", "AboutMenuItem", "DevMenuItem", "TerminateMenuItem")
$menuControls | ForEach-Object { Set-Variable -Name $_ -Value $window.FindName($_) }

$EnableDeviceMenuItem = $window.FindName("EnableDeviceMenuItem")
$SearchPurgeMenuItem = $window.FindName("SearchPurgeMenuItem")

$script:remediationCancellationSource = New-Object System.Threading.CancellationTokenSource

$ExportAuditLogMenuItem = $window.FindName("ExportAuditLogMenuItem")
if ($null -eq $ExportAuditLogMenuItem) {
    Write-Host "ExportAuditLogMenuItem not found in XAML"
} else {
    # Load and set the Audit icon
    $auditIcon = Get-IconImage "Audit"
    if ($null -ne $auditIcon) {
        $ExportAuditLogMenuItem.Icon = New-Object System.Windows.Controls.Image -Property @{
            Source = $auditIcon
            Width = 16
            Height = 16
        }
    }
}

$ConnectButton = $window.FindName("ConnectButton")
$OutputBox = $window.FindName("OutputBox")

# Load menu icons from local files with URL fallback
Get-MenuIcons

#endregion



#region Event Handlers
$clearMenuItem.Add_Click({
  $LockDownWForensicsToggleSwitch.IsChecked = $true
  $ForensicsOnlyToggleSwitch.IsChecked = $false
  $LockdownOnlyToggleSwitch.IsChecked = $false
  
  $targetUPN.Text = ""

  $OutputBox.Dispatcher.Invoke([action] {
      $OutputBox.Clear()
      $OutputBox.AppendText("                                    All output and selections have been cleared.`r`n")
  })

  [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
  Start-Sleep -Milliseconds 900

  $OutputBox.Clear()
  $OutputBox.AppendText("                             Welcome to the M365 Breach Remediation Toolkit v$ScriptVersion`r`n")
})

$SearchPurgeMenuItem.Add_Click({
    try {
        $scriptPath = Join-Path $PSScriptRoot "modules\Search-Purge.ps1"
        if (Test-Path $scriptPath) {
            # Start the script in a new PowerShell process
            Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -WindowStyle Hidden
        } else {
            [System.Windows.MessageBox]::Show(
                "Search-Purge script not found at: $scriptPath", 
                "Script Not Found", 
                [System.Windows.MessageBoxButton]::OK, 
                [System.Windows.MessageBoxImage]::Error
            )
        }
    } catch {
        [System.Windows.MessageBox]::Show(
            "Error launching Search-Purge script: $_", 
            "Error", 
            [System.Windows.MessageBoxButton]::OK, 
            [System.Windows.MessageBoxImage]::Error
        )
    }
})

$AbortMenuItem.Add_Click({
    try {
        # Set the abort flag
        $script:abortRemediation = $true
        
        # Signal cancellation if cancellation source exists
        if ($script:remediationCancellationSource) {
            $script:remediationCancellationSource.Cancel()
        }
        
        # Stop and cleanup the remediation runspace if it exists
        if ($script:currentRemediationRunspace) {
            if ($script:currentRemediationRunspace.RunspaceHandle) {
                $script:currentRemediationRunspace.Stop()
                $script:currentRemediationRunspace.Dispose()
            }
            $script:currentRemediationRunspace = $null
        }
        
        # Create new cancellation source for future operations
        $script:remediationCancellationSource = New-Object System.Threading.CancellationTokenSource
        
        # Update UI to show abortion
        $OutputBox.Dispatcher.Invoke([Action]{
            $OutputBox.AppendText("`r`n`r`n                                    Remediation process aborted by user.`r`n")
            $OutputBox.ScrollToEnd()
            
            # Update progress indicators
            $ProgressBar.IsIndeterminate = $false
            $ProgressBar.Value = 0
            
            $ProgressTextBlock.Inlines.Clear()
            $boldText = New-Object System.Windows.Documents.Run
            $boldText.Text = "Remediation Aborted"
            $boldText.FontWeight = [System.Windows.FontWeights]::Bold
            $ProgressTextBlock.Inlines.Add($boldText)
            $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
        })
        
        # Re-enable buttons
        $window.Dispatcher.Invoke([Action]{
            $QueryButton.IsEnabled = $true
            $SecureButton.IsEnabled = $true
            $DisconnectButton.IsEnabled = $true
            $AbortMenuItem.IsEnabled = $false
        })
        
        # Cleanup
        [System.GC]::Collect()
    }
    catch {
        Write-Host "Error in abort handler: $_"
        $OutputBox.Dispatcher.Invoke([Action]{
            $OutputBox.AppendText("`r`nError aborting remediation: $_`r`n")
            $OutputBox.AppendText("Stack Trace: $($_.ScriptStackTrace)`r`n")
            $OutputBox.ScrollToEnd()
        })
    }
})

$Window.FindName("AboutMenuItem").Add_Click({
  try {        
      [xml]$aboutReader = $aboutXaml
      
      $script:aboutWindow = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $aboutReader))
      
      if ($null -eq $script:aboutWindow) {
          throw "Failed to create About window"
      }
      
      $script:aboutWindow.WindowStartupLocation = 'CenterOwner'
      $script:aboutWindow.Owner = $Window
      
      # Apply theme immediately after creation
      Update-AboutWindowTheme
      # Get the AboutTextBox from the window
      $aboutTextBox = $script:aboutWindow.FindName("AboutTextBox")
      
      if ($null -eq $aboutTextBox) {
          throw "AboutTextBox not found in the About window"
      }
      
      # Close button event
      $closeButton = $script:aboutWindow.FindName("AboutClose")
      
      if ($null -eq $closeButton) {
          throw "Close button not found in the About window"
      }
      
      $closeButton.Add_Click({
          if ($null -ne $script:typingCancellationTokenSource) {
              $script:typingCancellationTokenSource.Cancel()
          }
          if ($null -ne $script:aboutWindow) {
              $script:aboutWindow.Close()
          } else {
          }
      })

      # Populate the AboutTextBox

      PopulateAboutTextBox -AboutTextBox $aboutTextBox -AboutWindow $script:aboutWindow
      

  }
  catch {
      $errorMessage = "Error creating About window: $_`nStack Trace:`n$($_.ScriptStackTrace)"
      [System.Windows.MessageBox]::Show($errorMessage, "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
  }
})

$ExportAuditLogMenuItem.Add_Click({
    Open-AuditLogWindow
})

$EnableDeviceMenuItem.Add_Click({
    try {
        Add-Type -AssemblyName PresentationFramework

        $mdapXaml = @"
<Window x:Name="MDAPWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        Width="800"
        Height="600"
        Background="White"
        Icon="https://advancestuff.hostedrmm.com/labtech/transfer/installers/mits.ico"
        Title="Managed Device Admin Panel">
  <Grid RenderTransformOrigin="0.5076,0.5951">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto" />
      <RowDefinition Height="Auto" />
      <RowDefinition Height="0.96343692870201*" />
      <RowDefinition Height="60.8000000000001" />
      <RowDefinition Height="Auto" />
    </Grid.RowDefinitions>
    <Label x:Name="MDAPLabel"
           Content="Managed Device Admin Panel"
           Width="370"
           Height="41"
           Margin="18,10,0,0"
           HorizontalAlignment="Left"
           VerticalAlignment="Top"
           FontSize="25"
           FontWeight="Bold"
           Grid.Column="0"
           Grid.Row="0" />
    <Label x:Name="MobileDeviceAdminPanel"
           Content="Enable a disabled device"
           Width="286"
           Height="30"
           Margin="19.9999999999999,47,0,0"
           HorizontalAlignment="Left"
           VerticalAlignment="Top"
           FontSize="18"
           Grid.Column="0"
           Grid.Row="0" />
    <Canvas Margin="18,9.59999999999999,18.4,31.1999999999999"
            HorizontalAlignment="Stretch"
            VerticalAlignment="Stretch"
            Grid.Column="0"
            Grid.Row="2">
      <TextBox x:Name="TargetUPNTextBox"
               Width="232"
               Height="25"
               Canvas.Left="0"
               Canvas.Top="25" />
      <Label x:Name="upnLabel"
             Content="User Principal Name:"
             Width="141"
             Height="23"
             FontWeight="Bold"
             Canvas.Left="0"
             Canvas.Top="0" />
      <StackPanel Orientation="Horizontal"
                  Canvas.Left="250"
                  Canvas.Top="25">
        <Label x:Name="AccountStatusLabel"
               Content="Account Status:"
               Width="100"
               Height="25"
               VerticalAlignment="Center" />
        <TextBlock x:Name="AccountStatusText"
                   Margin="5,0,0,0"
                   VerticalAlignment="Center"
                   Text="Unknown" />
      </StackPanel>
    </Canvas>
    <ListView x:Name="DeviceListView"
              Margin="18,70.6,18.4,30.8"
              HorizontalAlignment="Stretch"
              VerticalAlignment="Stretch"
              Grid.Column="0"
              Grid.Row="2">
      <ListView.View>
        <GridView>
          <GridViewColumn Width="120"
                          DisplayMemberBinding="{Binding DisplayName}"
                          Header="Device Name" />
          <GridViewColumn Width="200"
                          DisplayMemberBinding="{Binding Id}"
                          Header="Device ID" />
          <GridViewColumn Width="80"
                          DisplayMemberBinding="{Binding DeviceType}"
                          Header="Device Type" />
          <GridViewColumn Width="70" Header="Enabled">
            <GridViewColumn.CellTemplate>
              <DataTemplate>
                <TextBlock HorizontalAlignment="Center"
                           Text="{Binding AccountEnabled}" />
              </DataTemplate>
            </GridViewColumn.CellTemplate>
          </GridViewColumn>
          <GridViewColumn Width="120"
                          DisplayMemberBinding="{Binding LastSyncDateTime}"
                          Header="Last Sync" />
          <GridViewColumn Width="100"
                          DisplayMemberBinding="{Binding OperatingSystem}"
                          Header="OS" />
          <GridViewColumn Width="80"
                          DisplayMemberBinding="{Binding OSVersion}"
                          Header="OS Version" />
        </GridView>
      </ListView.View>
    </ListView>
    <Button x:Name="EnableDeviceButton"
            Content="Enable Device"
            Width="113"
            Height="34.400000000000034"
            Margin="0,0,251.4,36.8"
            HorizontalAlignment="Right"
            VerticalAlignment="Bottom"
            Grid.Column="0"
            Grid.Row="2"
            Grid.RowSpan="2" />
    <Button x:Name="GetDeviceDetailsButton"
            Content="Get Device Details"
            Width="113"
            Height="34.200000000000045"
            Margin="223.2,0,0,36.4000000000001"
            HorizontalAlignment="Left"
            VerticalAlignment="Bottom"
            RenderTransformOrigin="0.468,0.5"
            Grid.Column="0"
            Grid.Row="2"
            Grid.RowSpan="2" />
    <Image x:Name="AboutA"
           Width="76"
           Height="68.4"
           Margin="0,4.99999999999999,19.1999999999999,0"
           HorizontalAlignment="Right"
           VerticalAlignment="Top"
           Source="https://advancestuff.hostedrmm.com/labtech/transfer/installers/easyjob/redA.png"
           Grid.Column="0"
           Grid.Row="0" />
    <ProgressBar x:Name="OperationProgressBar"
                Margin="0,34.5999999999999,0,1.40000000000009"
                HorizontalAlignment="Stretch"
                VerticalAlignment="Stretch"
                Foreground="Crimson"
                IsIndeterminate="False"
                Value="0"
                Grid.Column="0"
                Grid.Row="3" />
    <TextBlock x:Name="ProgressTextBlock"
            Grid.Column="0"
            Grid.Row="3"
            HorizontalAlignment="Center"
            VerticalAlignment="Center"
            FontWeight="Bold"
           Foreground="White" />
  </Grid>
</Window>
"@

        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($mdapXaml))
        $mdapWindow = [System.Windows.Markup.XamlReader]::Load($reader)

        if ($null -eq $mdapWindow) {
            throw "Failed to create Mobile Device Admin Panel window"
        }
        
        # Set the DataContext
        $mdapWindow.DataContext = $script:MDAPViewModel
        
        # Store the window in a script-level variable
        $script:mdapWindow = $mdapWindow
        
        # Apply the current theme to the MDAP window
        Update-MDAPTheme

        $mdapWindow.Add_Loaded({
            # Apply the theme again when the window is loaded
            Update-MDAPTheme
        
            # Get the UPN from the main window
            $upn = $TargetUPN.Text.Trim()
        
            # Update the TargetUPN in the MDAP window
            $targetUPNTextBox = $mdapWindow.FindName("TargetUPNTextBox")
            if ($targetUPNTextBox) {
                $targetUPNTextBox.Text = $upn
            }
            
            $deviceListView.Add_SelectionChanged({
                $enableDeviceButton.IsEnabled = $null -ne $deviceListView.SelectedItem
            })

            # Set initial account status to "Unknown"
            $accountStatusText = $mdapWindow.FindName("AccountStatusText")
            if ($accountStatusText) {
                $accountStatusText.Text = "Unknown"
                $accountStatusText.Foreground = [System.Windows.Media.Brushes]::Gray
            }
        })
        
        $getDeviceDetailsButton = $mdapWindow.FindName("GetDeviceDetailsButton")
        $enableDeviceButton = $mdapWindow.FindName("EnableDeviceButton")
        $targetUPNTextBox = $mdapWindow.FindName("TargetUPNTextBox")
        $deviceListView = $mdapWindow.FindName("DeviceListView")
        $accountStatusText = $mdapWindow.FindName("AccountStatusText")

        if ($null -eq $getDeviceDetailsButton -or $null -eq $enableDeviceButton -or $null -eq $targetUPNTextBox -or $null -eq $deviceListView -or $null -eq $accountStatusText) {
            throw "Failed to find one or more controls in the window"
        }

        $getDeviceDetailsButton.Add_Click({
            $upn = $targetUPNTextBox.Text.Trim()
            if ([string]::IsNullOrWhiteSpace($upn)) {
                [System.Windows.MessageBox]::Show("Please enter a valid UPN.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                return
            }

            try {
                # Retrieve the user object based on UPN
                $user = Get-MgUser -UserId $upn -Property Id,UserPrincipalName,AccountEnabled -ErrorAction Stop

                if ($null -eq $user) {
                    Write-Host "No user found with UPN: $upn"
                    [System.Windows.MessageBox]::Show("No user found with UPN: $upn", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                    return
                } else {
                    # Check if the account is enabled or disabled
                    $accountStatus = if ($user.AccountEnabled -eq $false) { "Disabled" } else { "Enabled" }
                    Write-Host "Account Status: $accountStatus"
                    
                    # Update UI on the UI thread
                    $mdapWindow.Dispatcher.Invoke([Action]{
                        $accountStatusText.Text = $accountStatus
                        $accountStatusText.Foreground = if ($accountStatus -eq "Disabled") { [System.Windows.Media.Brushes]::Green } else { [System.Windows.Media.Brushes]::Green }
                    })
                }

                Write-Host "Retrieving device details for $upn"
                
                # Get mobile devices
                $mobileDevices = Get-MgUserManagedDevice -UserId $user.Id -ErrorAction Stop | Select-Object `
                    DeviceName, Id, DeviceType, ComplianceState, LastSyncDateTime, `
                    OperatingSystem, OSVersion, Model, Manufacturer, SerialNumber, `
                    IsManaged, EnrollmentType, AzureADRegistered

                # Get other associated devices
                $otherDevices = Get-MgUserRegisteredDevice -UserId $user.Id -ErrorAction Stop

                $formattedDevices = @()

                # Format mobile devices
                $formattedDevices += $mobileDevices | ForEach-Object {
                    [PSCustomObject]@{
                        DeviceType = "Mobile"
                        DisplayName = $_.DeviceName
                        Id = $_.Id
                        AccountEnabled = if ($_.ComplianceState -eq "Compliant") { "True" } else { "False" }
                        LastSyncDateTime = $_.LastSyncDateTime
                        OperatingSystem = $_.OperatingSystem
                        OSVersion = $_.OSVersion
                        Model = $_.Model
                        Manufacturer = $_.Manufacturer
                        SerialNumber = $_.SerialNumber
                        IsManaged = $_.IsManaged
                        EnrollmentType = $_.EnrollmentType
                        AzureADRegistered = $_.AzureADRegistered
                    }
                }

                # Format other devices
                $formattedDevices += $otherDevices | ForEach-Object {
                    $fullDevice = Get-MgDevice -DeviceId $_.Id -ErrorAction Stop
                    [PSCustomObject]@{
                        DeviceType = "Other"
                        DisplayName = $fullDevice.DisplayName
                        Id = $fullDevice.Id
                        AccountEnabled = if ($fullDevice.AccountEnabled) { "True" } else { "False" }
                        LastSyncDateTime = $fullDevice.ApproximateLastSignInDateTime
                        OperatingSystem = $fullDevice.OperatingSystem
                        OSVersion = $fullDevice.OperatingSystemVersion
                        Model = $fullDevice.Model
                        Manufacturer = $fullDevice.Manufacturer
                        SerialNumber = $fullDevice.SerialNumber
                        IsManaged = "N/A"
                        EnrollmentType = $fullDevice.EnrollmentType
                        AzureADRegistered = $fullDevice.IsManaged
                    }
                }

                $mdapWindow.Dispatcher.Invoke([Action]{
                    $deviceListView.ItemsSource = $formattedDevices
                    $enableDeviceButton.IsEnabled = $false
                })
                Write-Host "Device details retrieved successfully"
            }
            catch {
                Write-Host "Error retrieving account or device details: $_"
                [System.Windows.MessageBox]::Show("Error retrieving account or device details: $_", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                
                $mdapWindow.Dispatcher.Invoke([Action]{
                    $accountStatusText.Text = "Unknown"
                    $accountStatusText.Foreground = [System.Windows.Media.Brushes]::Gray
                    $accountStatusText.UpdateLayout()
                    $deviceListView.ItemsSource = $null
                })
            }
        })
        
        $enableDeviceButton.Add_Click({
            $selectedDevice = $deviceListView.SelectedItem
            if ($selectedDevice) {
                try {
                    $progressBar.IsIndeterminate = $true
                    $progressTextBlock.Text = "Enabling device..."
        
                    $writeOutputBox.Invoke("Attempting to enable device: $($selectedDevice.DisplayName) (ID: $($selectedDevice.Id))")
        
                    if ($selectedDevice.DeviceType -eq "Mobile") {
                        $writeOutputBox.Invoke("This is a managed mobile device. Using Graph API to enable...")
                        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($selectedDevice.Id)"
                        $body = @{
                            "managementState" = "managed"
                        } | ConvertTo-Json
        
                        $response = Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body -ContentType "application/json"
                        $writeOutputBox.Invoke("API Response: $($response | ConvertTo-Json -Depth 1)")
                    } else {
                        $writeOutputBox.Invoke("This is a registered device. Using Update-MgDevice to enable...")
                        Update-MgDevice -DeviceId $selectedDevice.Id -AccountEnabled:$true
                        $writeOutputBox.Invoke("Update-MgDevice command executed.")
                    }
        
                    $writeOutputBox.Invoke("Device enabling process initiated. Waiting 5 seconds before checking status...")
                    Start-Sleep -Seconds 5
        
                    # Check the account status again
            if ($selectedDevice.DeviceType -eq "Mobile") {
                $updatedDevice = Invoke-MgGraphRequest -Method GET -Uri $uri
                $updatedStatus = if ($null -ne $updatedDevice.managementState) {
                    $updatedDevice.managementState
                } else {
                    "Unknown"
                }
            } else {
                $updatedDevice = Get-MgDevice -DeviceId $selectedDevice.Id
                $updatedStatus = if ($updatedDevice.AccountEnabled) { "Enabled" } else { "Disabled" }
            }
            $writeOutputBox.Invoke("Updated device status: $updatedStatus")
            $writeOutputBox.Invoke("Full device details: $($updatedDevice | ConvertTo-Json -Depth 1)")

            # Refresh the device list
            $writeOutputBox.Invoke("Refreshing device list...")
            $mdapWindow.Dispatcher.Invoke([Action]{
                $upn = $targetUPNTextBox.Text.Trim()
                $user = Get-MgUser -UserId $upn -Property Id,UserPrincipalName,AccountEnabled -ErrorAction Stop
                $mobileDevices = Get-MgUserManagedDevice -UserId $user.Id -ErrorAction Stop
                $otherDevices = Get-MgUserRegisteredDevice -UserId $user.Id -ErrorAction Stop

                $formattedDevices = @()
                $formattedDevices += $mobileDevices | ForEach-Object {
                    [PSCustomObject]@{
                        DeviceType = "Mobile"
                        DisplayName = $_.DeviceName
                        Id = $_.Id
                        AccountEnabled = if ($_.ComplianceState -eq "Compliant") { "True" } else { "False" }
                        LastSyncDateTime = $_.LastSyncDateTime
                        OperatingSystem = $_.OperatingSystem
                        OSVersion = $_.OSVersion
                    }
                }
                $formattedDevices += $otherDevices | ForEach-Object {
                    $fullDevice = Get-MgDevice -DeviceId $_.Id -ErrorAction Stop
                    [PSCustomObject]@{
                        DeviceType = "Other"
                        DisplayName = $fullDevice.DisplayName
                        Id = $fullDevice.Id
                        AccountEnabled = if ($fullDevice.AccountEnabled) { "True" } else { "False" }
                        LastSyncDateTime = $fullDevice.ApproximateLastSignInDateTime
                        OperatingSystem = $fullDevice.OperatingSystem
                        OSVersion = $fullDevice.OperatingSystemVersion
                    }
                }
                $deviceListView.ItemsSource = $formattedDevices
            })
            $writeOutputBox.Invoke("Device list refreshed.")
        }
                catch {
                    $writeOutputBox.Invoke("Error enabling device: $_")
                    $writeOutputBox.Invoke("Stack Trace: $($_.ScriptStackTrace)")
                }
                finally {
                    $progressBar.IsIndeterminate = $false
                    $progressTextBlock.Text = ""
                }
            }
            else {
                [System.Windows.MessageBox]::Show("Please select a device first.", "No Device Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            }
        })
        $enableDeviceButton.IsEnabled = $false
        # Show the window
        $mdapWindow.ShowDialog()
    }
    catch {
        Write-Host "Error creating or showing the Mobile Device Admin Panel: $_"
        [System.Windows.MessageBox]::Show("Error creating or showing the Mobile Device Admin Panel: $_", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})

$TerminateMenuItem.Add_Click({
    try {
        # Prevent multiple clicks
        $TerminateMenuItem.IsEnabled = $false
        
        Terminate-AllConnections -OutputBox $OutputBox `
                               -ConnectButton $ConnectButton `
                               -QueryButton $QueryButton `
                               -SecureButton $SecureButton `
                               -DisconnectButton $DisconnectButton
                               
        # Re-enable the menu item after a short delay
        $OutputBox.Dispatcher.BeginInvoke([Action]{
            $TerminateMenuItem.IsEnabled = $true
        }, [System.Windows.Threading.DispatcherPriority]::Background)
    } catch {
        Write-Host "Error in terminate menu handler: $_"
        $TerminateMenuItem.IsEnabled = $true
    }
})

$exitMenuItem.Add_Click({
  $window.Close()
})

# Add this to your toggle switch change event handler
$ToggleSwitch.Add_Toggled({
    # First terminate existing connections
    Terminate-AllConnections -OutputBox $OutputBox -ConnectButton $ConnectButton -QueryButton $QueryButton -SecureButton $SecureButton -DisconnectButton $DisconnectButton
    
    # Clear any cached credentials or tokens
    [System.Windows.Forms.Application]::DoEvents()
    Clear-Variable -Name "*token*" -Scope Script -ErrorAction SilentlyContinue
    [System.GC]::Collect()
    
    # Reset connection state
    $global:IsConnected = $false
    $ConnectButton.Content = "Connect"
    
    # Update UI to reflect disconnected state
    $OutputBox.Clear()
    TypeOutputBoxMessage -OutputBox $OutputBox -Message "Mode changed - Please reconnect to continue."
})
#endregion




#region Button Controls
$ConnectButton.IsEnabled = $false
$ConnectButton.Foreground = New-Object System.Windows.Media.SolidColorBrush("#008000")

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(500)
$timer.Add_Tick({
    $message = "Click the 'Connect' button to get started."
    $totalWidth = 100
    $padding = [Math]::Max(0, ($totalWidth - $message.Length) / 5)
    
    $script:welcomeTypingTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:welcomeTypingTimer.Interval = [TimeSpan]::FromMilliseconds(15)
    
    $script:typingIndex = 0
    $script:typingMessage = ($message.PadLeft($message.Length + $padding).PadRight($totalWidth))
    
    $script:welcomeTypingTimer.Add_Tick({
        if ($script:typingIndex -lt $script:typingMessage.Length) {
            $OutputBox.AppendText($script:typingMessage[$script:typingIndex])
            $OutputBox.ScrollToEnd()
            $script:typingIndex++
        } else {
            $script:welcomeTypingTimer.Stop()
            # Enable the Connect button only after typing is complete
            $ConnectButton.Dispatcher.Invoke([action] {
                $ConnectButton.IsEnabled = $true
                $ConnectButton.Foreground = [System.Windows.Media.Brushes]::White
                $ConnectButton.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
            })
        }
    })
    
    $script:welcomeTypingTimer.Start()
    $timer.Stop()
})
$timer.Start()


$ConnectButton.Add_Click({
    $ConnectButton.Add_PreviewMouseDown({
        # Immediately stop typing and clear
        $script:isConnecting = $true
        if ($null -ne $script:welcomeTypingTimer) {
            $script:welcomeTypingTimer.Stop()
            $script:welcomeTypingTimer = $null
        }
        $OutputBox.Dispatcher.Invoke([action] { 
            $OutputBox.Clear() 
        }, [System.Windows.Threading.DispatcherPriority]::Send)
    })
  $OutputBox.ScrollToEnd()

  # Disable the Connect button to prevent multiple connection attempts

  $ConnectButton.Content = "Connecting..."

  # Call the Connect-ServicesAsync function
  Connect-ServicesAsync2 -OutputBox $OutputBox `
                        -QueryButton $QueryButton `
                        -SecureButton $SecureButton `
                        -DisconnectButton $DisconnectButton `
                        -ConnectButton $ConnectButton `
                        -ProgressBar $ProgressBar `
                        -ProgressTextBlock $ProgressTextBlock
})

$DisconnectButton.Add_Click({
    # Disable buttons immediately
    $DisconnectButton.IsEnabled = $false
    $ConnectButton.IsEnabled = $false
    $QueryButton.IsEnabled = $false
    $SecureButton.IsEnabled = $false
    $ExitButton.IsEnabled = $false
    
    # Clear output and update progress indicators
    $OutputBox.Clear()
    $ProgressBar.Visibility = 'Visible'
    $ProgressBar.IsIndeterminate = $true
    $ProgressTextBlock.Visibility = 'Visible'
    
    $boldText = New-Object System.Windows.Documents.Run
    $boldText.Text = "Disconnecting from M365..."
    $boldText.FontWeight = [System.Windows.FontWeights]::Bold
    $ProgressTextBlock.Inlines.Clear()
    $ProgressTextBlock.Inlines.Add($boldText)
    
    # Create and start background runspace for disconnection
    $runspace = [powershell]::Create().AddScript({
        param(
            $OutputBox,
            $ProgressBar,
            $ProgressTextBlock,
            $ConnectButton,
            $QueryButton,
            $SecureButton,
            $DisconnectButton,
            $ExitButton
        )
        
        try {
            # Disconnect from Microsoft Graph
            try {
                $graphContext = Get-MgContext -ErrorAction SilentlyContinue
                if ($graphContext) {
                    Disconnect-MgGraph -ErrorAction Stop
                }
            }
            catch {
                $OutputBox.Dispatcher.Invoke({ 
                    $OutputBox.AppendText("Warning: Error disconnecting from Microsoft Graph: $_`r`n") 
                })
            }

            # Disconnect from Exchange Online
            try {
                $exchangeSessions = Get-PSSession | Where-Object {
                    $_.ConfigurationName -eq "Microsoft.Exchange" -or 
                    $_.ComputerName -like "*.outlook.com" -or
                    $_.ConfigurationName -eq "Microsoft.ExchangeOnline"
                } -ErrorAction SilentlyContinue
                if ($exchangeSessions) {
                    $exchangeSessions | Remove-PSSession -ErrorAction Stop
                }
            }
            catch {
                $OutputBox.Dispatcher.Invoke({ 
                    $OutputBox.AppendText("Warning: Error disconnecting from Exchange Online: $_`r`n") 
                })
            }

            # Disconnect from Azure AD
            try {
                if (Get-Module -Name AzureAD -ErrorAction SilentlyContinue) {
                    $azureADConnection = Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue
                    if ($azureADConnection) {
                        Disconnect-AzureAD -ErrorAction Stop
                    }
                }
            }
            catch {
                $OutputBox.Dispatcher.Invoke({ 
                    $OutputBox.AppendText("Warning: Error disconnecting from Azure AD: $_`r`n") 
                })
            }

            # Success message
            $OutputBox.Dispatcher.Invoke({ 
                $OutputBox.AppendText("`r`n                             All active sessions have been terminated successfully.`r`n")
            })

            # Reset authentication flag
            $global:IsAuthenticated = $false
            
            # Update UI on completion
            $OutputBox.Dispatcher.Invoke({
                $ProgressBar.IsIndeterminate = $false
                $ProgressBar.Value = 100
                
                $boldText = New-Object System.Windows.Documents.Run
                $boldText.Text = "Disconnected"
                $boldText.FontWeight = [System.Windows.FontWeights]::Bold
                $ProgressTextBlock.Inlines.Clear()
                $ProgressTextBlock.Inlines.Add($boldText)
                
                # Reset button states
                $ConnectButton.Content = "Connect"
                $ConnectButton.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
                $ConnectButton.Foreground = [System.Windows.Media.Brushes]::White
                $ConnectButton.IsEnabled = $true

                $buttonsToUpdate = @($QueryButton, $SecureButton, $DisconnectButton)
                foreach ($button in $buttonsToUpdate) {
                    $button.IsEnabled = $false 
                    $button.Opacity = 0.5
                    $button.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
                }

                $ExitButton.IsEnabled = $true 
                $ExitButton.Background = New-Object System.Windows.Media.SolidColorBrush("#008000")
            })
        }
        catch {
            # Handle errors
            $OutputBox.Dispatcher.Invoke({
                $OutputBox.AppendText("`r`nError during disconnection process: $_`r`n")
                $OutputBox.AppendText("Stack Trace: $($_.ScriptStackTrace)`r`n")
                
                # Reset UI on error
                $ProgressBar.IsIndeterminate = $false
                $ProgressBar.Value = 0
                
                $boldText = New-Object System.Windows.Documents.Run
                $boldText.Text = "Disconnection Failed"
                $boldText.FontWeight = [System.Windows.FontWeights]::Bold
                $ProgressTextBlock.Inlines.Clear()
                $ProgressTextBlock.Inlines.Add($boldText)
                
                # Re-enable buttons
                $ConnectButton.IsEnabled = $true
                $DisconnectButton.IsEnabled = $true
                $QueryButton.IsEnabled = $true
                $SecureButton.IsEnabled = $true
                $ExitButton.IsEnabled = $true
            })
        }
    }).AddArgument($OutputBox).AddArgument($ProgressBar).AddArgument($ProgressTextBlock).AddArgument($ConnectButton).AddArgument($QueryButton).AddArgument($SecureButton).AddArgument($DisconnectButton).AddArgument($ExitButton)
    
    # Start the runspace
    $runspace.RunspacePool = $global:RunspacePool
    $handle = $runspace.BeginInvoke()
    
    # Optional: Store the runspace and handle for cleanup
    $script:currentDisconnectRunspace = @{
        PowerShell = $runspace
        Handle = $handle
    }
})

$QueryButton.Add_Click({
    $UPN = $TargetUPN.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($UPN) -or $UPN -eq "Enter target UPN") {
        [System.Windows.MessageBox]::Show("Please enter a valid User Principal Name.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return
    }
    $OutputBox.Clear()
  
  $ProgressBar.Dispatcher.Invoke([action] {
      $ProgressBar.Visibility = 'Visible'
      $ProgressBar.IsIndeterminate = $true
      $ProgressTextBlock.Visibility = 'Visible'
      $ProgressTextBlock.Inlines.Clear()
      $boldText = New-Object System.Windows.Documents.Run
      $boldText.Text = "Processing user query..."
      $boldText.FontWeight = [System.Windows.FontWeights]::Bold
      $ProgressTextBlock.Inlines.Add($boldText)
      $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Black
  })
  
  $writeOutputBox = {
      param([string]$text)
      $OutputBox.Dispatcher.Invoke([action] {
          $OutputBox.AppendText("$text`r`n")
      })
  }
  
  $updateProgressText = {
      param([string]$text)
      $ProgressTextBlock.Dispatcher.Invoke([action] {
          $ProgressTextBlock.Inlines.Clear()
          $boldText = New-Object System.Windows.Documents.Run
          $boldText.Text = $text
          $boldText.FontWeight = [System.Windows.FontWeights]::Bold
          $ProgressTextBlock.Inlines.Add($boldText)
      })
  }
  
  TypeOutputBoxMessage -OutputBox $OutputBox -Message "                  Retrieving user account information for $UPN, Please wait..."
  
  $startTime = Get-Date

  $runspace = [powershell]::Create().AddScript({
      param($UPN, $OutputBox, $ProgressBar, $ProgressTextBlock, $startTime, $writeOutputBox, $updateProgressText)
      
      try {
          Import-Module Microsoft.Graph.Users, Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Applications, Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
      
          $context = Get-MgContext
          if (-not $context) {
              throw "Not connected to Microsoft Graph. Please connect first."
          }
      
          & $updateProgressText "Collecting user details..."
          $userId = (Get-MgUser -Filter "UserPrincipalName eq '$UPN'" -Select Id).Id
          
          if (-not $userId) {
              throw "No user found with UPN: $UPN"
          }
      
          $user = Get-MgUser -UserId $userId -Property DisplayName, UserPrincipalName, Mail, AccountEnabled, CreatedDateTime, LastPasswordChangeDateTime, AssignedLicenses, SignInSessionsValidFromDateTime, UserType, OnPremisesSyncEnabled, SignInActivity -ErrorAction Stop
          
          if (-not $user) {
              throw "Failed to retrieve details for user with ID: $userId"
          }
      
          $OutputBox.Dispatcher.Invoke([action] { $OutputBox.Clear() })
          & $writeOutputBox "$([char]0x2022) User Details:"
          @('DisplayName', 'UserPrincipalName', 'Mail', 'AccountEnabled', 'CreatedDateTime', 'LastPasswordChangeDateTime', 'UserType', 'SignInSessionsValidFromDateTime') | ForEach-Object {
              $propertyName = $_
              & $writeOutputBox "  $([char]0x25E6) $propertyName`: $($user.$propertyName)"
          }
          
          $syncStatus = if ($null -eq $user.OnPremisesSyncEnabled -or $user.OnPremisesSyncEnabled -eq '') {
              "Not configured"
          } else {
              $user.OnPremisesSyncEnabled
          }
          $syncStatusMessage = if ($syncStatus -eq $true) {
              "This account is synced from an on-premises Active Directory!"
          } elseif ($syncStatus -eq $false) {
              "This account is not synced from an on-premises directory (cloud-only account)."
          } else {
              "The directory sync status is not configured."
          }
          #& $writeOutputBox "`r`n$([char]0x2022) Directory Sync Status: "
          #& $writeOutputBox "$syncStatusMessage"

          & $updateProgressText "Collecting group memberships..."
          & $writeOutputBox "`r`n$([char]0x2022) Group Memberships:"
          $groups = Get-MgUserMemberOf -UserId $userId -ErrorAction Stop
          if ($groups) {
              $groups | ForEach-Object { & $writeOutputBox "  $([char]0x25E6) $($_.AdditionalProperties.displayName)" }
          } else {
              & $writeOutputBox "  $([char]0x25E6) No group memberships found."
          }
      
          & $updateProgressText "Collecting assigned roles..."
          & $writeOutputBox "`r`n$([char]0x2022) Assigned Roles:"
          $roles = Get-MgUserAppRoleAssignment -UserId $userId -ErrorAction Stop
          if ($roles) {
              $roles | ForEach-Object { & $writeOutputBox "  $([char]0x25E6) $($_.AppRoleId)" }
          } else {
              & $writeOutputBox "  $([char]0x25E6) No assigned roles found."
          }
      
          & $updateProgressText "Collecting authentication methods..."
          & $writeOutputBox "`r`n$([char]0x2022) Authentication Methods:"
          $authMethods = Get-MgUserAuthenticationMethod -UserId $userId -ErrorAction Stop
          if ($authMethods) {
              $authMethods | ForEach-Object { & $writeOutputBox "  $([char]0x25E6) $($_.AdditionalProperties.'@odata.type'.Split('.')[-1])" }
          } else {
              & $writeOutputBox "  $([char]0x25E6) No authentication methods found."
          }
      
          & $updateProgressText "Collecting last sign-in activity..."
          & $writeOutputBox "`r`n$([char]0x2022) Last Sign-In Activity:"
          if ($user.SignInActivity) {
              & $writeOutputBox "  $([char]0x25E6) Last Interactive Sign-In: $($user.SignInActivity.LastSignInDateTime)"
              & $writeOutputBox "  $([char]0x25E6) Last Non-Interactive Sign-In: $($user.SignInActivity.LastNonInteractiveSignInDateTime)"
          } else {
              & $writeOutputBox "  $([char]0x25E6) No sign-in activity found."
          }

          $endTime = Get-Date
          $duration = $endTime - $startTime       
          & $writeOutputBox "`r$([char]0x2022) User attribute query complete!"
          & $writeOutputBox "  $([char]0x25E6) Execution Time: $($duration.TotalSeconds.ToString("F2")) seconds."
          
          $ProgressBar.Dispatcher.Invoke([action] {
              $ProgressBar.IsIndeterminate = $false
              $ProgressBar.Value = 100
          })
          $ProgressTextBlock.Dispatcher.Invoke([action] {
            $ProgressTextBlock.Inlines.Clear()
            $boldText = New-Object System.Windows.Documents.Run
            $boldText.Text = "Query Complete."
            $boldText.FontWeight = [System.Windows.FontWeights]::Bold
            $ProgressTextBlock.Inlines.Add($boldText)
            $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::White
        })
        
        # Wait for 2 seconds
        Start-Sleep -Seconds 2
        
        $ProgressTextBlock.Dispatcher.Invoke([action] {
            $ProgressTextBlock.Inlines.Clear()
            $boldText = New-Object System.Windows.Documents.Run
            $boldText.Text = "Ready for action!"
            $boldText.FontWeight = [System.Windows.FontWeights]::Bold
            $ProgressTextBlock.Inlines.Add($boldText)
            $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::White
        })
      }
      catch {
          $endTime = Get-Date
          $duration = $endTime - $startTime
          & $writeOutputBox "Failed to query account: $_"
          #& $writeOutputBox "Stack Trace: $($_.ScriptStackTrace)"
          & $writeOutputBox "Query failed after $($duration.TotalSeconds.ToString("F2")) seconds."
          
          $ProgressBar.Dispatcher.Invoke([action] {
              $ProgressBar.IsIndeterminate = $false
              $ProgressBar.Value = 0
          })
          $ProgressTextBlock.Dispatcher.Invoke([action] {
              $ProgressTextBlock.Inlines.Clear()
              $boldText = New-Object System.Windows.Documents.Run
              $boldText.Text = "Query failed after $($duration.TotalSeconds.ToString("F2")) seconds"
              $boldText.FontWeight = [System.Windows.FontWeights]::Bold
              $ProgressTextBlock.Inlines.Add($boldText)
              $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
          })
      }
  }).AddArgument($UPN).AddArgument($OutputBox).AddArgument($ProgressBar).AddArgument($ProgressTextBlock).AddArgument($startTime).AddArgument($writeOutputBox).AddArgument($updateProgressText)
  
  $runspace.RunspacePool = $global:RunspacePool
  $runspace.BeginInvoke()
})

$SecureButton.Add_Click({
    # Disable buttons immediately to show processing
    $SecureButton.IsEnabled = $false
    $QueryButton.IsEnabled = $false
    $DisconnectButton.IsEnabled = $false
    
    try {
        $UPN = $TargetUPN.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($UPN) -or $UPN -eq "Enter target UPN") {
            [System.Windows.MessageBox]::Show("Please enter a valid User Principal Name.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            return
        }
        
        # Run remediation in background thread
        $window.Dispatcher.BeginInvoke([Action]{
            if ($LockDownWForensicsToggleSwitch.IsChecked -eq $true) {
                $script:currentRemediationRunspace = Start-LockdownComprehensiveUser
            } elseif ($ForensicsOnlyToggleSwitch.IsChecked -eq $true) {
                $script:currentRemediationRunspace = Start-ForensicsOnly
            } elseif ($LockdownOnlyToggleSwitch.IsChecked -eq $true) {
                $script:currentRemediationRunspace = Start-LockdownOnly -UPN $UPN
            }
        }, [System.Windows.Threading.DispatcherPriority]::Background)
    }
    finally {
        # Re-enable buttons
        $SecureButton.IsEnabled = $true 
        $QueryButton.IsEnabled = $true
        $DisconnectButton.IsEnabled = $true
    }
})

$ExitButton.Add_Click({
  $window.Close()
})

$window.Add_Loaded({
    $window.ResizeMode = 'CanMinimize'
    $window.WindowStyle = 'SingleBorderWindow'
    $script:writeOutputBox = {
        param([string]$text)
        $OutputBox.Dispatcher.Invoke([action] {
            $OutputBox.AppendText("$text`r`n")
            $OutputBox.ScrollToEnd()
        })
    }
    
  # Initialize controls
  $script:controls = @("OutputBox", "TargetUPN", "ConnectButton", "QueryButton", "SecureButton", "DisconnectButton", "ExitButton", "ProgressBar", "ProgressTextBlock", "TerminateButton")
  $script:controls | ForEach-Object { 
      Set-Variable -Name $_ -Value $window.FindName($_) -Scope Script
  }

  $script:menuControls = @("ClearMenuItem", "ExitMenuItem", "DarkModeMenuItem", "AboutMenuItem", "DevMenuItem", "AbortMenuItem", "TerminateMenuItem")
  $script:menuControls | ForEach-Object { 
      Set-Variable -Name $_ -Value $window.FindName($_) -Scope Script
  }

  # Get toggle switch controls
  $script:LockDownWForensicsToggleSwitch = $window.FindName("LockDownWForensicsToggleSwitch")
  $script:ForensicsOnlyToggleSwitch = $window.FindName("ForensicsOnlyToggleSwitch")
  $script:LockdownOnlyToggleSwitch = $window.FindName("LockdownOnlyToggleSwitch")
  $script:EnableDeviceHandler = {
    $selectedDevice = $deviceListView.SelectedItem
    if ($selectedDevice) {
        try {
            $progressBar.IsIndeterminate = $true
            $progressTextBlock.Text = "Enabling device..."

            # Determine the correct URI and body based on device type
            if ($selectedDevice.DeviceType -eq "Mobile") {
                $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($selectedDevice.Id)"
                $body = @{
                    "managementState" = "managed"
                } | ConvertTo-Json
            } else {
                $uri = "https://graph.microsoft.com/v1.0/devices/$($selectedDevice.Id)"
                $body = @{
                    "accountEnabled" = $true
                } | ConvertTo-Json
            }

            # Make the API call to enable the device
            $response = Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body -ContentType "application/json"
            $writeOutputBox.Invoke("Device enable request sent. Response: " + ($response | ConvertTo-Json -Depth 1))

            # Wait for 5 seconds
            Start-Sleep -Seconds 5

            # Check the updated device status
            $updatedDevice = Invoke-MgGraphRequest -Method GET -Uri $uri
            $writeOutputBox.Invoke("Updated device details: " + ($updatedDevice | ConvertTo-Json -Depth 1))

            if ($selectedDevice.DeviceType -eq "Mobile") {
                $updatedStatus = if ($null -ne $updatedDevice.managementState) {
                    $updatedDevice.managementState
                } else {
                    "Unknown"
                }
            } else {
                $updatedStatus = if ($updatedDevice.accountEnabled) { "Enabled" } else { "Disabled" }
            }
            $writeOutputBox.Invoke("Updated device status: $updatedStatus")

            # Refresh the device list
            & $script:GetDeviceDetailsHandler
        }
        catch {
            $errorMessage = "Error enabling device: $_`nStack Trace:`n$($_.ScriptStackTrace)"
            $writeOutputBox.Invoke($errorMessage)
            [System.Windows.MessageBox]::Show($errorMessage, "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
        finally {
            $progressBar.IsIndeterminate = $false
            $progressTextBlock.Text = ""
        }
    }
    else {
        [System.Windows.MessageBox]::Show("Please select a device first.", "No Device Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
    }
}  

$AbortMenuItem.Add_Click({
    try {
        # Set the abort flag
        $script:abortRemediation = $true
        
        # Update UI to show abort in progress
        $OutputBox.Dispatcher.Invoke([Action]{
            #$OutputBox.AppendText("`r`n  $([char]0x25E6) Aborting remediation process...`r`n")
            $OutputBox.ScrollToEnd()
            
            $ProgressBar.IsIndeterminate = $true
            $ProgressTextBlock.Inlines.Clear()
            $boldText = New-Object System.Windows.Documents.Run
            $boldText.Text = "Aborting..."
            $boldText.FontWeight = [System.Windows.FontWeights]::Bold
            $ProgressTextBlock.Inlines.Add($boldText)
            $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
        })

        # Stop the current remediation runspace if it exists
        if ($script:currentRemediationRunspace) {
            if ($script:currentRemediationRunspace.PowerShell) {
                # Stop all running jobs in the runspace
                $script:currentRemediationRunspace.PowerShell.Stop()
                
                # Handle the EndInvoke call safely
                try {
                    $script:currentRemediationRunspace.PowerShell.EndInvoke($script:currentRemediationRunspace.Handle)
                }
                catch {
                    # Expected exception when stopping a pipeline, can be safely ignored
                    $OutputBox.Dispatcher.Invoke([Action]{
                        #$OutputBox.AppendText("Safely handling pipeline termination...`r`n")
                    })
                }
                
                $script:currentRemediationRunspace.PowerShell.Dispose()
            }
            
            # Clear the runspace reference
            $script:currentRemediationRunspace = $null
        }

        # Cancel any pending operations
        if ($script:remediationCancellationSource) {
            $script:remediationCancellationSource.Cancel()
            $script:remediationCancellationSource.Dispose()
            $script:remediationCancellationSource = $null
        }

        # Clean up any remaining sessions
        Get-PSSession | Where-Object { 
            $_.Name -like "*Remediation*" -or 
            $_.Name -like "*Forensics*" 
        } | Remove-PSSession -ErrorAction SilentlyContinue

        # Force garbage collection
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        
        # Update UI after abort completes
        $OutputBox.Dispatcher.Invoke([Action]{
            $OutputBox.AppendText("`r`n  $([char]0x25E6) Remediation process aborted successfully!`r`n")
            $OutputBox.ScrollToEnd()
            
            $ProgressBar.Value = 0
            $ProgressBar.IsIndeterminate = $false
            
            $ProgressTextBlock.Inlines.Clear()
            $boldText = New-Object System.Windows.Documents.Run
            $boldText.Text = "Remediation Aborted"
            $boldText.FontWeight = [System.Windows.FontWeights]::Bold
            $ProgressTextBlock.Inlines.Add($boldText)
            $ProgressTextBlock.Foreground = [System.Windows.Media.Brushes]::Green
            
            # Re-enable buttons
            $SecureButton.IsEnabled = $true
            $QueryButton.IsEnabled = $true
            $DisconnectButton.IsEnabled = $true
            $AbortMenuItem.IsEnabled = $false
        })
    }
    catch {
        $errorMessage = "Error during abort: $_`nStack Trace:`n$($_.ScriptStackTrace)"
        $OutputBox.Dispatcher.Invoke([Action]{
            $OutputBox.AppendText("$errorMessage`r`n")
            $OutputBox.ScrollToEnd()
        })
    }
    finally {
        # Reset abort flag
        $script:abortRemediation = $false
    }
})
  # Attach event handlers to toggle switches
  Set-ToggleSwitchHandlers
  
    # Get the TargetUPN textbox
    $TargetUPN = $window.FindName("TargetUPN")

    # Set initial text and color
    $TargetUPN.Text = "Enter target UPN"
    $TargetUPN.Background = if ($DarkMode) { [System.Windows.Media.Brushes]::Black } else { [System.Windows.Media.Brushes]::White }
    $TargetUPN.Foreground = if ($DarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }

    # Add GotFocus event handler
    $TargetUPN.Add_GotFocus({
        if ($this.Text -eq "Enter target UPN") {
            $this.Text = ""
            #$this.Background = if ($DarkMode) { [System.Windows.Media.Brushes]::Black } else { [System.Windows.Media.Brushes]::White }
            #$this.Foreground = if ($DarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
        }
    })

    # Add LostFocus event handler
    $TargetUPN.Add_LostFocus({
        if ([string]::IsNullOrWhiteSpace($this.Text)) {
            $this.Text = "Enter target UPN"
            #$this.Background = if ($DarkMode) { [System.Windows.Media.Brushes]::Black } else { [System.Windows.Media.Brushes]::White }
            #$this.Foreground = if ($DarkMode) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.Brushes]::Black }
        }
    })
  
  $LockDownWForensicsToggleSwitch.IsChecked = $true
  $ForensicsOnlyToggleSwitch.IsChecked = $false
  $LockdownOnlyToggleSwitch.IsChecked = $false
  $LockDownWForensicsToggleSwitch.IsEnabled = $true
  $ForensicsOnlyToggleSwitch.IsEnabled = $true
  $LockdownOnlyToggleSwitch.IsEnabled = $true

  # Apply dark mode preference on startup
  $darkModePreference = Get-DarkModePreference
  Set-DarkMode -IsDarkMode $darkModePreference

$DarkModeMenuItem.Add_Click({
    $script:IsDarkMode = !$script:IsDarkMode
    Set-DarkMode -IsDarkMode $script:IsDarkMode
    # Update AuditLogWindow if it's open
    if ($script:AuditLogWindow -ne $null -and $script:AuditLogWindow.IsLoaded) {
        Update-AuditLogWindowTheme
    }
})

  # Set initial OutputBox content
  $OutputBox.AppendText("                              Welcome to the M365 Breach Remediation Toolkit v$ScriptVersion`r`n`r`n")
  
  # Update UI elements
  $ConnectButton.IsEnabled = $false
  $ConnectButton.Style = $window.FindResource("PressableButtonStyle")

  $QueryButton.IsEnabled = $false
  $QueryButton.Opacity = 0.5
  $QueryButton.Background = [System.Windows.Media.Brushes]::LightGray
  $QueryButton.Foreground = [System.Windows.Media.Brushes]::DarkGray
    
  $SecureButton.IsEnabled = $false
  $SecureButton.Opacity = 0.5
  $SecureButton.Background = [System.Windows.Media.Brushes]::LightGray
  $SecureButton.Foreground = [System.Windows.Media.Brushes]::DarkGray
  
  $DisconnectButton.IsEnabled = $false
  $DisconnectButton.Opacity = 0.5
  $DisconnectButton.Background = [System.Windows.Media.Brushes]::LightGray
  $DisconnectButton.Foreground = [System.Windows.Media.Brushes]::DarkGray

  # Display the progress bar with "Not Connected" text
  $ProgressBar.Visibility = "Visible"
  $ProgressBar.IsIndeterminate = $false
  $ProgressBar.Value = 0
  $ProgressBar.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#09ca44')
    
  $ProgressTextBlock.Visibility = "Visible"
    
  # Create a new Run with bold, black text
  $boldText = New-Object System.Windows.Documents.Run
  $boldText.Text = "Not Connected"
  $boldText.FontWeight = [System.Windows.FontWeights]::Bold
  $boldText.Foreground = [System.Windows.Media.Brushes]::Black
    
  # Clear existing inlines and add the new bold text
  $ProgressTextBlock.Inlines.Clear()
  $ProgressTextBlock.Inlines.Add($boldText)

  # Add newlines to push the typed message to the bottom
  $OutputBox.AppendText("`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n")

  $AbortMenuItem.IsEnabled = $false
  $TerminateMenuItem.IsEnabled = $false
  $EnableDeviceMenuItem.IsEnabled = $false
  # Schedule icon loading to occur after the window has loaded
  $window.Dispatcher.BeginInvoke([Action]{
      Load-MenuIcons
  }, [System.Windows.Threading.DispatcherPriority]::Background)

  # Type out the message at the bottom of the OutputBox
  #& $writeOutputBox "            Click the 'Connect' button to get started."
  TypeOutputBoxMessage -OutputBox $OutputBox -Message "            Click the 'Connect' button to get started"
  
  # Ensure the OutputBox is scrolled to the end
  $OutputBox.ScrollToEnd()
})
#endregion

#region Splash Screen
$scriptPath = $PSScriptRoot
if (-not $scriptPath) {
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
}

$splashImagePath = Join-Path $scriptPath "fsir.png"
Show-SplashScreen -ImagePath $splashImagePath -Duration 3000 -ImageWidth 300 -ImageHeight 300
#endregion


#region Show Window
$window.ShowDialog()
#endregion
