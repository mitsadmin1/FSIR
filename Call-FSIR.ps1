$scriptDirectory = "C:\temp\FSIR"
$FSIR = "C:\temp\FSIR\FSIR-Toolkit.ps1"
$trackerFile = "C:\temp\FSIR\fsir_initialized.track"

set-location -Path $scriptDirectory

if (Test-Path $scriptDirectory) {
    Write-Output "Directory exists: $scriptDirectory"
} else {
    Write-Output "Directory does not exist: $scriptDirectory"
    New-Item -ItemType Directory -Path $scriptDirectory
}

# Check if tracker file exists
if (Test-Path $trackerFile) {
    Write-Output "Loading Future State IR Toolkit..."
    
    # Create a shortcut that uses the custom icon
    $shortcutPath = Join-Path $env:TEMP "FSIR-Toolkit.lnk"
    $iconPath = Join-Path $scriptDirectory "fsir.ico"
    
    try {
        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($shortcutPath)
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FSIR`""
        if (Test-Path $iconPath) {
            $Shortcut.IconLocation = $iconPath
        }
        $Shortcut.Save()
        
        # Launch via the shortcut
        Start-Process -FilePath $shortcutPath
    }
    catch {
        # Fallback to direct launch if shortcut creation fails
        $Process = Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$FSIR`"" -WindowStyle Hidden -PassThru
    }
    exit
}

# If we get here, this is first run - proceed with initialization
Write-Output "`r`nFirst run detected - performing initial setup..."



function Download-Icons {
    param (
        [hashtable]$IconUrls
    )

    Write-Output "Downloading icons to icons folder..."
    
    # Create a thread-safe hashtable to store the results
    $results = [System.Collections.Concurrent.ConcurrentDictionary[string,bool]]::new()
    $iconFolder = "C:\temp\FSIR\icons"
    if (-not (Test-Path $iconFolder)) {
        Write-Output "Creating icons directory: $iconFolder"
        New-Item -ItemType Directory -Path $iconFolder -Force | Out-Null
    }
    # Create a runspace pool
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
    $runspacePool.Open()

    # Create an array to hold the runspace handles
    $runspaces = @()

    foreach ($icon in $IconUrls.GetEnumerator()) {
        $powershell = [powershell]::Create().AddScript({
            param($name, $url, $iconFolder, $results)

            try {
                # Ensure the directory exists in each runspace
                if (-not (Test-Path $iconFolder)) {
                    New-Item -ItemType Directory -Path $iconFolder -Force | Out-Null
                }
                
                $outFile = Join-Path $iconFolder ($name + [System.IO.Path]::GetExtension($url))
                Invoke-WebRequest -Uri $url -OutFile $outFile -UseBasicParsing -ErrorAction Stop -TimeoutSec 30
                $results[$name] = $true
            }
            catch {
                $results[$name] = $false
                # Could log error here if needed: Write-Host "Failed to download $name from $url : $_"
            }
        }).AddArgument($icon.Key).AddArgument($icon.Value).AddArgument($iconFolder).AddArgument($results)

        $powershell.RunspacePool = $runspacePool

        $runspaces += [PSCustomObject]@{
            Pipe = $powershell
            Status = $powershell.BeginInvoke()
        }
    }

    # Wait for all runspaces to complete
    $runspaces | ForEach-Object {
        $_.Pipe.EndInvoke($_.Status)
        $_.Pipe.Dispose()
    }

    # Close the runspace pool
    $runspacePool.Close()
    $runspacePool.Dispose()

    # Report results
    $successCount = ($results.Values | Where-Object { $_ -eq $true }).Count
    $totalCount = $results.Count
    Write-Output "Downloaded $successCount of $totalCount icons successfully."
    
    # Return the results
    return $results
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
    "fsir" = "https://axcientrestore.blob.core.windows.net/win11/resources/fsir.ico"
}
Download-Icons -IconUrls $iconUrls

# Check for NuGet Provider
Write-Output "`r`nChecking for required modules and package provider..."
$nugetProvider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue

if ($nugetProvider) {
    #Write-Output "NuGet provider is installed. Version: $($nugetProvider.Version)"
} else {
    Write-Output "NuGet provider is NOT installed."
    Write-Output "Installing package provider, please wait..."
    irm "https://raw.githubusercontent.com/wju10755/o365AuditParser/master/Check-Modules.ps1" | Invoke-Expression
}

$scriptPath = Join-Path $scriptDirectory "FSIR-Toolkit.ps1"
if (Test-Path $scriptPath) {
    Invoke-WebRequest -OutFile .\fsir.png https://axcientrestore.blob.core.windows.net/win11/resources/fsir.png | Out-Null   
} else {
    Write-Output "[ERROR] Could not find FSIR-Toolkit.ps1 at: $scriptPath"
    Write-Output "Current location: $PSScriptRoot"
    exit 1
}


# List of modules to check
$modules = @('Microsoft.Graph.Users', 'MSAL.PS', 'ExchangeOnlineManagement')

foreach ($module in $modules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Output "Module $module is not installed. Installing now..."
        Install-Module -Name $module -Force -AllowClobber
        Write-Output " done."
    } else {
        #Write-Output "Module $module is already installed."
    }
}

# Create tracker file with timestamp
$initializationData = @{
    InitializedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Version = "1.0"
    Path = $scriptDirectory
} | ConvertTo-Json

# Create tracker file
$initializationData | Out-File -FilePath $trackerFile -Force

Write-Output "Initial setup complete. Loading FSIR Toolkit..."

# Create a shortcut that uses the custom icon
$shortcutPath = Join-Path $env:TEMP "FSIR-Toolkit.lnk"
$iconPath = Join-Path $scriptDirectory "fsir.ico"

try {
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FSIR`""
    if (Test-Path $iconPath) {
        $Shortcut.IconLocation = $iconPath
    }
    $Shortcut.Save()
    
    # Launch via the shortcut
    Start-Process -FilePath $shortcutPath
}
catch {
    # Fallback to direct launch if shortcut creation fails
    $Process = Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$FSIR`"" -WindowStyle Hidden -PassThru
}

