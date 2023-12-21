################################################################################
##  File:  
##  Desc:  Functions
################################################################################

function Install-Binary {
    <#
    .SYNOPSIS
        A function to install binaries from either a URL or a local path.

    .DESCRIPTION
        This function downloads and installs .exe or .msi binaries from a specified URL or a local path. It also supports checking the binary's signature and SHA256/SHA512 sum before installation.

    .PARAMETER Url
        The URL from which the binary will be downloaded. This parameter is required if LocalPath is not specified.

    .PARAMETER LocalPath
        The local path of the binary to be installed. This parameter is required if Url is not specified.

    .PARAMETER Type
        The type of the binary to be installed. Valid values are "MSI" and "EXE". If not specified, the type is inferred from the file extension.

    .PARAMETER InstallArgs
        The list of arguments that will be passed to the installer. Cannot be used together with ExtraInstallArgs.

    .PARAMETER ExtraInstallArgs
        Additional arguments that will be passed to the installer. Cannot be used together with InstallArgs.

    .PARAMETER ExpectedSignature
        The expected signature of the binary. If specified, the binary's signature is checked before installation.

    .PARAMETER ExpectedSHA256Sum
        The expected SHA256 sum of the binary. If specified, the binary's SHA256 sum is checked before installation.

    .PARAMETER ExpectedSHA512Sum
        The expected SHA512 sum of the binary. If specified, the binary's SHA512 sum is checked before installation.

    .EXAMPLE
        Install-Binary -Url "https://go.microsoft.com/fwlink/p/?linkid=2083338" -Type EXE -InstallArgs ("/features", "+", "/quiet") -ExpectedSignature "A5C7D5B7C838D5F89DDBEDB85B2C566B4CDA881F"
    #>

    Param
    (
        [Parameter(Mandatory, ParameterSetName = "Url")]
        [String] $Url,
        [Parameter(Mandatory, ParameterSetName = "LocalPath")]
        [String] $LocalPath,
        [ValidateSet("MSI", "EXE")]
        [String] $Type,
        [String[]] $InstallArgs,
        [String[]] $ExtraInstallArgs,
        [String[]] $ExpectedSignature,
        [String] $ExpectedSHA256Sum,
        [String] $ExpectedSHA512Sum
    )

    if ($PSCmdlet.ParameterSetName -eq "LocalPath") {
        if (-not (Test-Path -Path $LocalPath)) {
            throw "LocalPath parameter is specified, but the file does not exist."
        }
        if (-not $Type) {
            $Type = ([System.IO.Path]::GetExtension($LocalPath)).Replace(".", "").ToUpper()
            if ($Type -ne "MSI" -and $Type -ne "EXE") {
                throw "LocalPath parameter is specified, but the file extension is not .msi or .exe. Please specify the Type parameter."
            }
        }
        $filePath = $LocalPath
    } else {
        if (-not $Type) {
            $Type = ([System.IO.Path]::GetExtension($Url)).Replace(".", "").ToUpper()
            if ($Type -ne "MSI" -and $Type -ne "EXE") {
                throw "Cannot determine the file type from the URL. Please specify the Type parameter."
            }
            $fileName = [System.IO.Path]::GetFileName($Url)
        } else {
            $fileName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName()) + ".$Type".ToLower()
        }
        $filePath = Invoke-DownloadWithRetry -Url $Url -Path "${env:Temp}\$fileName"
    }

    if ($PSBoundParameters.ContainsKey('ExpectedSignature')) {
        if ($ExpectedSignature) {
            Test-FileSignature -Path $filePath -ExpectedThumbprint $ExpectedSignature
        } else {
            throw "ExpectedSignature parameter is specified, but no signature is provided."
        }
    }

    if ($ExpectedSHA256Sum) {
        Test-FileChecksum $filePath -ExpectedSHA256Sum $ExpectedSHA256Sum
    }

    if ($ExpectedSHA512Sum) {
        Test-FileChecksum $filePath -ExpectedSHA512Sum $ExpectedSHA512Sum
    }

    if ($ExtraInstallArgs -and $InstallArgs) {
        throw "InstallArgs and ExtraInstallArgs parameters cannot be used together."
    }
 
    if ($Type -eq "MSI") {
        # MSI binaries should be installed via msiexec.exe
        if ($ExtraInstallArgs) {
            $InstallArgs = @('/i', $filePath, '/qn', '/norestart') + $ExtraInstallArgs
        } elseif (-not $InstallArgs) {
            Write-Host "No arguments provided for MSI binary. Using default arguments: /i, /qn, /norestart"
            $InstallArgs = @('/i', $filePath, '/qn', '/norestart')
        }
        $filePath = "msiexec.exe"
    } else {
        # EXE binaries should be started directly
        if ($ExtraInstallArgs) {
            $InstallArgs = $ExtraInstallArgs
        }
    }

    $installStartTime = Get-Date
    Write-Host "Starting Install $Name..."
    try {
        $process = Start-Process -FilePath $filePath -ArgumentList $InstallArgs -Wait -PassThru
        $exitCode = $process.ExitCode
        $installCompleteTime = [math]::Round(($(Get-Date) - $installStartTime).TotalSeconds, 2)
        if ($exitCode -eq 0) {
            Write-Host "Installation successful in $installCompleteTime seconds"
        } elseif ($exitCode -eq 3010) {
            Write-Host "Installation successful in $installCompleteTime seconds. Reboot is required."
        } else {
            Write-Host "Installation process returned unexpected exit code: $exitCode"
            Write-Host "Time elapsed: $installCompleteTime seconds"
            exit $exitCode
        }
    } catch {
        $installCompleteTime = [math]::Round(($(Get-Date) - $installStartTime).TotalSeconds, 2)
        Write-Host "Installation failed in $installCompleteTime seconds"
    }
}

function Invoke-DownloadWithRetry {
    <#
    .SYNOPSIS
        Downloads a file from a given URL with retry functionality.

    .DESCRIPTION
        The Invoke-DownloadWithRetry function downloads a file from the specified URL
        to the specified path. It includes retry functionality in case the download fails.

    .PARAMETER Url
        The URL of the file to download.

    .PARAMETER Path
        The path where the downloaded file will be saved. If not provided, a temporary path
        will be used.

    .EXAMPLE
        Invoke-DownloadWithRetry -Url "https://example.com/file.zip" -Path "C:\Downloads\file.zip"
        Downloads the file from the specified URL and saves it to the specified path.

    .EXAMPLE
        Invoke-DownloadWithRetry -Url "https://example.com/file.zip"
        Downloads the file from the specified URL and saves it to a temporary path.
    
    .OUTPUTS
        The path where the downloaded file is saved.
    #>

    Param
    (
        [Parameter(Mandatory)]
        [string] $Url,
        [Alias("Destination")]
        [string] $Path
    )

    if (-not $Path) {
        $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
        $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
        $fileName = [IO.Path]::GetFileName($Url) -replace $re

        if ([String]::IsNullOrEmpty($fileName)) {
            $fileName = [System.IO.Path]::GetRandomFileName()
        }
        $Path = Join-Path -Path "${env:Temp}" -ChildPath $fileName
    }

    Write-Host "Downloading package from $Url to $Path..."

    $interval = 30
    $downloadStartTime = Get-Date
    for ($retries = 20; $retries -gt 0; $retries--) {
        try {
            $attemptStartTime = Get-Date
            (New-Object System.Net.WebClient).DownloadFile($Url, $Path)
            $attemptSeconds = [math]::Round(($(Get-Date) - $attemptStartTime).TotalSeconds, 2)
            Write-Host "Package downloaded in $attemptSeconds seconds"
            break
        } catch {
            $attemptSeconds = [math]::Round(($(Get-Date) - $attemptStartTime).TotalSeconds, 2)
            Write-Warning "Package download failed in $attemptSeconds seconds"
            Write-Warning $_.Exception.Message

            if ($_.Exception.InnerException.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound) {
                Write-Warning "Request returned 404 Not Found. Aborting download."
                $retries = 0
            }
        }
            
        if ($retries -eq 0) {
            $totalSeconds = [math]::Round(($(Get-Date) - $downloadStartTime).TotalSeconds, 2)
            throw "Package download failed after $totalSeconds seconds"
        }

        Write-Warning "Waiting $interval seconds before retrying (retries left: $retries)..."
        Start-Sleep -Seconds $interval
    }

    return $Path
}

function Test-FileSignature {
    <#
    .SYNOPSIS
        Tests the file signature of a given file.

    .DESCRIPTION
        The Test-FileSignature function checks the signature of a file against the expected thumbprints. 
        It uses the Get-AuthenticodeSignature cmdlet to retrieve the signature information of the file.
        If the signature status is not valid or the thumbprint does not match the expected thumbprints, an exception is thrown.

    .PARAMETER Path
        Specifies the path of the file to test.

    .PARAMETER ExpectedThumbprint
        Specifies the expected thumbprints to match against the file's signature.

    .EXAMPLE
        Test-FileSignature -Path "C:\Path\To\File.exe" -ExpectedThumbprint "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0"

        This example tests the signature of the file "C:\Path\To\File.exe" against the expected thumbprint "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0".

    #>
    
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Path,
        [Parameter(Mandatory = $true)]
        [string[]] $ExpectedThumbprint
    )

    $signature = Get-AuthenticodeSignature $Path

    if ($signature.Status -ne "Valid") {
        throw "Signature status is not valid. Status: $($signature.Status)"
    }
    
    foreach ($thumbprint in $ExpectedThumbprint) {
        if ($signature.SignerCertificate.Thumbprint.Contains($thumbprint)) {
            Write-Output "Signature for $Path is valid"
            $signatureMatched = $true
            return
        }
    }

    if ($signatureMatched) {
        Write-Output "Signature for $Path is valid"
    } else {
        throw "Signature thumbprint do not match expected."
    }
}

function Update-Environment {
    <#
    .SYNOPSIS
        Updates the environment variables by reading values from the registry.

    .DESCRIPTION
        This function updates current environment by reading values from the registry.
        It is useful when you need to update the environment variables without restarting the current session.

    .NOTES
        The function requires administrative privileges to modify the system registry.
    #>

    $locations = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
        'HKCU:\Environment'
    )

    # Update PATH variable
    $pathItems = $locations | ForEach-Object { 
        (Get-Item $_).GetValue('PATH').Split(';') 
    } | Select-Object -Unique
    $env:PATH = $pathItems -join ';'

    # Update other variables
    $locations | ForEach-Object {
        $key = Get-Item $_
        foreach ($name in $key.GetValueNames()) {
            $value = $key.GetValue($name)
            if (-not ($name -ieq 'PATH')) {
                Set-Item -Path Env:$name -Value $value
            } 
        }
    }
}


################################################################################
##  File:  Configure-BaseImage.ps1
##  Desc:  Prepare the base image for software installation
################################################################################

function Disable-InternetExplorerESC {
    $adminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $userKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $adminKey -Name "IsInstalled" -Value 0 -Force
    Set-ItemProperty -Path $userKey -Name "IsInstalled" -Value 0 -Force

    $ieProcess = Get-Process -Name Explorer -ErrorAction SilentlyContinue

    if ($ieProcess) {
        Stop-Process -Name Explorer -Force -ErrorAction Continue
    }

    Write-Host "IE Enhanced Security Configuration (ESC) has been disabled."
}

function Disable-InternetExplorerWelcomeScreen {
    $adminKey = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
    New-Item -Path $adminKey -Value 1 -Force
    Set-ItemProperty -Path $adminKey -Name "DisableFirstRunCustomize" -Value 1 -Force
    Write-Host "Disabled IE Welcome screen"
}

function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
    Write-Host "User Access Control (UAC) has been disabled."
}

function Disable-WindowsUpdate {
    $autoUpdatePath = "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (Test-Path -Path $autoUpdatePath) {
        Set-ItemProperty -Path $autoUpdatePath -Name NoAutoUpdate -Value 1
        Write-Host "Disabled Windows Update"
    } else {
        Write-Host "Windows Update key does not exist"
    }
}

# Enable $ErrorActionPreference='Stop' for AllUsersAllHosts
Add-Content -Path $profile.AllUsersAllHosts -Value '$ErrorActionPreference="Stop"'

Write-Host "Disable Server Manager on Logon"
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask

Write-Host "Disable 'Allow your PC to be discoverable by other PCs' popup"
New-Item -Path HKLM:\System\CurrentControlSet\Control\Network -Name NewNetworkWindowOff -Force

Write-Host 'Disable Windows Update Medic Service'
Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\WaaSMedicSvc -Name Start -Value 4 -Force

Write-Host "Disable Windows Update"
Disable-WindowsUpdate

Write-Host "Disable UAC"
Disable-UserAccessControl

Write-Host "Disable IE Welcome Screen"
Disable-InternetExplorerWelcomeScreen

Write-Host "Disable IE ESC"
Disable-InternetExplorerESC

Write-Host "Setting local execution policy"
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -ErrorAction Continue | Out-Null
Get-ExecutionPolicy -List

Write-Host "Enable long path behavior"
# See https://docs.microsoft.com/en-us/windows/desktop/fileio/naming-a-file#maximum-path-length-limitation
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1

# Expand disk size of OS drive
$driveLetter = "C"
$size = Get-PartitionSupportedSize -DriveLetter $driveLetter
Resize-Partition -DriveLetter $driveLetter -Size $size.SizeMax
Get-Volume | Select-Object DriveLetter, SizeRemaining, Size | Sort-Object DriveLetter

################################################################################
##  File:  Configure-DeveloperMode.ps1
##  Desc:  Enables Developer Mode by toggling registry setting. Developer Mode is required to enable certain tools (e.g. WinAppDriver). 
################################################################################

# Create AppModelUnlock if it doesn't exist, required for enabling Developer Mode
$registryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
if (-not(Test-Path -Path $registryKeyPath)) {
    New-Item -Path $registryKeyPath -ItemType Directory -Force
}

# Add registry value to enable Developer Mode
New-ItemProperty -Path $registryKeyPath -Name AllowDevelopmentWithoutDevLicense -PropertyType DWORD -Value 1

################################################################################
##  File:  Configure-Diagnostics.ps1
##  Desc:  Disables Just-In-Time Debugger and Windows Error Reporting
################################################################################

Write-Host "Disable Just-In-Time Debugger"

# Turn off Application Error Debugger
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger -Value "-" -Type String -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger -Value "-" -Type String -Force

# Turn off the Debug dialog
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name DbgManagedDebugger -Value "-" -Type String -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework" -Name DbgManagedDebugger -Value "-" -Type String -Force

# Disable the WER UI
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name DontShowUI -Value 1 -Type DWORD -Force
# Send all reports to the user's queue
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name ForceQueue -Value 1 -Type DWORD -Force
# Default consent choice 1 - Always ask (default)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" -Name DefaultConsent -Value 1 -Type DWORD -Force

################################################################################
##  File:  Configure-DotnetSecureChannel.ps1
##  Desc:  Configure .NET to use TLS 1.2
################################################################################

$registryPath = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
$name = "SchUseStrongCrypto"
$value = "1"
if (Test-Path $registryPath) {
    Set-ItemProperty -Path $registryPath -Name $name -Value $value -Type DWORD
}

$registryPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
if (Test-Path $registryPath) {
    Set-ItemProperty -Path $registryPath -Name $name -Value $value -Type DWORD
}

################################################################################
##  File:  Configure-DynamicPort.ps1
##  Desc:  Configure dynamic port range for TCP and UDP to start at port 49152
##         and to end at the 65536 (16384 ports)
################################################################################

# https://support.microsoft.com/en-us/help/929851/the-default-dynamic-port-range-for-tcp-ip-has-changed-in-windows-vista
# The new default start port is 49152, and the new default end port is 65535.
# Default port configuration was changed during image generation by Visual Studio Enterprise Installer to:
#   Protocol tcp Dynamic Port Range
#   ---------------------------------
#   Start Port      : 1024
#   Number of Ports : 64511

Write-Host "Set the dynamic port range to start at port 49152 and to end at the 65536 (16384 ports)"
foreach ($ipVersion in @("ipv4", "ipv6")) {
    foreach ($protocol in @("tcp", "udp")) {
        $command = "netsh int $ipVersion set dynamicport $protocol start=49152 num=16384"
        Invoke-Expression $command | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to set dynamic port range for $ipVersion $protocol"
            exit $LASTEXITCODE
        }
    }
}

Invoke-PesterTests -TestFile "WindowsFeatures" -TestName "DynamicPorts"

################################################################################
##  File:  Configure-GDIProcessHandleQuota.ps1
##  Desc:  Set the GDIProcessHandleQuota value to 20000
################################################################################

# https://docs.microsoft.com/en-us/windows/win32/sysinfo/gdi-objects
# This value can be set to a number between 256 and 65,536

$defaultValue = 20000
Write-Host "Set the GDIProcessHandleQuota value to $defaultValue"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name GDIProcessHandleQuota -Value $defaultValue
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -Name GDIProcessHandleQuota -Value $defaultValue

Invoke-PesterTests -TestFile "WindowsFeatures" -TestName "GDIProcessHandleQuota"

################################################################################
##  File:  Configure-ImageDataFile.ps1
##  Desc:  Creates a JSON file with information about the image
################################################################################

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$caption = $os.Caption
$osName = $caption.Substring(0, $caption.LastIndexOf(" "))
$osEdition = $caption.Substring($caption.LastIndexOf(" ") + 1)
$osVersion = $os.Version
$imageVersion = $env:IMAGE_VERSION
$imageVersionComponents = $imageVersion.Split('.')
$imageMajorVersion = $imageVersionComponents[0]
$imageMinorVersion = $imageVersionComponents[1]
$imageDataFile = $env:IMAGEDATA_FILE
$githubUrl = "https://github.com/actions/runner-images/blob"

if (Test-IsWin22) {
    $imageLabel = "windows-2022"
    $softwareUrl = "${githubUrl}/win22/$imageMajorVersion.$imageMinorVersion/images/windows/Windows2022-Readme.md"
    $releaseUrl = "https://github.com/actions/runner-images/releases/tag/win22%2F$imageMajorVersion.$imageMinorVersion"
} elseif (Test-IsWin19) {
    $imageLabel = "windows-2019"
    $softwareUrl = "${githubUrl}/win19/$imageMajorVersion.$imageMinorVersion/images/windows/Windows2019-Readme.md"
    $releaseUrl = "https://github.com/actions/runner-images/releases/tag/win19%2F$imageMajorVersion.$imageMinorVersion"
} else {
    throw "Invalid platform version is found. Either Windows Server 2019 or 2022 are required"
}

$json = @"
[
  {
    "group": "Operating System",
    "detail": "${osName}\n${osVersion}\n${osEdition}"
  },
  {
    "group": "Runner Image",
    "detail": "Image: ${imageLabel}\nVersion: ${imageVersion}\nIncluded Software: ${softwareUrl}\nImage Release: ${releaseUrl}"
  }
]
"@

$json | Out-File -FilePath $imageDataFile

################################################################################
##  File:  Configure-Powershell.ps1
##  Desc:  Manage PowerShell configuration
################################################################################

#region System
Write-Host "Setup PowerShellGet"
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

# Specifies the installation policy
Set-PSRepository -InstallationPolicy Trusted -Name PSGallery

Write-Host 'Warmup PSModuleAnalysisCachePath (speedup first powershell invocation by 20s)'
$PSModuleAnalysisCachePath = 'C:\PSModuleAnalysisCachePath\ModuleAnalysisCache'

[Environment]::SetEnvironmentVariable('PSModuleAnalysisCachePath', $PSModuleAnalysisCachePath, "Machine")
# make variable to be available in the current session
${env:PSModuleAnalysisCachePath} = $PSModuleAnalysisCachePath

New-Item -Path $PSModuleAnalysisCachePath -ItemType 'File' -Force | Out-Null
#endregion

#region User (current user, image generation only)
if (-not (Test-Path $profile)) {
    New-Item $profile -ItemType File -Force
}
  
@" 
  if ( -not(Get-Module -ListAvailable -Name PowerHTML)) {
      Install-Module PowerHTML -Scope CurrentUser 
  } 
  
  if ( -not(Get-Module -Name PowerHTML)) {
      Import-Module PowerHTML
  } 
"@ | Add-Content -Path $profile -Force

#endregion

# Create shells folder
$shellPath = "C:\shells"
New-Item -Path $shellPath -ItemType Directory | Out-Null

# add a wrapper for C:\msys64\usr\bin\bash.exe
@'
@echo off
setlocal
IF NOT DEFINED MSYS2_PATH_TYPE set MSYS2_PATH_TYPE=strict
IF NOT DEFINED MSYSTEM set MSYSTEM=mingw64
set CHERE_INVOKING=1
C:\msys64\usr\bin\bash.exe -leo pipefail %*
'@ | Out-File -FilePath "$shellPath\msys2bash.cmd" -Encoding ascii

# gitbash <--> C:\Program Files\Git\bin\bash.exe
New-Item -ItemType SymbolicLink -Path "$shellPath\gitbash.exe" -Target "$env:ProgramFiles\Git\bin\bash.exe" | Out-Null

# wslbash <--> C:\Windows\System32\bash.exe
New-Item -ItemType SymbolicLink -Path "$shellPath\wslbash.exe" -Target "$env:SystemRoot\System32\bash.exe" | Out-Null

################################################################################
##  File:  Configure-System.ps1
##  Desc:  Applies various configuration settings to the final image
################################################################################

Write-Host "Cleanup WinSxS"
dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
if ($LASTEXITCODE -ne 0) {
    throw "Failed to cleanup WinSxS"
}

# Set default version to 1 for WSL (aka LXSS - Linux Subsystem)
# The value should be set in the default user registry hive
# https://github.com/actions/runner-images/issues/5760
if (Test-IsWin22) {
    Write-Host "Setting WSL default version to 1"

    Mount-RegistryHive `
        -FileName "C:\Users\Default\NTUSER.DAT" `
        -SubKey "HKLM\DEFAULT"

    # Create the key if it doesn't exist
    $keyPath = "DEFAULT\Software\Microsoft\Windows\CurrentVersion\Lxss"
    if (-not (Test-Path $keyPath)) {
        Write-Host "Creating $keyPath key"
        New-Item -Path (Join-Path "HKLM:\" $keyPath) -Force | Out-Null
    }

    # Set the DefaultVersion value to 1
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyPath, $true)
    $key.SetValue("DefaultVersion", "1", "DWord")
    $key.Handle.Close()
    [System.GC]::Collect()
    
    Dismount-RegistryHive "HKLM\DEFAULT"
}

Write-Host "Clean up various directories"
@(
    "$env:SystemDrive\Recovery",
    "$env:SystemRoot\logs",
    "$env:SystemRoot\winsxs\manifestcache",
    "$env:SystemRoot\Temp",
    "$env:SystemDrive\Users\$env:INSTALL_USER\AppData\Local\Temp",
    "$env:TEMP",
    "$env:AZURE_CONFIG_DIR\logs",
    "$env:AZURE_CONFIG_DIR\commands",
    "$env:AZURE_CONFIG_DIR\telemetry"
) | ForEach-Object {
    if (Test-Path $_) {
        Write-Host "Removing $_"
        cmd /c "takeown /d Y /R /f $_ 2>&1" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to take ownership of $_"
        }
        cmd /c "icacls $_ /grant:r administrators:f /t /c /q 2>&1" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to grant administrators full control of $_"
        }
        Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

$winInstallDir = "$env:SystemRoot\Installer"
New-Item -Path $winInstallDir -ItemType Directory -Force | Out-Null

# Remove AllUsersAllHosts profile
Remove-Item $profile.AllUsersAllHosts -Force -ErrorAction SilentlyContinue | Out-Null

# Clean yarn and npm cache
cmd /c "yarn cache clean 2>&1" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to clean yarn cache"
}

cmd /c "npm cache clean --force 2>&1" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to clean npm cache"
}

# allow msi to write to temp folder
# see https://github.com/actions/runner-images/issues/1704
cmd /c "icacls $env:SystemRoot\Temp /grant Users:f /t /c /q 2>&1" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to grant Users full control of $env:SystemRoot\Temp"
}

# Registry settings
$registrySettings = @(
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "AUOptions"; Value = 1; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"; Value = 1; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DoNotConnectToWindowsUpdateInternetLocations"; Value = 1; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DisableWindowsUpdateAccess"; Value = 1; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata"; Name = "PreventDeviceMetadataFromNetwork"; Value = 1; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"; Name = "CEIPEnable"; Value = 0; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "AITEnable"; Value = 0; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "DisableUAR"; Value = 1; PropertyType = "DWORD" }
    @{Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"; Name = "MaintenanceDisabled"; Value = 1; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\MRT"; Name = "DontOfferThroughWUAU"; Value = 1; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\MRT"; Name = "DontReportInfectionInformation"; Value = 1; PropertyType = "DWORD" }
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortana"; Value = 0; PropertyType = "DWORD" }
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control"; Name = "ServicesPipeTimeout"; Value = 120000; PropertyType = "DWORD" }
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener"; Name = "Start"; Value = 0; PropertyType = "DWORD" }
    @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger"; Name = "Start"; Value = 0; PropertyType = "DWORD" }
)

$registrySettings | ForEach-Object {
    $regPath = $_.Path
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force -ErrorAction Ignore | Out-Null
    }
    New-ItemProperty @_ -Force -ErrorAction Ignore
} | Out-Null

# Disable Template Services / User Services added by Desktop Experience
$regUserServicesToDisables = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc"
    "HKLM:\SYSTEM\CurrentControlSet\Services\OneSyncSvc"
    "HKLM:\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc"
    "HKLM:\SYSTEM\CurrentControlSet\Services\UnistoreSvc"
    "HKLM:\SYSTEM\CurrentControlSet\Services\UserDataSvc"
)

$regUserServicesToDisables | ForEach-Object {
    $regPath = $_
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force -ErrorAction Ignore | Out-Null
    }
    New-ItemProperty -Path $regPath -Name "Start" -Value 4 -PropertyType DWORD -Force -ErrorAction Ignore
    New-ItemProperty -Path $regPath -Name "UserServiceFlags" -Value 0 -PropertyType DWORD -Force -ErrorAction Ignore
} | Out-Null


Write-Host 'Disable Windows Update Service'
Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\wuauserv -Name Start -Value 4 -Force

# Disabled services
$servicesToDisable = @(
    'wuauserv'
    'DiagTrack'
    'dmwappushservice'
    'PcaSvc'
    'SysMain'
    'gupdate'
    'gupdatem'
    'StorSvc'
) | Get-Service -ErrorAction SilentlyContinue
Stop-Service $servicesToDisable
$servicesToDisable.WaitForStatus('Stopped', "00:01:00")
$servicesToDisable | Set-Service -StartupType Disabled

# Disable scheduled tasks
$allTasksInTaskPath = @(
    "\"
    "\Microsoft\Azure\Security\"
    "\Microsoft\VisualStudio\"
    "\Microsoft\VisualStudio\Updates\"
    "\Microsoft\Windows\Application Experience\"
    "\Microsoft\Windows\ApplicationData\"
    "\Microsoft\Windows\Autochk\"
    "\Microsoft\Windows\Chkdsk\"
    "\Microsoft\Windows\Customer Experience Improvement Program\"
    "\Microsoft\Windows\Data Integrity Scan\"
    "\Microsoft\Windows\Defrag\"
    "\Microsoft\Windows\Diagnosis\"
    "\Microsoft\Windows\DiskCleanup\"
    "\Microsoft\Windows\DiskDiagnostic\"
    "\Microsoft\Windows\Maintenance\"
    "\Microsoft\Windows\PI\"
    "\Microsoft\Windows\Power Efficiency Diagnostics\"
    "\Microsoft\Windows\Server Manager\"
    "\Microsoft\Windows\Speech\"
    "\Microsoft\Windows\UpdateOrchestrator\"
    "\Microsoft\Windows\Windows Error Reporting\"
    "\Microsoft\Windows\WindowsUpdate\"
    "\Microsoft\XblGameSave\"
)

$allTasksInTaskPath | ForEach-Object {
    Get-ScheduledTask -TaskPath $_ -ErrorAction Ignore | Disable-ScheduledTask -ErrorAction Ignore
} | Out-Null

$disableTaskNames = @(
    @{TaskPath = "\Microsoft\Windows\.NET Framework\"; TaskName = ".NET Framework NGEN v4.0.30319" }
    @{TaskPath = "\Microsoft\Windows\.NET Framework\"; TaskName = ".NET Framework NGEN v4.0.30319 64" }
    @{TaskPath = "\Microsoft\Windows\AppID\"; TaskName = "SmartScreenSpecific" }
)

$disableTaskNames | ForEach-Object {
    Disable-ScheduledTask @PSItem -ErrorAction Ignore
} | Out-Null

Write-Host "Finalize-VM.ps1 - completed"

################################################################################
##  File:  Configure-SystemEnvironment.ps1
##  Desc:  Configures system environment variables
################################################################################

$variables = @{
    "ImageVersion"                        = $env:IMAGE_VERSION
    "ImageOS"                             = $env:IMAGE_OS
    "AGENT_TOOLSDIRECTORY"                = $env:AGENT_TOOLSDIRECTORY
}

$variables.GetEnumerator() | ForEach-Object {
    [Environment]::SetEnvironmentVariable($_.Key, $_.Value, "Machine")
}

################################################################################
##  File:  Configure-Toolset.ps1
##  Team:  CI-Build
##  Desc:  Configure Toolset
################################################################################

$toolEnvConfigs = @{
    Python = @{
        pathTemplates = @(
            "{0}"
            "{0}\Scripts"
        )
    }
    go     = @{
        pathTemplates  = @(
            "{0}\bin"
        )
        envVarTemplate = "GOROOT_{0}_{1}_X64"
    }
}

$tools = Get-ToolsetContent `
| Select-Object -ExpandProperty toolcache `
| Where-Object { $toolEnvConfigs.Keys -contains $_.name }

Write-Host "Configure toolset tools environment..."
foreach ($tool in $tools) {
    $toolEnvConfig = $toolEnvConfigs[$tool.name]
    
    if (-not ([string]::IsNullOrEmpty($toolEnvConfig.envVarTemplate))) {
        foreach ($version in $tool.versions) {
            Write-Host "Set $($tool.name) $version environment variable..."

            $foundVersionArchPath = Get-TCToolVersionPath -Name $tool.name -Version $version -Arch $tool.arch
            $envName = $toolEnvConfig.envVarTemplate -f $version.Split(".")

            Write-Host "Set $envName to $foundVersionArchPath"
            [Environment]::SetEnvironmentVariable($envName, $foundVersionArchPath, "Machine")
        }
    }

    if (-not ([string]::IsNullOrEmpty($tool.default))) {
        Write-Host "Use $($tool.name) $($tool.default) as a system $($tool.name)..."

        $toolVersionPath = Get-TCToolVersionPath -Name $tool.name -Version $tool.default -Arch $tool.arch

        foreach ($template in $toolEnvConfig.pathTemplates) {
            $toolSystemPath = $template -f $toolVersionPath
            Write-Host "Add $toolSystemPath to system PATH..."
            Add-MachinePathItem -PathItem $toolSystemPath | Out-Null
        }
    
        if (-not ([string]::IsNullOrEmpty($tool.defaultVariable))) {
            Write-Host "Set $($tool.name) $($tool.default) $($tool.defaultVariable) environment variable..."
            [Environment]::SetEnvironmentVariable($tool.defaultVariable, $toolVersionPath, "Machine")
        }
    }
}

Invoke-PesterTests -TestFile "Toolset"

################################################################################
##  File:  Configure-User.ps1
##  Desc:  Performs user part of warm up and moves data to C:\Users\Default
################################################################################

#
# more: https://github.com/actions/runner-images-internal/issues/5320
#       https://github.com/actions/runner-images/issues/5301#issuecomment-1648292990
#

Write-Host "Warmup 'devenv.exe /updateconfiguration'"
$vsInstallRoot = (Get-VisualStudioInstance).InstallationPath
cmd.exe /c "`"$vsInstallRoot\Common7\IDE\devenv.exe`" /updateconfiguration"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to warmup 'devenv.exe /updateconfiguration'"
}

# we are fine if some file is locked and cannot be copied
Copy-Item ${env:USERPROFILE}\AppData\Local\Microsoft\VisualStudio -Destination c:\users\default\AppData\Local\Microsoft\VisualStudio -Recurse -ErrorAction SilentlyContinue

Mount-RegistryHive `
    -FileName "C:\Users\Default\NTUSER.DAT" `
    -SubKey "HKLM\DEFAULT"

reg.exe copy HKCU\Software\Microsoft\VisualStudio HKLM\DEFAULT\Software\Microsoft\VisualStudio /s
if ($LASTEXITCODE -ne 0) {
    throw "Failed to copy HKCU\Software\Microsoft\VisualStudio to HKLM\DEFAULT\Software\Microsoft\VisualStudio"
}

# disable TSVNCache.exe
$registryKeyPath = 'HKCU:\Software\TortoiseSVN'
if (-not(Test-Path -Path $registryKeyPath)) {
    New-Item -Path $registryKeyPath -ItemType Directory -Force
}

New-ItemProperty -Path $registryKeyPath -Name CacheType -PropertyType DWORD -Value 0
reg.exe copy HKCU\Software\TortoiseSVN HKLM\DEFAULT\Software\TortoiseSVN /s
if ($LASTEXITCODE -ne 0) {
    throw "Failed to copy HKCU\Software\TortoiseSVN to HKLM\DEFAULT\Software\TortoiseSVN"
}

Dismount-RegistryHive "HKLM\DEFAULT"

Write-Host "Configure-User.ps1 - completed"

################################################################################
##  File:  Configure-WindowsDefender.ps1
##  Desc:  Disables Windows Defender
################################################################################

Write-Host "Disable Windows Defender..."
$avPreference = @(
    @{DisableArchiveScanning = $true}
    @{DisableAutoExclusions = $true}
    @{DisableBehaviorMonitoring = $true}
    @{DisableBlockAtFirstSeen = $true}
    @{DisableCatchupFullScan = $true}
    @{DisableCatchupQuickScan = $true}
    @{DisableIntrusionPreventionSystem = $true}
    @{DisableIOAVProtection = $true}
    @{DisablePrivacyMode = $true}
    @{DisableScanningNetworkFiles = $true}
    @{DisableScriptScanning = $true}
    @{MAPSReporting = 0}
    @{PUAProtection = 0}
    @{SignatureDisableUpdateOnStartupWithoutEngine = $true}
    @{SubmitSamplesConsent = 2}
    @{ScanAvgCPULoadFactor = 5; ExclusionPath = @("D:\", "C:\")}
    @{DisableRealtimeMonitoring = $true}
    @{ScanScheduleDay = 8}
)

$avPreference += @(
    @{EnableControlledFolderAccess = "Disable"}
    @{EnableNetworkProtection = "Disabled"}
)

$avPreference | Foreach-Object {
    $avParams = $_
    Set-MpPreference @avParams
}

# https://github.com/actions/runner-images/issues/4277
# https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-compatibility?view=o365-worldwide
$atpRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
if (Test-Path $atpRegPath) {
    Write-Host "Set Microsoft Defender Antivirus to passive mode"
    Set-ItemProperty -Path $atpRegPath -Name 'ForceDefenderPassiveMode' -Value '1' -Type 'DWORD'
}



################################################################################
##  File:  Install-AzureCli.ps1
##  Desc:  Install and warm-up Azure CLI
################################################################################

Write-Host 'Install the latest Azure CLI release'

$azureCliConfigPath = 'C:\azureCli'
# Store azure-cli cache outside of the provisioning user's profile
[Environment]::SetEnvironmentVariable('AZURE_CONFIG_DIR', $azureCliConfigPath, "Machine")

$azureCliExtensionPath = Join-Path $env:CommonProgramFiles 'AzureCliExtensionDirectory'
New-Item -ItemType 'Directory' -Path $azureCliExtensionPath | Out-Null
[Environment]::SetEnvironmentVariable('AZURE_EXTENSION_DIR', $azureCliExtensionPath, "Machine")

Install-Binary -Type MSI `
    -Url 'https://aka.ms/installazurecliwindowsx64' `
    -ExpectedSignature '72105B6D5F370B62FD5C82F1512F7AD7DEE5F2C0'

Update-Environment

# Warm-up Azure CLI
Write-Host "Warmup 'az'"
az --help | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Command 'az --help' failed"
}

Invoke-PesterTests -TestFile 'CLI.Tools' -TestName 'Azure CLI'
