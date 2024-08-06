#Requires -Version 3.0

<#

.SYNOPSIS
    This is a PowerShell Module for ConnectWise Automate (Formerly LabTech).

.DESCRIPTION
    This is a set of commandlets to interface with the ConnectWise Automate (LabTech) Agent.

.NOTES
    Version:        2.0.0
    Author:         Chris Taylor (Original)
                    Josiah McCall

    -- Legacy update notes removed. --

    Update Date:    2024.08.05
    Purpose/Change: Error handling, code readability, performance.
                    Updating code with best practices and removing legacy functionality.
#>

#region [Variables]

#Module Version
$ModuleVersion = "2.0.0";
$ModuleGuid = 'f1f06c84-00c8-11ea-b6e8-000c29aaa7df';

$Kernel32Definition = @"
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool Wow64DisableWow64FsRedirection(ref IntPtr ptr);

[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool Wow64RevertWow64FsRedirection(ref IntPtr ptr);
"@;

$TrustAllCertsDefinition = @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@;

#endregion [Variables]

if ($env:PROCESSOR_ARCHITEW6432 -match '64' -and [IntPtr]::Size -ne 8 -and $env:PROCESSOR_ARCHITEW6432 -ne 'ARM64') {

    Write-Warning '32-bit PowerShell session detected on 64-bit OS. Attempting to launch 64-Bit session to process commands.';

    $pshell = "${env:windir}\SysNative\WindowsPowershell\v1.0\powershell.exe";

    if (-not(Test-Path -Path $pshell -ErrorAction SilentlyContinue)) {

        $pshell = "${env:windir}\System32\WindowsPowershell\v1.0\powershell.exe";

        if ($null -eq ([System.Management.Automation.PSTypeName]'Kernel32.Wow64').Type -or $null -eq [Kernel32.Wow64].GetMethod('Wow64DisableWow64FsRedirection')) {

            Write-Debug 'Loading WOW64Redirection functions';
            Add-Type -Name Wow64 -Namespace Kernel32 -Debug:$false -MemberDefinition $Kernel32Definition;
        }

        Write-Verbose 'System32 path is redirected. Disabling redirection.';

        [ref]$ptr = New-Object System.IntPtr;
        $Result = [Kernel32.Wow64]::Wow64DisableWow64FsRedirection($ptr);
        $FSRedirectionDisabled = $true;
    }

    if ($myInvocation.Line) {
        &"$pshell" -NonInteractive -NoProfile $myInvocation.Line;
    } elseif ($myInvocation.InvocationName) {
        &"$pshell" -NonInteractive -NoProfile -File "$($myInvocation.InvocationName)" $args;
    } else {
        &"$pshell" -NonInteractive -NoProfile $myInvocation.MyCommand;
    }

    $ExitResult = $LASTEXITCODE;

    if ($null -ne ([System.Management.Automation.PSTypeName]'Kernel32.Wow64').Type -and $null -ne [Kernel32.Wow64].GetMethod('Wow64DisableWow64FsRedirection') -and $FSRedirectionDisabled -eq $true) {

        [ref]$defaultptr = New-Object System.IntPtr;
        $Result = [Kernel32.Wow64]::Wow64RevertWow64FsRedirection($defaultptr);

        Write-Verbose 'System32 path redirection has been re-enabled.';
    }

    Write-Warning 'Exiting 64-bit session. Module will only remain loaded in native 64-bit PowerShell environment.';

    exit $ExitResult;
}

#Ignore SSL errors
if ($null -eq ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
    Add-Type -Debug:$false $TrustAllCertsDefinition;
}

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy;

# Old method would allow the use of insecure protocols if the system had them enabled.
# Force TLS 1.2 by default, TLS 1.3 if supported.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
IF ([Net.SecurityProtocolType]::Tls13) { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13; }

#region [functions]-------------------------------------------------------------

function Get-LTServiceInfo {
    <#
    .SYNOPSIS
        This function will pull all of the registry data into an object.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    Param ()

    Begin {

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";
        Clear-Variable key, BasePath, exclude, Servers -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false; #Clearing Variables for use

        $exclude = "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSPath";
        $key = $null;
    }

    Process {

        if (-not(Test-Path 'HKLM:\SOFTWARE\LabTech\Service' -ErrorAction SilentlyContinue)) {
            Write-Error "ERROR: Unable to find information on LTSvc. Make sure the agent is installed." -ErrorAction Stop;
        }

        if ($PSCmdlet.ShouldProcess("LTService", "Retrieving Service Registry Values")) {

            Write-Verbose "Checking for LT Service registry keys.";

            try {

                $key = Get-ItemProperty 'HKLM:\SOFTWARE\LabTech\Service' -ErrorAction Stop | Select-Object * -exclude $exclude;

                if ($null -ne $key -and -not ($key | Get-Member -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'BasePath' })) {

                    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LTService' -ErrorAction SilentlyContinue) {

                        try {
                            $BasePath = Get-Item $( Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LTService' -ErrorAction Stop | Select-Object -Expand ImagePath | Select-String -Pattern '^[^"][^ ]+|(?<=^")[^"]+' | Select-Object -Expand Matches -First 1 | Select-Object -Expand Value -ErrorAction SilentlyContinue -First 1 ) | Select-Object -Expand DirectoryName -ErrorAction SilentlyContinue;
                        } catch {
                            $BasePath = "${env:windir}\LTSVC";
                        }

                    } else {
                        $BasePath = "${env:windir}\LTSVC";
                    }

                    Add-Member -InputObject $key -MemberType NoteProperty -Name BasePath -Value $BasePath;
                }

                $key.BasePath = [System.Environment]::ExpandEnvironmentVariables($($key | Select-Object -Expand BasePath -ErrorAction SilentlyContinue)) -replace '\\\\', '\';

                if ($null -ne $key -and ($key | Get-Member | Where-Object { $_.Name -match 'Server Address' })) {

                    $Servers = ($Key | Select-Object -Expand 'Server Address' -ErrorAction SilentlyContinue).Split('|') | ForEach-Object { $_.Trim() -replace '~', '' } | Where-Object { $_ -match '.+' };
                    Add-Member -InputObject $key -MemberType NoteProperty -Name 'Server' -Value $Servers -Force;
                }

            } catch {
                Write-Error "ERROR: There was a problem reading the registry keys. $($Error[0])" -ErrorAction Stop;
            }
        }
    }

    End {

        if ($?) {
            Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
            return $key
        } else {
            Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
            return $null;
        }
    }
}

function Get-LTServiceSettings {
    <#
    .SYNOPSIS
        This function will pull the registry data from HKLM:\SOFTWARE\LabTech\Service\Settings into an object.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    Param ()

    Begin {

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";
        $Settings = $null;
        $exclude = "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSPath";
    }

    Process {

        if (-not(Test-Path 'HKLM:\SOFTWARE\LabTech\Service\Settings' -ErrorAction SilentlyContinue)) {
            Write-Error "ERROR: Unable to find LTSvc settings. Make sure the agent is installed." -ErrorAction Stop;
        }

        if ($PSCmdlet.ShouldProcess("LTService", "Retrieving Service Settings Registry Values")) {

            try {
                $Settings = Get-ItemProperty HKLM:\SOFTWARE\LabTech\Service\Settings -ErrorAction Stop | Select-Object * -exclude $exclude;
            } catch {
                Write-Error "ERROR: There was a problem reading the registry keys. $($Error[0])" -ErrorAction Stop;
            }
        }
    }

    End {

        if ($?) {
            Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
            return $Settings;
        } else {
            Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
            return $null;
        }
    }
}

function Restart-LTService {
    <#
    .SYNOPSIS
        This function will restart the LabTech Services.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param()

    Begin {
        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";
    }

    Process {

        if (-not (Get-Service 'LTService', 'LTSvcMon' -ErrorAction SilentlyContinue)) {

            if ($WhatIfPreference -ne $true) {
                Write-Error "ERROR: Services NOT Found $($Error[0])" -ErrorAction Stop;
            } else {
                Write-Error "What-If: Stopping: Services NOT Found" -ErrorAction Stop;
            }
        }

        try {
            Stop-LTService;
        } catch {
            Write-Error "ERROR: There was an error stopping the services. $($Error[0])" -ErrorAction Stop;
        }

        try {
            Start-LTService;
        } catch {
            Write-Error "ERROR: There was an error starting the services. $($Error[0])" -ErrorAction Stop;
        }
    }

    End {

        if ($WhatIfPreference -ne $true) {

            if ($?) {
                Write-Output "Services Restarted successfully.";
            } else {
                Write-Error $Error[0];
            }
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function Stop-LTService {
    <#
    .SYNOPSIS
        This function will stop the LabTech Services.

    .DESCRIPTION
        This function will verify that the LabTech services are present then attempt to stop them.
        It will then check for any remaining LabTech processes and kill them.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param()

    Begin {
        Clear-Variable sw, timeout, svcRun -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false -Verbose:$false #Clearing Variables for use
        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";
    }

    Process {

        if (-not (Get-Service 'LTService', 'LTSvcMon' -ErrorAction SilentlyContinue)) {

            if ($WhatIfPreference -ne $true) {
                Write-Error "ERROR: Services NOT Found $($Error[0])" -ErrorAction Stop;
            } else {
                Write-Error "What If: Stopping: Services NOT Found" -ErrorAction Stop;
            }
        }

        if ($PSCmdlet.ShouldProcess("LTService, LTSvcMon", "Stop-Service")) {

            Write-Verbose "Stopping Labtech Services";

            $null = Invoke-LTServiceCommand ('Kill VNC', 'Kill Trays') -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false;

            try {

                ('LTService', 'LTSvcMon') | ForEach-Object {

                    try {

                        $null = Stop-Service -ServiceName $($_) -Force -WarningAction SilentlyContinue -ErrorAction Stop;

                    } catch {

                        try {
                            $null = & "${env:windir}\system32\sc.exe" stop "$($_)" 2>'';
                        } catch {
                            Write-Output "Error stopping service $($_): $($Error[0])";
                        }
                    }
                }

                $timeout = New-TimeSpan -Minutes 1;
                $sw = [diagnostics.stopwatch]::StartNew();

                Write-Host -NoNewline "Waiting for Services to Stop.";

                Do {

                    Write-Host -NoNewline '.';
                    Start-Sleep 2;

                    $svcRun = ('LTService', 'LTSvcMon') | Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Stopped' } | Measure-Object | Select-Object -Expand Count;

                } Until ($sw.elapsed -gt $timeout -or $svcRun -eq 0);

                Write-Host "";

                $sw.Stop();

                if ($svcRun -gt 0) {
                    Write-Verbose "Services did not stop. Terminating Processes after $(([int32]$sw.Elapsed.TotalSeconds).ToString()) seconds.";
                }

                Get-Process | Where-Object { @('LTTray', 'LTSVC', 'LTSvcMon') -contains $_.ProcessName } | Stop-Process -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false;

            } catch {
                Write-Error "ERROR: There was an error stopping the LabTech processes. $($Error[0])" -ErrorAction Stop;
            }
        }
    }

    End {

        if ($WhatIfPreference -ne $true) {

            if ($?) {

                if ((('LTService', 'LTSvcMon') | Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Stopped' } | Measure-Object | Select-Object -Expand Count) -eq 0) {
                    Write-Output "Services Stopped successfully.";
                } else {
                    Write-Warning "WARNING: Services have not stopped completely.";
                }

            } else {
                Write-Error $Error[0];
            }
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function Start-LTService {
    <#
    .SYNOPSIS
        This function will start the LabTech Services.

    .DESCRIPTION
        This function will verify that the LabTech services are present.
        It will then check for any process that is using the LTTray port (Default 42000) and kill it.
        Next it will start the services.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param()

    Begin {

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        $processes = [System.Collections.Generic.List[string]]::new();
        $Port = (Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false | Select-Object -Expand TrayPort -ErrorAction SilentlyContinue);

        if (-not ($Port)) { $Port = "42000" }
        $startedSvcCount = 0;
    }

    Process {

        if (-not (Get-Service 'LTService', 'LTSvcMon' -ErrorAction SilentlyContinue)) {

            if ($WhatIfPreference -ne $true) {
                Write-Error "ERROR: Services NOT Found: $($Error[0])" -ErrorAction Stop;
            } else {
                Write-Error "What If: Stopping: Services NOT Found" -ErrorAction Stop;
            }
        }

        try {

            if ((('LTService') | Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Stopped' } | Measure-Object | Select-Object -Expand Count) -gt 0) {

                try {
                    $netstat = & "${env:windir}\system32\netstat.exe" -a -o -n 2>'' | Select-String -Pattern " .*[0-9\.]+:$($Port).*[0-9\.]+:[0-9]+ .*?([0-9]+)" -ErrorAction SilentlyContinue;
                } catch {
                    Write-Output "Error calling netstat.exe:  $($Error[0])";
                    $netstat = $null;
                }

                foreach ($line in $netstat) {
                    $processes.Add(($line -split ' {4,}')[-1]);
                }

                $processes = $processes | Where-Object { $_ -gt 0 -and $_ -match '^\d+$' } | Sort-Object | Get-Unique;

                if (-not($null = $processes)) {

                    foreach ($proc in $processes) {

                        Write-Output "Process ID:$proc is using port $Port. Killing process.";

                        try {

                            $null = Stop-Process -Id $proc -Force -ErrorAction Stop ;

                        } catch {

                            Write-Warning "WARNING: There was an issue killing the following process: $proc";
                            Write-Warning "WARNING: This generally means that a 'protected application' is using this port.";

                            $newPort = [int]$port + 1;

                            if ($newPort -gt 42009) { $newPort = 42000 }

                            Write-Warning "WARNING: Setting tray port to $newPort.";
                            $null = New-ItemProperty -Path "HKLM:\Software\Labtech\Service" -Name TrayPort -PropertyType String -Value $newPort -Force -WhatIf:$false -Confirm:$false;
                        }
                    }
                }
            }

            if ($PSCmdlet.ShouldProcess("LTService, LTSvcMon", "Start Service")) {

                @('LTService', 'LTSvcMon') | ForEach-Object {

                    if (Get-Service $_ -ErrorAction SilentlyContinue) {

                        Set-Service $_ -StartupType Automatic -ErrorAction SilentlyContinue -Confirm:$false -WhatIf:$false;

                        $null = & "${env:windir}\system32\sc.exe" start "$($_)" 2>'';
                        $startedSvcCount++

                        Write-Debug "Executed Start Service for $($_)";
                    }

                }-Object
            }

        } catch {
            Write-Error "ERROR: There was an error starting the LabTech services. $($Error[0])" -ErrorAction Stop;
        }
    }

    End {

        if ($WhatIfPreference -ne $true) {

            if ($?) {

                $svcnotRunning = ('LTService') | Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Running' } | Measure-Object | Select-Object -Expand Count;

                if ($svcnotRunning -gt 0 -and $startedSvcCount -eq 2) {

                    $timeout = New-TimeSpan -Minutes 1;
                    $sw = [diagnostics.stopwatch]::StartNew();
                    Write-Host -NoNewline "Waiting for Services to Start.";

                    Do {

                        Write-Host -NoNewline '.';
                        Start-Sleep 2
                        $svcnotRunning = ('LTService') | Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Running' } | Measure-Object | Select-Object -Expand Count;

                    } Until ($sw.elapsed -gt $timeout -or $svcnotRunning -eq 0)

                    Write-Host "";
                    $sw.Stop();
                }

                if ($svcnotRunning -eq 0) {

                    Write-Output "Services Started successfully.";
                    $null = Invoke-LTServiceCommand 'Send Status' -ErrorAction SilentlyContinue -Confirm:$false;

                } elseif ($startedSvcCount -gt 0) {
                    Write-Output "Service Start was issued but LTService has not reached Running state.";
                } else {
                    Write-Output "Service Start was not issued.";
                }

            } else {
                Write-Output $($Error[0]);
            }
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function Uninstall-LTService {
    <#
    .SYNOPSIS
        This function will uninstall the LabTech agent from the machine.

    .DESCRIPTION
        This function will stop all the LabTech services. It will then download the current agent install MSI and issue an uninstall command.
        It will then download and run Agent_Uninstall.exe from the LabTech server. It will then scrub any remaining file/registry/service data.

    .PARAMETER Server
        This is the URL to your LabTech server.
        Example: https://lt.domain.com
        This is used to download the uninstall utilities.
        ifno server is provided the uninstaller will use Get-LTServiceInfo to get the server address.

    .PARAMETER Backup
        This will run a 'New-LTServiceBackup' before uninstalling.

    .PARAMETER Force
        This will force operation on an agent detected as a probe.

    .EXAMPLE
        Uninstall-LTService
        This will uninstall the LabTech agent using the server address in the registry.

    .EXAMPLE
        Uninstall-LTService -Server 'https://lt.domain.com'
        This will uninstall the LabTech agent using the provided server URL to download the uninstallers.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $True)]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [AllowNull()]
        [string[]]$Server,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]$Backup,
        [switch]$Force
    )

    Begin {

        #Clearing Variables for use
        Clear-Variable Executables, BasePath, reg, regs, installer, installerTest, installerResult, LTSI, uninstaller, uninstallerTest, uninstallerResult, xarg, Svr, SVer, SvrVer, SvrVerCheck, GoodServer, AlternateServer, Item -ErrorAction SilentlyContinue -WhatIf:$False -Confirm:$False;

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        if (-not ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object -Expand groups -ErrorAction SilentlyContinue) -match 'S-1-5-32-544'))) {
            throw "Line $(LINENUM): Needs to be ran as Administrator";
        }

        $LTSI = Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$False -WhatIf:$False -Confirm:$False -Debug:$False;

        if (($LTSI) -and ($LTSI | Select-Object -Expand Probe -ErrorAction SilentlyContinue) -eq '1') {

            if ($Force -eq $True) {
                Write-Output "Probe Agent Detected. UnInstall Forced.";
            } else {
                Write-Error -Exception [System.OperationCanceledException]"Line $(LINENUM): Probe Agent Detected. UnInstall Denied." -ErrorAction Stop;
            }
        }

        if ($Backup) {

            if ( $PSCmdlet.ShouldProcess("LTService", "Backup Current Service Settings") ) {
                New-LTServiceBackup;
            }
        }

        $BasePath = $(Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$False -WhatIf:$False -Confirm:$False -Debug:$False | Select-Object -Expand BasePath -ErrorAction SilentlyContinue);

        if (-not ($BasePath)) { $BasePath = "${env:windir}\LTSVC" }

        $UninstallBase = "${env:windir}\Temp";
        $UninstallEXE = 'Agent_Uninstall.exe';
        $UninstallMSI = 'RemoteAgent.msi';

        $null = New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue -WhatIf:$False -Confirm:$False -Debug:$False;

        $regs = @( 'Registry::HKEY_LOCAL_MACHINE\Software\LabTechMSP',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\LabTech\Service',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\LabTech\LabVNC',
            'Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\LabTech\Service',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\D1003A85576B76D45A1AF09A0FC87FAC',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\D1003A85576B76D45A1AF09A0FC87FAC',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Managed\\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\D1003A85576B76D45A1AF09A0FC87FAC\InstallProperties',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{58A3001D-B675-4D67-A5A1-0FA9F08CF7CA}',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{3426921d-9ad5-4237-9145-f15dee7e3004}',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Appmgmt\{40bf8c82-ed0d-4f66-b73e-58a3d7ab6582}',
            'Registry::HKEY_CLASSES_ROOT\Installer\Dependencies\{3426921d-9ad5-4237-9145-f15dee7e3004}',
            'Registry::HKEY_CLASSES_ROOT\Installer\Dependencies\{3F460D4C-D217-46B4-80B6-B5ED50BD7CF5}',
            'Registry::HKEY_CLASSES_ROOT\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F',
            'Registry::HKEY_CLASSES_ROOT\Installer\Products\D1003A85576B76D45A1AF09A0FC87FAC',
            'Registry::HKEY_CLASSES_ROOT\CLSID\{09DF1DCA-C076-498A-8370-AD6F878B6C6A}',
            'Registry::HKEY_CLASSES_ROOT\CLSID\{15DD3BF6-5A11-4407-8399-A19AC10C65D0}',
            'Registry::HKEY_CLASSES_ROOT\CLSID\{3C198C98-0E27-40E4-972C-FDC656EC30D7}',
            'Registry::HKEY_CLASSES_ROOT\CLSID\{459C65ED-AA9C-4CF1-9A24-7685505F919A}',
            'Registry::HKEY_CLASSES_ROOT\CLSID\{7BE3886B-0C12-4D87-AC0B-09A5CE4E6BD6}',
            'Registry::HKEY_CLASSES_ROOT\CLSID\{7E092B5C-795B-46BC-886A-DFFBBBC9A117}',
            'Registry::HKEY_CLASSES_ROOT\CLSID\{9D101D9C-18CC-4E78-8D78-389E48478FCA}',
            'Registry::HKEY_CLASSES_ROOT\CLSID\{B0B8CDD6-8AAA-4426-82E9-9455140124A1}',
            'Registry::HKEY_CLASSES_ROOT\CLSID\{B1B00A43-7A54-4A0F-B35D-B4334811FAA4}',
            'Registry::HKEY_CLASSES_ROOT\CLSID\{BBC521C8-2792-43FE-9C91-CCA7E8ACBCC9}',
            'Registry::HKEY_CLASSES_ROOT\CLSID\{C59A1D54-8CD7-4795-AEDD-F6F6E2DE1FE7}',
            'Registry::HKEY_CLASSES_ROOT\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F',
            'Registry::HKEY_CLASSES_ROOT\Installer\Products\D1003A85576B76D45A1AF09A0FC87FAC',
            'Registry::HKEY_CURRENT_USER\SOFTWARE\LabTech\Service',
            'Registry::HKEY_CURRENT_USER\SOFTWARE\LabTech\LabVNC',
            'Registry::HKEY_CURRENT_USER\Software\Microsoft\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F',
            'HKU:\*\Software\Microsoft\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F'
        )

        $xarg = "/x ""$UninstallBase\$UninstallMSI"" /qn"
    }

    Process {

        if ($null -eq $Server) {
            $Server = Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$False -WhatIf:$False -Confirm:$False -Debug:$False | Select-Object -Expand 'Server' -ErrorAction SilentlyContinue;
        }

        if ($null -eq $Server) {
            $Server = Read-Host -Prompt 'Provide the URL to your LabTech server (https://lt.domain.com)';
        }

        $Server = foreach ($Svr in $Server) {

            if (-not([string]::IsNullOrEmpty($Svr))) {

                if ($Svr -notmatch 'https?://.+') {
                    "https://$($Svr)"
                }

                $Svr;
            }
        }

        foreach ($Svr in $Server) {

            if (-not ($GoodServer)) {

                if ($Svr -match '^(https?://)?(([12]?[0-9]{1,2}\.){3}[12]?[0-9]{1,2}|[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)*)$') {

                    try {

                        if ($Svr -notmatch 'https?://.+') {
                            $Svr = "http://$($Svr)"
                        }

                        $SvrVerCheck = "$($Svr)/LabTech/Agent.aspx";

                        Write-Debug "Line $(LINENUM): Testing Server Response and Version: $SvrVerCheck";

                        $SvrVer = $Script:LTServiceNetWebClient.DownloadString($SvrVerCheck);

                        Write-Debug "Line $(LINENUM): Raw Response: $SvrVer";

                        $SVer = $SvrVer | Select-String -Pattern '(?<=[|]{6})[0-9]{1,3}\.[0-9]{1,3}' | ForEach-Object { $_.matches } | Select-Object -Expand value -ErrorAction SilentlyContinue;

                        if ($null -eq $SVer) {
                            Write-Verbose "Unable to test version response from $($Svr).";
                            continue;
                        }

                        $installer = "$($Svr)/LabTech/Service/LabTechRemoteAgent.msi";
                        $installerTest = [System.Net.WebRequest]::Create($installer);

                        if (($Script:LTProxy.Enabled) -eq $True) {
                            Write-Debug "Line $(LINENUM): Proxy Configuration Needed. Applying Proxy Settings to request.";
                            $installerTest.Proxy = $Script:LTWebProxy;
                        }

                        $installerTest.KeepAlive = $False;
                        $installerTest.ProtocolVersion = '1.0';
                        $installerResult = $installerTest.GetResponse();
                        $installerTest.Abort();

                        if ($installerResult.StatusCode -ne 200) {

                            Write-Warning "WARNING: Line $(LINENUM): Unable to download $UninstallMSI from server $($Svr).";
                            continue;

                        } else {

                            if ($PSCmdlet.ShouldProcess("$installer", "DownloadFile")) {

                                Write-Debug "Line $(LINENUM): Downloading $UninstallMSI from $installer";
                                $Script:LTServiceNetWebClient.DownloadFile($installer, "$UninstallBase\$UninstallMSI");

                                if (Test-Path "$UninstallBase\$UninstallMSI" -ErrorAction SilentlyContinue) {

                                    if (-not((Get-Item "$UninstallBase\$UninstallMSI" -ErrorAction SilentlyContinue).length / 1KB -gt 1234)) {

                                        Write-Warning "WARNING: Line $(LINENUM): $UninstallMSI size is below normal. Removing suspected corrupt file.";
                                        $null = Remove-Item "$UninstallBase\$UninstallMSI" -ErrorAction SilentlyContinue -Force -Confirm:$False;

                                        continue;
                                    }
                                }
                            }
                        }

                        #Why was there an IF statement here if they both return the exact same results...
                        $uninstaller = "$($Svr)/LabTech/Service/LabUninstall.exe";

                        $uninstallerTest = [System.Net.WebRequest]::Create($uninstaller);

                        if (($Script:LTProxy.Enabled) -eq $True) {

                            Write-Debug "Line $(LINENUM): Proxy Configuration Needed. Applying Proxy Settings to request.";
                            $uninstallerTest.Proxy = $Script:LTWebProxy;
                        }

                        $uninstallerTest.KeepAlive = $False;
                        $uninstallerTest.ProtocolVersion = '1.0';
                        $uninstallerResult = $uninstallerTest.GetResponse();
                        $uninstallerTest.Abort();

                        if ($uninstallerResult.StatusCode -ne 200) {

                            Write-Warning "WARNING: Line $(LINENUM): Unable to download Agent_Uninstall from server.";
                            continue;

                        } else {

                            if ($PSCmdlet.ShouldProcess("$uninstaller", "DownloadFile")) {

                                Write-Debug "Line $(LINENUM): Downloading $UninstallEXE from $uninstaller";
                                $Script:LTServiceNetWebClient.DownloadFile($uninstaller, "$UninstallBase\$UninstallEXE");

                                if ((Test-Path "$UninstallBase\$UninstallEXE" -ErrorAction SilentlyContinue) -and -not((Get-Item "$UninstallBase\$UninstallEXE" -ErrorAction SilentlyContinue).length / 1KB -gt 80)) {

                                    Write-Warning "WARNING: Line $(LINENUM): $UninstallEXE size is below normal. Removing suspected corrupt file.";
                                    $null = Remove-Item "$UninstallBase\$UninstallEXE" -ErrorAction SilentlyContinue -Force -Confirm:$False
                                    continue;
                                }
                            }
                        }

                        if ($WhatIfPreference -eq $True) {

                            $GoodServer = $Svr;

                        } elseif ((Test-Path "$UninstallBase\$UninstallMSI" -ErrorAction SilentlyContinue) -and (Test-Path "$UninstallBase\$UninstallEXE" -ErrorAction SilentlyContinue)) {

                            Write-Verbose "Successfully downloaded files from $($Svr).";
                            $GoodServer = $Svr;

                        } else {
                            Write-Warning "WARNING: Line $(LINENUM): Error encountered downloading from $($Svr). Uninstall file(s) could not be received.";
                            continue;
                        }

                    } catch {
                        Write-Warning "WARNING: Line $(LINENUM): Error encountered downloading from $($Svr).";
                        continue;
                    }

                } elseif (-not($null -eq $Svr)) {
                    Write-Verbose "Server address $($Svr) is not formatted correctly. Example: https://lt.domain.com";
                }

            } else {
                Write-Debug "Line $(LINENUM): Server $($GoodServer) has been selected.";
                Write-Verbose "Server has already been selected - Skipping $($Svr).";
            }
        }
    }

    End {

        if (-not ($GoodServer -match 'https?://.+')) {

            $uninstaller = 'https://s3.amazonaws.com/assets-cp/assets/Agent_Uninstall.exe';

            if ($PSCmdlet.ShouldProcess("$uninstaller", "DownloadFile")) {

                Write-Debug "Line $(LINENUM): Downloading $UninstallEXE from $uninstaller";
                $Script:LTServiceNetWebClient.DownloadFile($uninstaller, "$UninstallBase\$UninstallEXE");

                if ((Test-Path "$UninstallBase\$UninstallEXE" -ErrorAction SilentlyContinue)) {

                    If (((Get-Item "$UninstallBase\$UninstallEXE" -ErrorAction SilentlyContinue).length / 1KB -gt 80)) {

                        $GoodServer = 'https://s3.amazonaws.com';

                    } else {

                        Write-Warning "Line $(LINENUM): $UninstallEXE size is below normal. Removing suspected corrupt file.";
                        $null = Remove-Item "$UninstallBase\$UninstallEXE" -ErrorAction SilentlyContinue -Force -Confirm:$False;
                    }
                }
            }

        } elseif ($GoodServer -match 'https?://.+') {

            try {

                Write-Output "Starting Uninstall.";

                try { Stop-LTService -ErrorAction SilentlyContinue; } catch {}

                #Kill all running processes from %ltsvcdir%
                if (Test-Path $BasePath) {

                    $Executables = (Get-ChildItem $BasePath -Filter *.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -Expand FullName);

                    if (-not($null -eq $Executables)) {

                        Write-Verbose "Terminating LabTech Processes from $($BasePath) if found running: $(($Executables) -replace [Regex]::Escape($BasePath),'' -replace '^\\','')";

                        Get-Process | Where-Object { $Executables -contains $_.Path } | ForEach-Object {

                            Write-Debug "Line $(LINENUM): Terminating Process $($_.ProcessName)";
                            $($_) | Stop-Process -Force -ErrorAction SilentlyContinue;
                        }

                        Get-ChildItem $BasePath -Filter labvnc.exe -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction 0;
                    }

                    if ($PSCmdlet.ShouldProcess("$($BasePath)\wodVPN.dll", "Unregister DLL")) {
                        #Unregister DLL
                        Write-Debug "Line $(LINENUM): Executing Command ""regsvr32.exe /u $($BasePath)\wodVPN.dll /s""";

                        try {

                            & "${env:windir}\system32\regsvr32.exe" /u "$($BasePath)\wodVPN.dll" /s 2>'';

                        } catch {
                            Write-Output "Error calling regsvr32.exe.";
                        }
                    }
                }

                if ($PSCmdlet.ShouldProcess("msiexec.exe $($xarg)", "Execute MSI Uninstall")) {

                    if ((Test-Path "$UninstallBase\$UninstallMSI" -ErrorAction SilentlyContinue)) {

                        #Run MSI uninstaller for current installation
                        Write-Verbose "Launching MSI Uninstall.";
                        Write-Debug "Line $(LINENUM): Executing Command ""msiexec.exe $($xarg)""";

                        Start-Process -Wait -FilePath "${env:windir}\system32\msiexec.exe" -ArgumentList $xarg -WorkingDirectory $UninstallBase;
                        Start-Sleep -Seconds 5;

                    } else {
                        Write-Verbose "WARNING: $UninstallBase\$UninstallMSI was not found.";
                    }
                }

                if ($PSCmdlet.ShouldProcess("$UninstallBase\$UninstallEXE", "Execute Agent Uninstall")) {

                    if ((Test-Path "$UninstallBase\$UninstallEXE" -ErrorAction SilentlyContinue)) {

                        #Run $UninstallEXE
                        Write-Verbose "Launching Agent Uninstaller";
                        Write-Debug "Line $(LINENUM): Executing Command ""$UninstallBase\$UninstallEXE""";

                        Start-Process -Wait -FilePath "$UninstallBase\$UninstallEXE" -WorkingDirectory $UninstallBase;
                        Start-Sleep -Seconds 5;

                    } else {
                        Write-Verbose "WARNING: $UninstallBase\$UninstallEXE was not found.";
                    }
                }

                Write-Verbose "Removing Services if found.";

                #Remove Services
                @('LTService', 'LTSvcMon', 'LabVNC') | ForEach-Object {

                    if (Get-Service $_ -ErrorAction SilentlyContinue) {

                        if ( $PSCmdlet.ShouldProcess("$($_)", "Remove Service") ) {

                            Write-Debug "Line $(LINENUM): Removing Service: $($_)";

                            try {
                                & "${env:windir}\system32\sc.exe" delete "$($_)" 2>'';
                            } catch {
                                Write-Output "Error calling sc.exe.";
                            }
                        }
                    }
                }

                Write-Verbose "Cleaning Files remaining if found.";

                #Remove %ltsvcdir% - Depth First Removal, First by purging files, then Removing Folders, to get as much removed as possible if complete removal fails
                @($BasePath, "${env:windir}\temp\_ltupdate", "${env:windir}\temp\_ltupdate") | ForEach-Object {

                    if ((Test-Path "$($_)" -ErrorAction SilentlyContinue)) {

                        if ( $PSCmdlet.ShouldProcess("$($_)", "Remove Folder") ) {

                            Write-Debug "Line $(LINENUM): Removing Folder: $($_)";

                            try {

                                Get-ChildItem -Path $_ -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { ($_.psiscontainer) } | ForEach-Object { Get-ChildItem -Path "$($_.FullName)" -ErrorAction SilentlyContinue | Where-Object { -not ($_.psiscontainer) } | Remove-Item -Force -ErrorAction SilentlyContinue -Confirm:$False -WhatIf:$False };
                                Get-ChildItem -Path $_ -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { ($_.psiscontainer) } | Sort-Object { $_.fullname.length } -Descending | Remove-Item -Force -ErrorAction SilentlyContinue -Recurse -Confirm:$False -WhatIf:$False;
                                Remove-Item -Recurse -Force -Path $_ -ErrorAction SilentlyContinue -Confirm:$False -WhatIf:$False;

                            } catch {}
                        }
                    }
                }

                Write-Verbose "Cleaning Registry Keys if found.";

                #Remove all registry keys - Depth First Value Removal, then Key Removal, to get as much removed as possible if complete removal fails
                foreach ($reg in $regs) {

                    if ((Test-Path "$($reg)" -ErrorAction SilentlyContinue)) {

                        Write-Debug "Line $(LINENUM): Found Registry Key: $($reg)";

                        if ( $PSCmdlet.ShouldProcess("$($Reg)", "Remove Registry Key") ) {

                            try {

                                Get-ChildItem -Path $reg -Recurse -Force -ErrorAction SilentlyContinue | Sort-Object { $_.name.length } -Descending | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$False -WhatIf:$False;
                                Remove-Item -Recurse -Force -Path $reg -ErrorAction SilentlyContinue -Confirm:$False -WhatIf:$False;

                            } catch {}
                        }
                    }
                }

            } catch {
                Write-Error "ERROR: Line $(LINENUM): There was an error during the uninstall process. $($Error[0])" -ErrorAction Stop;
            }

            if ($WhatIfPreference -ne $True) {

                if ($?) {

                    #Post Uninstall Check
                    If ((Test-Path "${env:windir}\ltsvc" -ErrorAction SilentlyContinue) -or (Test-Path "${env:windir}\temp\_ltupdate" -ErrorAction SilentlyContinue) -or (Test-Path registry::HKLM\Software\LabTech\Service) -or (Test-Path registry::HKLM\Software\WOW6432Node\Labtech\Service)) {
                        Start-Sleep -Seconds 10;
                    }

                    If ((Test-Path "${env:windir}\ltsvc" -ErrorAction SilentlyContinue) -or (Test-Path "${env:windir}\temp\_ltupdate" -ErrorAction SilentlyContinue) -or (Test-Path registry::HKLM\Software\LabTech\Service) -or (Test-Path registry::HKLM\Software\WOW6432Node\Labtech\Service)) {
                        Write-Error "ERROR: Line $(LINENUM): Remnants of previous install still detected after uninstall attempt. Please reboot and try again.";
                    } else {
                        Write-Output "LabTech has been successfully uninstalled.";
                    }

                } else {
                    Write-Output $($Error[0]);
                }
            }

        } elseif ($WhatIfPreference -ne $True) {
            Write-Error "ERROR: Line $(LINENUM): No valid server was reached to use for the uninstall." -ErrorAction Stop;
        }

        if ($WhatIfPreference -ne $True) {

            #Cleanup uninstall files
            Remove-Item "$UninstallBase\$UninstallEXE", "$UninstallBase\$UninstallMSI" -ErrorAction SilentlyContinue -Force -Confirm:$False;
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

Function Install-LTService {
    <#
    .SYNOPSIS
        This function will install the LabTech agent on the machine.

    .DESCRIPTION
        This function will install the LabTech agent on the machine with the specified server/password/location.

    .PARAMETER Server
        This is the URL to your LabTech server.
        example: https://lt.domain.com
        This is used to download the installation files.
        (Get-LTServiceInfo|Select-Object -Expand 'Server Address' -ErrorAction SilentlyContinue)

    .PARAMETER ServerPassword
        This is the server password that agents use to authenticate with the LabTech server.
        SELECT SystemPassword FROM config;

    .PARAMETER InstallerToken
        Permits use of installer tokens for customized MSI downloads. (Other installer types are not supported)

    .PARAMETER LocationID
        This is the LocationID of the location that the agent will be put into.
        (Get-LTServiceInfo).LocationID

    .PARAMETER TrayPort
        This is the port LTSvc.exe listens on for communication with LTTray processes.

    .PARAMETER Rename
        This will call Rename-LTAddRemove after the install.

    .PARAMETER Hide
        This will call Hide-LTAddRemove after the install.

    .PARAMETER SkipDotNet
        This will disable the error checking for the .NET 3.5 and .NET 2.0 frameworks during the install process.

    .PARAMETER Force
        This will disable some of the error checking on the install process.

    .PARAMETER NoWait
        This will skip the ending health check for the install process.
        The function will exit once the installer has completed.

    .EXAMPLE
        Install-LTService -Server https://lt.domain.com -Password 'plain text pass' -LocationID 42
        This will install the LabTech agent using the provided Server URL, Password, and LocationID.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $True, DefaultParameterSetName = 'deployment')]
    Param(
        [Parameter(ParameterSetName = 'deployment')]
        [Parameter(ParameterSetName = 'installertoken')]
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string[]]$Server,
        [Parameter(ParameterSetName = 'deployment')]
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [AllowNull()]
        [Alias("Password")]
        [string]$ServerPassword,
        [Parameter(ParameterSetName = 'installertoken')]
        [ValidatePattern('(?s:^[0-9a-z\-]+$)')]
        [string]$InstallerToken,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [AllowNull()]
        [int]$LocationID,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [AllowNull()]
        [int]$TrayPort,
        [Parameter()]
        [AllowNull()]
        [string]$Rename,
        [switch]$Hide,
        [switch]$SkipDotNet,
        [switch]$Force,
        [switch]$NoWait
    )

    Begin {

        Clear-Variable DotNET, OSVersion, PasswordArg, Result, logpath, logfile, curlog, installer, installerTest, installerResult, GoodServer, GoodTrayPort, TestTrayPort, Svr, SVer, SvrVer, SvrVerCheck, iarg, timeout, sw, tmpLTSI -ErrorAction SilentlyContinue -WhatIf:$False -Confirm:$False; #Clearing Variables for use

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        if (-not($Force)) {

            if (Get-Service 'LTService', 'LTSvcMon' -ErrorAction SilentlyContinue) {

                if ($WhatIfPreference -ne $True) {
                    Write-Error "ERROR: Line $(LINENUM): Services are already installed." -ErrorAction Stop;
                } else {
                    Write-Error "ERROR: Line $(LINENUM): What if: Stopping: Services are already installed." -ErrorAction Stop;
                }
            }
        }

        if (-not ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object -Expand groups -ErrorAction SilentlyContinue) -match 'S-1-5-32-544'))) {
            throw "Needs to be ran as Administrator";
        }

        if (-not($SkipDotNet)) {

            $DotNET = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -ErrorAction SilentlyContinue | Get-ItemProperty -Name Version, Release -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -ExpandProperty Version -ErrorAction SilentlyContinue;

            if (-not ($DotNet -like '3.5.*')) {

                Write-Output ".NET Framework 3.5 installation needed.";

                $OSVersion = [System.Environment]::OSVersion.Version;

                if ([version]$OSVersion -gt [version]'6.2') {

                    try {

                        if ( $PSCmdlet.ShouldProcess('NetFx3', 'Enable-WindowsOptionalFeature') ) {

                            $Install = Get-WindowsOptionalFeature -Online -FeatureName 'NetFx3';

                            if (-not($Install.State -eq 'EnablePending')) {
                                $Install = Enable-WindowsOptionalFeature -Online -FeatureName 'NetFx3' -All -NoRestart;
                            }

                            if ($Install.RestartNeeded -or $Install.State -eq 'EnablePending') {
                                Write-Output ".NET Framework 3.5 installed but a reboot is needed.";
                            }
                        }

                    } catch {

                        Write-Error "ERROR: Line $(LINENUM): .NET 3.5 install failed." -ErrorAction Continue;

                        if (-not($Force)) {
                            Write-Error ("Line $(LINENUM):", $Install) -ErrorAction Stop;
                        }
                    }

                } else {
                    throw "You should be ashamed of yourself for running this on such an outdated OS!";
                }

                $DotNET = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name Version -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -ExpandProperty Version;
            }

            if (-not ($DotNet -like '3.5.*')) {

                if ($Force) {

                    if ($DotNet -match '(?m)^[2-4].\d') {
                        Write-Error "ERROR: Line $(LINENUM): .NET 3.5 is not detected and could not be installed." -ErrorAction Continue;
                    } else {
                        Write-Error "ERROR: Line $(LINENUM): .NET 2.0 or greater is not detected and could not be installed." -ErrorAction Stop;
                    }

                } else {
                    Write-Error "ERROR: Line $(LINENUM): .NET 3.5 is not detected and could not be installed." -ErrorAction Stop;
                }
            }
        }

        $InstallBase = "${env:windir}\Temp\LabTech";
        $logfile = "LTAgentInstall";
        $curlog = "$($InstallBase)\$($logfile).log";

        if ($ServerPassword -match '"') {
            $ServerPassword = $ServerPassword.Replace('"', '""');
        }

        if (-not (Test-Path -PathType Container -Path "$InstallBase\Installer" -ErrorAction SilentlyContinue)) {
            $null = New-Item "$InstallBase\Installer" -type directory -ErrorAction SilentlyContinue;
        }

        if (Test-Path -PathType Leaf -Path $($curlog)-ErrorAction SilentlyContinue) {

            if ($PSCmdlet.ShouldProcess("$($curlog)", "Rotate existing log file")) {

                Get-Item -LiteralPath $curlog -ErrorAction SilentlyContinue | Where-Object { $_ } | ForEach-Object {

                    Rename-Item -Path $($_ | Select-Object -Expand FullName -ErrorAction SilentlyContinue) -NewName "$($logfile)-$(Get-Date $($_|Select-Object -Expand LastWriteTime -ErrorAction SilentlyContinue) -Format 'yyyyMMddHHmmss').log" -Force -Confirm:$False -WhatIf:$False;
                    Remove-Item -Path $($_ | Select-Object -Expand FullName -ErrorAction SilentlyContinue) -Force -ErrorAction SilentlyContinue -Confirm:$False -WhatIf:$False;
                }
            }
        }
    }

    Process {

        if (-not ($LocationID -or $PSCmdlet.ParameterSetName -eq 'installertoken')) {
            $LocationID = "1";
        }

        if (-not ($TrayPort) -or -not ($TrayPort -ge 1 -and $TrayPort -le 65535)) {
            $TrayPort = "42000";
        }

        $Server = foreach ($Svr in $Server) {

            if ($Svr -notmatch 'https?://.+') {
                "https://$($Svr)"
            }

            $Svr
        }

        foreach ($Svr in $Server) {

            if (-not ($GoodServer)) {

                if ($Svr -match '^(https?://)?(([12]?[0-9]{1,2}\.){3}[12]?[0-9]{1,2}|[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)*)$') {

                    $InstallMSI = 'Agent_Install.msi';

                    if ($Svr -notmatch 'https?://.+') {
                        $Svr = "http://$($Svr)";
                    }

                    try {

                        $SvrVerCheck = "$($Svr)/LabTech/Agent.aspx";

                        Write-Debug "Line $(LINENUM): Testing Server Response and Version: $SvrVerCheck";
                        $SvrVer = $Script:LTServiceNetWebClient.DownloadString($SvrVerCheck);

                        Write-Debug "Line $(LINENUM): Raw Response: $SvrVer";
                        $SVer = $SvrVer | Select-String -Pattern '(?<=[|]{6})[0-9]{1,3}\.[0-9]{1,3}' | ForEach-Object { $_.matches } | Select-Object -Expand value -ErrorAction SilentlyContinue;

                        if ($null -eq $SVer) {
                            Write-Verbose "Unable to test version response from $($Svr).";
                            continue;
                        }

                        if (($PSCmdlet.ParameterSetName -eq 'installertoken')) {

                            $installer = "$($Svr)/LabTech/Deployment.aspx?InstallerToken=$InstallerToken";

                            if ([System.Version]$SVer -ge [System.Version]'240.331') {

                                Write-Debug "Line $(LINENUM): New MSI Installer Format Needed";
                                $InstallMSI = 'Agent_Install.zip'
                            }

                        } elseif ($ServerPassword) {

                            $installer = "$($Svr)/LabTech/Service/LabTechRemoteAgent.msi";

                        } elseif ([System.Version]$SVer -ge [System.Version]'110.374') {

                            #New Style Download Link starting with LT11 Patch 13 - Direct Location Targeting is no longer available
                            $installer = "$($Svr)/LabTech/Deployment.aspx?Probe=1&installType=msi&MSILocations=1";

                        } else {
                            #Original URL
                            Write-Warning 'Update your damn server!';
                            $installer = "$($Svr)/LabTech/Deployment.aspx?Probe=1&installType=msi&MSILocations=$LocationID";
                        }

                        # Vuln test June 10, 2020: ConnectWise Automate API Vulnerability - Only test if version is below known minimum.
                        if ([System.Version]$SVer -lt [System.Version]'200.197') {

                            try {

                                $HTTP_Request = [System.Net.WebRequest]::Create("$($Svr)/LabTech/Deployment.aspx");

                                if ($HTTP_Request.GetResponse().StatusCode -eq 'OK') {

                                    $Message = $('Your server is vulnerable!!{0}{0}https://docs.connectwise.com/ConnectWise_Automate/ConnectWise_Automate_Supportability_Statements/Supportability_Statement%3A_ConnectWise_Automate_Mitigation_Steps' -f [System.Environment]::NewLine)
                                    Write-Warning $($Message | Out-String)
                                }

                            } catch {

                                if ($null -eq $ServerPassword) {

                                    Write-Error 'Anonymous downloads are not allowed. ServerPassword or InstallerToken may be needed.';
                                    continue;
                                }
                            }
                        }

                        if ( $PSCmdlet.ShouldProcess($installer, "DownloadFile") ) {

                            Write-Debug "Line $(LINENUM): Downloading $InstallMSI from $installer";
                            $Script:LTServiceNetWebClient.DownloadFile($installer, "$InstallBase\Installer\$InstallMSI");

                            If ((Test-Path "$InstallBase\Installer\$InstallMSI" -ErrorAction SilentlyContinue) -and -not((Get-Item "$InstallBase\Installer\$InstallMSI" -ErrorAction SilentlyContinue).length / 1KB -gt 1234)) {

                                Write-Warning "WARNING: Line $(LINENUM): $InstallMSI size is below normal. Removing suspected corrupt file.";
                                Remove-Item "$InstallBase\Installer\$InstallMSI" -ErrorAction SilentlyContinue -Force -Confirm:$False;
                                continue;
                            }
                        }

                        if ($WhatIfPreference -eq $True) {

                            $GoodServer = $Svr;

                        } elseif (Test-Path "$InstallBase\Installer\$InstallMSI" -ErrorAction SilentlyContinue) {

                            $GoodServer = $Svr;
                            Write-Verbose "$InstallMSI downloaded successfully from server $($Svr).";

                            if (($PSCmdlet.ParameterSetName -eq 'installertoken') -and [System.Version]$SVer -ge [System.Version]'240.331') {

                                Expand-Archive "$InstallBase\Installer\$InstallMSI" -DestinationPath "$InstallBase\Installer" -Force;
                                #Cleanup .ZIP
                                Remove-Item "$InstallBase\Installer\$InstallMSI" -ErrorAction SilentlyContinue -Force -Confirm:$False;
                                #Reset InstallMSI Value
                                $InstallMSI = 'Agent_Install.msi';
                            }

                        } else {
                            Write-Warning "WARNING: Line $(LINENUM): Error encountered downloading from $($Svr). No installation file was received.";
                            continue;
                        }

                    } catch {

                        Write-Warning "WARNING: Line $(LINENUM): Error encountered downloading from $($Svr).";
                        continue;
                    }

                } else {
                    Write-Warning "WARNING: Line $(LINENUM): Server address $($Svr) is not formatted correctly. Example: https://lt.domain.com";
                }

            } else {
                Write-Debug "Line $(LINENUM): Server $($GoodServer) has been selected.";
                Write-Verbose "Server has already been selected - Skipping $($Svr).";
            }
        }
    }

    End {

        if ($GoodServer) {

            if ( $WhatIfPreference -eq $True -and (Get-PSCallStack)[1].Command -eq 'Redo-LTService' ) {

                Write-Debug "Line $(LINENUM): Skipping Preinstall Check: Called by Redo-LTService and ""-WhatIf=`$True""";

            } else {

                if ((Test-Path "${env:windir}\ltsvc" -ErrorAction SilentlyContinue) -or (Test-Path "${env:windir}\temp\_ltupdate" -ErrorAction SilentlyContinue) -or (Test-Path registry::HKLM\Software\LabTech\Service -ErrorAction SilentlyContinue) -or (Test-Path registry::HKLM\Software\WOW6432Node\Labtech\Service -ErrorAction SilentlyContinue)) {

                    Write-Warning "WARNING: Line $(LINENUM): Previous installation detected. Calling Uninstall-LTService";

                    Uninstall-LTService -Server $GoodServer -Force;
                    Start-Sleep 10;
                }
            }

            if ($WhatIfPreference -ne $True) {

                $GoodTrayPort = $null;
                $TestTrayPort = $TrayPort;

                For ($i = 0; $i -le 10; $i++) {

                    if (-not ($GoodTrayPort)) {

                        if (-not (Test-LTPorts -TrayPort $TestTrayPort -Quiet)) {

                            $TestTrayPort++;

                            if ($TestTrayPort -gt 42009) {
                                $TestTrayPort = 42000;
                            }

                        } else {
                            $GoodTrayPort = $TestTrayPort;
                        }
                    }
                }

                if ($GoodTrayPort -and $GoodTrayPort -ne $TrayPort -and $GoodTrayPort -ge 1 -and $GoodTrayPort -le 65535) {

                    Write-Verbose "TrayPort $($TrayPort) is in use. Changing TrayPort to $($GoodTrayPort)";
                    $TrayPort = $GoodTrayPort
                }

                Write-Output "Starting Install.";
            }

            #Build parameter string
            $iarg = ($(
                    "/i `"$InstallBase\Installer\$InstallMSI`""
                    "SERVERADDRESS=$GoodServer"
                    if (($PSCmdlet.ParameterSetName -eq 'installertoken') -and [System.Version]$SVer -ge [System.Version]'240.331') { "TRANSFORMS=`"Agent_Install.mst`"" }
                    if ($ServerPassword -and $ServerPassword -match '.') { "SERVERPASS=`"$($ServerPassword)`"" }
                    if ($LocationID -and $LocationID -match '^\d+$') { "LOCATION=$LocationID" }
                    if ($TrayPort -and $TrayPort -ne 42000) { "SERVICEPORT=$TrayPort" }
                    "/qn"
                    "/l `"$InstallBase\$logfile.log`""
                ) | Where-Object { $_ }) -join ' '

            try {

                if ( $PSCmdlet.ShouldProcess("msiexec.exe $($iarg)", "Execute Install") ) {

                    $InstallAttempt = 0;

                    Do {

                        if ($InstallAttempt -gt 0 ) {

                            Write-Warning "WARNING: Line $(LINENUM): Service Failed to Install. Retrying in 30 seconds." -WarningAction 'Continue';

                            $timeout = New-TimeSpan -Seconds 30;
                            $sw = [diagnostics.stopwatch]::StartNew();

                            Do {

                                Start-Sleep 5;
                                $svcRun = ('LTService') | Get-Service -ErrorAction SilentlyContinue | Measure-Object | Select-Object -Expand Count;

                            } Until ($sw.elapsed -gt $timeout -or $svcRun -eq 1)

                            $sw.Stop();
                        }

                        $InstallAttempt++
                        $svcRun = ('LTService') | Get-Service -ErrorAction SilentlyContinue | Measure-Object | Select-Object -Expand Count;

                        if ($svcRun -eq 0) {

                            Write-Verbose "Launching Installation Process: msiexec.exe $(($iarg -join ''))";
                            Start-Process -Wait -FilePath "${env:windir}\system32\msiexec.exe" -ArgumentList $iarg -WorkingDirectory $env:TEMP;
                            Start-Sleep 5;
                        }

                        $svcRun = ('LTService') | Get-Service -ErrorAction SilentlyContinue | Measure-Object | Select-Object -Expand Count;

                    } Until ($InstallAttempt -ge 3 -or $svcRun -eq 1)

                    if ($svcRun -eq 0) {
                        Write-Error "ERROR: Line $(LINENUM): LTService was not installed. Installation failed." -ErrorAction Stop;
                    }
                }

                if (($Script:LTProxy.Enabled) -eq $True) {

                    Write-Verbose "Proxy Configuration Needed. Applying Proxy Settings to Agent Installation.";

                    if ( $PSCmdlet.ShouldProcess($Script:LTProxy.ProxyServerURL, "Configure Agent Proxy") ) {

                        $svcRun = ('LTService') | Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | Measure-Object | Select-Object -Expand Count;

                        if ($svcRun -ne 0) {

                            $timeout = New-TimeSpan -Minutes 2;
                            $sw = [diagnostics.stopwatch]::StartNew();

                            Write-Host -NoNewline "Waiting for Service to Start.";

                            Do {

                                Write-Host -NoNewline '.';
                                Start-Sleep 2;
                                $svcRun = ('LTService') | Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | Measure-Object | Select-Object -Expand Count;

                            } Until ($sw.elapsed -gt $timeout -or $svcRun -eq 1)

                            Write-Host "";
                            $sw.Stop();

                            if ($svcRun -eq 1) {
                                Write-Debug "Line $(LINENUM): LTService Initial Startup Successful.";
                            } else {
                                Write-Debug "Line $(LINENUM): LTService Initial Startup failed to complete within expected period.";
                            }
                        }

                        Set-LTProxy -ProxyServerURL $Script:LTProxy.ProxyServerURL -ProxyUsername $Script:LTProxy.ProxyUsername -ProxyPassword $Script:LTProxy.ProxyPassword -Confirm:$False -WhatIf:$False;
                    }

                } else {
                    Write-Verbose "No Proxy Configuration has been specified - Continuing.";
                }

                if (-not($NoWait) -and $PSCmdlet.ShouldProcess("LTService", "Monitor For Successful Agent Registration") ) {

                    $timeout = New-TimeSpan -Minutes 3;
                    $sw = [diagnostics.stopwatch]::StartNew();

                    Write-Host -NoNewline "Waiting for agent to register.";

                    Do {

                        Write-Host -NoNewline '.';
                        Start-Sleep 5;

                        $tmpLTSI = (Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$False -WhatIf:$False -Confirm:$False -Debug:$False | Select-Object -Expand 'ID' -ErrorAction SilentlyContinue);

                    } Until ($sw.elapsed -gt $timeout -or $tmpLTSI -ge 1)

                    Write-Host "";
                    $sw.Stop();

                    Write-Verbose "Completed wait for LabTech Installation after $(([int32]$sw.Elapsed.TotalSeconds).ToString()) seconds.";
                    $null = Get-LTProxy -ErrorAction Continue;
                }

                if ($Hide) {
                    Hide-LTAddRemove;
                }

            } catch {
                Write-Error "ERROR: Line $(LINENUM): There was an error during the install process. $($Error[0])" -ErrorAction Stop;
            }

            if ($WhatIfPreference -ne $True) {

                #Cleanup Install files
                Remove-Item "$InstallBase\Installer\$InstallMSI" -ErrorAction SilentlyContinue -Force -Confirm:$False;
                Remove-Item "$InstallBase\Installer\Agent_Install.mst" -ErrorAction SilentlyContinue -Force -Confirm:$False;

                @($curlog, "${env:windir}\LTSvc\Install.log") | ForEach-Object {

                    if (Test-Path -PathType Leaf -LiteralPath $($_) -ErrorAction SilentlyContinue) {

                        $logcontents = Get-Content -Path $_;
                        $logcontents = $logcontents -replace '(?<=PreInstallPass:[^\r\n]+? (?:result|value)): [^\r\n]+', ': <REDACTED>';

                        if ($logcontents) {
                            Set-Content -Path $_ -Value $logcontents -Force -Confirm:$False;
                        }
                    }
                }

                $tmpLTSI = Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$False -WhatIf:$False -Confirm:$False -Debug:$False;

                if (($tmpLTSI)) {

                    if (($tmpLTSI | Select-Object -Expand 'ID' -ErrorAction SilentlyContinue) -ge 1) {

                        Write-Output "LabTech has been installed successfully. Agent ID: $($tmpLTSI|Select-Object -Expand 'ID' -ErrorAction SilentlyContinue) LocationID: $($tmpLTSI|Select-Object -Expand 'LocationID' -ErrorAction SilentlyContinue)";

                    } elseif (-not($NoWait)) {

                        Write-Error "ERROR: Line $(LINENUM): LabTech installation completed but Agent failed to register within expected period." -ErrorAction Continue;

                    } else {
                        Write-Warning "WARNING: Line $(LINENUM): LabTech installation completed but Agent did not yet register." -WarningAction continue;
                    }

                } else {

                    if (-not($null -eq $Error)) {

                        Write-Error "ERROR: Line $(LINENUM): There was an error installing LabTech. Check the log, $InstallBase\$logfile.log $($Error[0])" -ErrorAction Stop;

                    } elseif (-not($NoWait)) {

                        Write-Error "ERROR: Line $(LINENUM): There was an error installing LabTech. Check the log, $InstallBase\$logfile.log" -ErrorAction Stop;

                    } else {
                        Write-Warning "WARNING: Line $(LINENUM): LabTech installation may not have succeeded." -WarningAction continue;
                    }
                }
            }

            if (($Rename) -and $Rename -notmatch 'False') {
                Rename-LTAddRemove -Name $Rename;
            }

        } elseif ( $WhatIfPreference -ne $True ) {
            Write-Error "ERROR: Line $(LINENUM): No valid server was reached to use for the install.";
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function Redo-LTService {
    <#
    .SYNOPSIS
        This function will reinstall the LabTech agent from the machine.

    .DESCRIPTION
        This script will attempt to pull all current settings from machine and issue an 'Uninstall-LTService', 'Install-LTService' with gathered information.
        ifthe function is unable to find the settings it will ask for needed parameters.

    .PARAMETER Server
        This is the URL to your LabTech server.
        Example: https://lt.domain.com
        This is used to download the installation and removal utilities.
        ifno server is provided the uninstaller will use Get-LTServiceInfo to get the server address.
        ifit is unable to find LT currently installed it will try Get-LTServiceInfoBackup

    .PARAMETER ServerPassword
        This is the Server Password to your LabTech server.
        SELECT SystemPassword FROM config;

    .PARAMETER InstallerToken
        Permits use of installer tokens for customized MSI downloads. (Other installer types are not supported)

    .PARAMETER LocationID
        The LocationID of the location that you want the agent in
        example: 555

    .PARAMETER Backup
        This will run a New-LTServiceBackup command before uninstalling.

    .PARAMETER Hide
        Will remove from add-remove programs

    .PARAMETER Rename
        This will call Rename-LTAddRemove to rename the install in Add/Remove Programs

    .PARAMETER SkipDotNet
        This will disable the error checking for the .NET 3.5 and .NET 2.0 frameworks during the install process.

    .PARAMETER Force
        This will force operation on an agent detected as a probe.

    .EXAMPLE
        Redo-LTService
        This will ReInstall the LabTech agent using the server address in the registry.

    .EXAMPLE
        Redo-LTService -Server https://lt.domain.com -Password sQWZzEDYKFFnTT0yP56vgA== -LocationID 42
        This will ReInstall the LabTech agent using the provided server URL to download the installation files.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'deployment')]
    Param(
        [Parameter(ParameterSetName = 'deployment')]
        [Parameter(ParameterSetName = 'installertoken')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        [string[]]$Server,
        [Parameter(ParameterSetName = 'deployment')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [Alias("Password")]
        [string]$ServerPassword,
        [Parameter(ParameterSetName = 'installertoken')]
        [ValidatePattern('(?s:^[0-9a-z]+$)')]
        [string]$InstallerToken,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [AllowNull()]
        [string]$LocationID,
        [switch]$Backup,
        [switch]$Hide,
        [Parameter()]
        [AllowNull()]
        [string]$Rename,
        [switch]$SkipDotNet,
        [switch]$Force
    )

    Begin {

        Clear-Variable PasswordArg, RenameArg, Svr, ServerList, Settings -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false; #Clearing Variables for use
        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        # Gather install stats from registry or backed up settings
        try {

            $Settings = Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false;

            if ($null -ne $Settings) {

                if (($Settings | Select-Object -Expand Probe -ErrorAction SilentlyContinue) -eq '1') {

                    if ($Force -eq $true) {
                        Write-Output "Probe Agent Detected. Re-Install Forced.";
                    } else {

                        if ($WhatIfPreference -ne $true) {
                            Write-Error -Exception [System.OperationCanceledException]"ERROR: Probe Agent Detected. Re-Install Denied." -ErrorAction Stop;
                        } else {
                            Write-Error -Exception [System.OperationCanceledException]"What If: Probe Agent Detected. Re-Install Denied." -ErrorAction Stop;
                        }
                    }
                }
            }

        } catch {
            Write-Debug "Failed to retrieve current Agent Settings.";
        }

        if ($null -eq $Settings) {

            Write-Debug "Unable to retrieve current Agent Settings. Testing for Backup Settings";

            try {
                $Settings = Get-LTServiceInfoBackup -ErrorAction SilentlyContinue;
            } catch {}
        }

        $ServerList = [System.Collections.Generic.List[string]]::new();
    }

    Process {

        if (-not ($Server)) {

            if ($Settings) {
                $Server = $Settings | Select-Object -Expand 'Server' -ErrorAction SilentlyContinue;
            }

            if (-not ($Server)) {
                $Server = Read-Host -Prompt 'Provide the URL to your LabTech server (https://lt.domain.com):';
            }
        }

        if (-not ($LocationID)) {

            if ($Settings) {
                $LocationID = $Settings | Select-Object -Expand LocationID -ErrorAction SilentlyContinue;
            }

            if (-not ($LocationID)) {
                $LocationID = Read-Host -Prompt 'Provide the LocationID';
            }
        }

        if (-not ($LocationID)) {
            $LocationID = "1";
        }

        $ServerList.Add($Server);
    }

    End {

        if ($Backup) {

            if ( $PSCmdlet.ShouldProcess("LTService", "Backup Current Service Settings") ) {
                New-LTServiceBackup;
            }
        }

        $RenameArg = '';

        if ($Rename) {
            $RenameArg = "-Rename $Rename";
        }

        if ($PSCmdlet.ParameterSetName -eq 'installertoken') {
            $PasswordPresent = "-InstallerToken 'REDACTED'";
        } elseif (($ServerPassword)) {
            $PasswordPresent = "-Password 'REDACTED'";
        }

        Write-Output "Reinstalling LabTech with the following information, -Server $($ServerList -join ',') $PasswordPresent -LocationID $LocationID $RenameArg";
        Write-Verbose "Starting: Uninstall-LTService -Server $($ServerList -join ',')";

        try {

            Uninstall-LTService -Server $ServerList -ErrorAction Stop -Force;

        } catch {

            Write-Error "ERROR: There was an error during the reinstall process while uninstalling. $($Error[0])" -ErrorAction Stop;

        } finally {

            if ($WhatIfPreference -ne $true) {
                Write-Verbose "Waiting 20 seconds for prior uninstall to settle before starting Install.";
                Start-Sleep 20;
            }
        }

        Write-Verbose "Starting: Install-LTService -Server $($ServerList -join ',') $PasswordPresent -LocationID $LocationID -Hide:`$$($Hide) $RenameArg";

        try {

            if ($PSCmdlet.ParameterSetName -ne 'installertoken') {
                Install-LTService -Server $ServerList -ServerPassword $ServerPassword -LocationID $LocationID -Hide:$Hide -Rename $Rename -SkipDotNet:$SkipDotNet -Force;
            } else {
                Install-LTService -Server $ServerList -InstallerToken $InstallerToken -LocationID $LocationID -Hide:$Hide -Rename $Rename -SkipDotNet:$SkipDotNet -Force;
            }

        } catch {
            Write-Error "ERROR: There was an error during the reinstall process while installing. $($Error[0])" -ErrorAction Stop;
        }

        if (-not($?)) {
            $($Error[0]);
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}
Set-Alias -Name ReInstall-LTService -Value Redo-LTService;

function Update-LTService {
    <#
    .SYNOPSIS
        This function will manually update the LabTech agent to the requested version.

    .DESCRIPTION
        This script will attempt to pull current server settings from machine, then download and run the agent updater.


    .PARAMETER Version
        This is the agent version to install.
        Example: 120.240
        This is needed to download the update file. ifomitted, the version advertised by the server will be used.

    .EXAMPLE
        Update-LTService -Version 120.240
        This will update the Automate agent to the specific version requested, using the server address in the registry.

    .EXAMPLE
        Update-LTService
        This will update the Automate agent to the current version advertised, using the server address in the registry.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [parameter(Position = 0)]
        [AllowNull()]
        [string]$Version
    )

    Begin {

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        Clear-Variable Svr, GoodServer, Settings -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false; #Clearing Variables for use

        $Settings = Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false;
        $updaterPath = [System.Environment]::ExpandEnvironmentVariables("%windir%\temp\_LTUpdate");
        $xarg = @("/o""$updaterPath""", "/y");
        $uarg = @("""$updaterPath\Update.ini""");
    }

    Process {

        if ($null -eq $Server) {
            if ($Settings) {
                $Server = $Settings | Select-Object -Expand 'Server' -ErrorAction SilentlyContinue;
            }
        }

        $Server = foreach ($Svr in $Server) {

            if ($Svr -notmatch 'https?://.+') {
                "https://$($Svr)"
            }

            $Svr;
        }

        foreach ($Svr in $Server) {

            if (-not ($GoodServer)) {

                if ($Svr -match '^(https?://)?(([12]?[0-9]{1,2}\.){3}[12]?[0-9]{1,2}|[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)*)$') {

                    if ($Svr -notmatch 'https?://.+') {
                        $Svr = "http://$($Svr)";
                    }

                    try {

                        $SvrVerCheck = "$($Svr)/LabTech/Agent.aspx";

                        Write-Debug "Testing Server Response and Version: $SvrVerCheck";
                        $SvrVer = $Script:LTServiceNetWebClient.DownloadString($SvrVerCheck);

                        Write-Debug "Raw Response: $SvrVer";
                        $SVer = $SvrVer | Select-String -Pattern '(?<=[|]{6})[0-9]{1,3}\.[0-9]{1,3}' | ForEach-Object { $_.matches } | Select-Object -Expand value -ErrorAction SilentlyContinue;

                        if ($null -eq ($SVer)) {
                            Write-Verbose "Unable to test version response from $($Svr).";
                            continue;
                        }

                        if ($Version -match '[1-9][0-9]{2}\.[0-9]{1,3}') {

                            $updater = "$($Svr)/LabTech/Updates/LabtechUpdate_$($Version).zip";

                        } elseif ([System.Version]$SVer -ge [System.Version]'105.001') {

                            $Version = $SVer;
                            Write-Verbose "Using detected version ($Version) from server: $($Svr).";
                            $updater = "$($Svr)/LabTech/Updates/LabtechUpdate_$($Version).zip";
                        }

                        #Kill all running processes from $updaterPath
                        if (Test-Path $updaterPath -ErrorAction SilentlyContinue) {

                            $Executables = (Get-ChildItem $updaterPath -Filter *.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -Expand FullName);

                            if ($Executables) {

                                Write-Verbose "Terminating LabTech Processes from $($updaterPath) if found running: $(($Executables) -replace [Regex]::Escape($updaterPath),'' -replace '^\\','')";

                                Get-Process | Where-Object { $Executables -contains $_.Path } | ForEach-Object {
                                    Write-Debug "Terminating Process $($_.ProcessName)";
                                    $($_) | Stop-Process -Force -ErrorAction SilentlyContinue;
                                }
                            }
                        }

                        #Remove $updaterPath - Depth First Removal, First by purging files, then Removing Folders, to get as much removed as possible if complete removal fails
                        @("$updaterPath") | ForEach-Object {

                            if ((Test-Path "$($_)" -ErrorAction SilentlyContinue)) {

                                if ( $PSCmdlet.ShouldProcess("$($_)", "Remove Folder") ) {

                                    Write-Debug "Removing Folder: $($_)";
                                    try {

                                        Get-ChildItem -Path $_ -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { ($_.psiscontainer) } | ForEach-Object {
                                            Get-ChildItem -Path "$($_.FullName)" -ErrorAction SilentlyContinue | Where-Object { -not ($_.psiscontainer) } | Remove-Item -Force -ErrorAction SilentlyContinue -Confirm:$false -WhatIf:$false;
                                        }

                                        Get-ChildItem -Path $_ -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { ($_.psiscontainer) } | Sort-Object { $_.fullname.length } -Descending | Remove-Item -Force -ErrorAction SilentlyContinue -Recurse -Confirm:$false -WhatIf:$false;

                                        Remove-Item -Recurse -Force -Path $_ -ErrorAction SilentlyContinue -Confirm:$false -WhatIf:$false;

                                    } catch {}
                                }
                            }
                        }-Object

                        try {

                            if (-not (Test-Path -PathType Container -Path "$updaterPath" -ErrorAction SilentlyContinue)) {
                                $null = New-Item "$updaterPath" -type directory -ErrorAction SilentlyContinue;
                            }

                            $updaterTest = [System.Net.WebRequest]::Create($updater);

                            if (($Script:LTProxy.Enabled) -eq $true) {
                                Write-Debug "Proxy Configuration Needed. Applying Proxy Settings to request.";
                                $updaterTest.Proxy = $Script:LTWebProxy;
                            }

                            $updaterTest.KeepAlive = $false;
                            $updaterTest.ProtocolVersion = '1.0';
                            $updaterResult = $updaterTest.GetResponse();
                            $updaterTest.Abort();

                            if ($updaterResult.StatusCode -ne 200) {

                                Write-Warning "WARNING: Unable to download LabtechUpdate.exe version $Version from server $($Svr).";
                                continue;

                            } else {

                                if ( $PSCmdlet.ShouldProcess($updater, "DownloadFile") ) {

                                    Write-Debug "Downloading LabtechUpdate.exe from $updater";

                                    $Script:LTServiceNetWebClient.DownloadFile($updater, "$updaterPath\LabtechUpdate.exe")

                                    if ((Test-Path "$updaterPath\LabtechUpdate.exe" -ErrorAction SilentlyContinue) -and -not((Get-Item "$updaterPath\LabtechUpdate.exe" -ErrorAction SilentlyContinue).length / 1KB -gt 1234)) {

                                        Write-Warning "WARNING: LabtechUpdate.exe size is below normal. Removing suspected corrupt file.";
                                        Remove-Item "$updaterPath\LabtechUpdate.exe" -ErrorAction SilentlyContinue -Force -Confirm:$false
                                        continue;
                                    }
                                }

                                if ($WhatIfPreference -eq $true) {
                                    $GoodServer = $Svr;
                                } elseif (Test-Path "$updaterPath\LabtechUpdate.exe" -ErrorAction SilentlyContinue) {
                                    $GoodServer = $Svr;
                                    Write-Verbose "LabtechUpdate.exe downloaded successfully from server $($Svr).";
                                } else {
                                    Write-Warning "WARNING: Error encountered downloading from $($Svr). No update file was received.";
                                    continue;
                                }
                            }

                        } catch {
                            Write-Warning "WARNING: Error encountered downloading $updater.";
                            continue;
                        }

                    } catch {
                        Write-Warning "WARNING: Error encountered downloading from $($Svr).";
                        continue;
                    }

                } else {
                    Write-Warning "WARNING: Server address $($Svr) is not formatted correctly. Example: https://lt.domain.com";
                }

            } else {
                Write-Debug "Server $($GoodServer) has been selected.";
                Write-Verbose "Server has already been selected - Skipping $($Svr).";
            }
        }
    }

    End {

        $detectedVersion = $Settings | Select-Object -Expand 'Version' -ErrorAction SilentlyContinue;

        if ($null -eq $detectedVersion) {
            Write-Error "ERROR: No existing installation was found." -ErrorAction Stop;
        }

        if ([System.Version]$detectedVersion -ge [System.Version]$Version) {
            Write-Warning "WARNING: Installed version detected ($detectedVersion) is higher than or equal to the requested version ($Version).";
            return;
        }

        if (-not ($GoodServer)) {
            Write-Warning "WARNING: No valid server was detected.";
            return;
        }

        if ([System.Version]$SVer -gt [System.Version]$Version) {
            Write-Warning "WARNING: Server version detected ($SVer) is higher than the requested version ($Version).";
            return;
        }

        try {
            Stop-LTService;
        } catch {
            Write-Error "ERROR: There was an error stopping the services. $($Error[0])" -ErrorAction Stop;
        }

        Write-Output "Updating Agent with the following information: Server $($GoodServer), Version $Version";

        try {

            if ($PSCmdlet.ShouldProcess("LabtechUpdate.exe $($xarg)", "Extracting update files")) {

                if (Test-Path "$updaterPath\LabtechUpdate.exe" -ErrorAction SilentlyContinue) {

                    Write-Verbose "Launching LabtechUpdate Self-Extractor.";
                    Write-Debug "Executing Command ""LabtechUpdate.exe $($xarg)""";

                    try {

                        Push-Location $updaterPath;
                        & "$updaterPath\LabtechUpdate.exe" $($xarg) 2>'';
                        Pop-Location;

                    } catch {
                        Write-Output "Error calling LabtechUpdate.exe.";
                    }

                    Start-Sleep -Seconds 5;

                } else {
                    Write-Verbose "WARNING: $updaterPath\LabtechUpdate.exe was not found.";
                }
            }

            if ($PSCmdlet.ShouldProcess("Update.exe $($uarg)", "Launching Updater")) {

                if (Test-Path "$updaterPath\Update.exe" -ErrorAction SilentlyContinue) {

                    #Extract Update Files
                    Write-Verbose "Launching Labtech Updater";
                    Write-Debug "Executing Command ""Update.exe $($uarg)""";

                    try {

                        & "$updaterPath\Update.exe" $($uarg) 2>'';

                    } catch {
                        Write-Output "Error calling Update.exe."
                    }

                    Start-Sleep -Seconds 5;

                } else {
                    Write-Verbose "WARNING: $updaterPath\Update.exe was not found.";
                }
            }

        } catch {
            Write-Error "ERROR: There was an error during the update process $($Error[0])" -ErrorAction Continue;
        }

        try {
            Start-LTService;
        } catch {
            Write-Error "ERROR: There was an error starting the services. $($Error[0])" -ErrorAction Stop;
        }

        if ($WhatIfPreference -ne $true) {

            if (-not($?)) {
                $Error[0];
            }
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function Get-LTErrors {
    <#
    .SYNOPSIS
        This will pull the %ltsvcdir%\LTErrors.txt file into an object.

    .EXAMPLE
        Get-LTErrors | where {(Get-date $_.Time) -gt (get-date).AddHours(-24)}
        Get a list of all errors in the last 24hr

    .EXAMPLE
        Get-LTErrors | Out-Gridview
        Open the log file in a sortable searchable window.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding()]
    Param()

    Begin {

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        $BasePath = $(Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false | Select-Object -Expand BasePath -ErrorAction SilentlyContinue);

        if ($null -eq $BasePath) {
            $BasePath = "${env:windir}\LTSVC";
        }

        $ObjectArray = [System.Collections.Generic.List[object]]::new();
    }

    Process {

        if (-not(Test-Path -Path "$BasePath\LTErrors.txt" -ErrorAction SilentlyContinue)) {
            Write-Error "ERROR: Unable to find lelog." -ErrorAction Stop;
        }

        try {

            $errors = Get-Content "$BasePath\LTErrors.txt";
            $errors = $errors -join ' ' -split '::: ';

            foreach ($Line in $Errors) {

                $items = $Line -split "`t" -replace ' - ', '';

                if ($items[1]) {

                    $object = New-Object -TypeName PSObject
                    $object | Add-Member -MemberType NoteProperty -Name ServiceVersion -Value $items[0]
                    $object | Add-Member -MemberType NoteProperty -Name Timestamp -Value $(try { [datetime]::Parse($items[1]) } catch {})
                    $object | Add-Member -MemberType NoteProperty -Name Message -Value $items[2]

                    $ObjectArray.Add($object);
                }
            }

        } catch {
            Write-Error "ERROR: There was an error reading the log. $($Error[0])";
        }
    }

    End {

        if ($?) {

            if ($ObjectArray.Count -gt 0) {
                return $ObjectArray;
            }

        } else {
            Write-Output $($Error[0]);
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}
Set-Alias -Name Get-LTError -Value Get-LTErrors

function Reset-LTService {
    <#
    .SYNOPSIS
        This function will remove local settings on the agent.

    .DESCRIPTION
        This function can remove some of the agents local settings.
            ID, MAC, LocationID
        The function will stop the services, make the change, then start the services.
        Resetting all of these will force the agent to check in as a new agent.
        If you have MAC filtering enabled it should check back in with the same ID.
        This function is useful for duplicate agents.

    .PARAMETER ID
        This will reset the AgentID of the computer

    .PARAMETER Location
        This will reset the LocationID of the computer

    .PARAMETER MAC
        This will reset the MAC of the computer

    .PARAMETER Force
        This will force operation on an agent detected as a probe.

    .PARAMETER NoWait
        This will skip the ending health check for the reset process.
        The function will exit once the values specified have been reset.

    .EXAMPLE
        Reset-LTService
        This resets the ID, MAC and LocationID on the agent.

    .EXAMPLE
        Reset-LTService -ID
        This resets only the ID of the agent.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [switch]$ID,
        [switch]$Location,
        [switch]$MAC,
        [switch]$Force,
        [switch]$NoWait
    )

    Begin {

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        $Reg = 'HKLM:\Software\LabTech\Service';

        if ((-not($ID.IsPresent)) -and (-not($Location.IsPresent)) -and (-not($Location.IsPresent))) {

            $ID = $true;
            $Location = $true;
            $MAC = $true;

        }

        $LTSI = Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false;

        if (($LTSI) -and ($LTSI | Select-Object -Expand Probe -ErrorAction SilentlyContinue) -eq '1') {

            if ($Force -eq $true) {

                Write-Output "Probe Agent Detected. Reset Forced.";

            } else {

                if ($WhatIfPreference -ne $true) {
                    Write-Error -Exception [System.OperationCanceledException]"ERROR: Probe Agent Detected. Reset Denied." -ErrorAction Stop
                } else {
                    Write-Error -Exception [System.OperationCanceledException]"What If: Probe Agent Detected. Reset Denied." -ErrorAction Stop
                }
            }
        }

        Write-Output "OLD ID: $($LTSI|Select-Object -Expand ID -ErrorAction SilentlyContinue) LocationID: $($LTSI|Select-Object -Expand LocationID -ErrorAction SilentlyContinue) MAC: $($LTSI|Select-Object -Expand MAC -ErrorAction SilentlyContinue)";

        $LTSI = $null;
    }

    Process {

        if (-not(Get-Service 'LTService', 'LTSvcMon' -ErrorAction SilentlyContinue)) {

            if ($WhatIfPreference -ne $true) {
                Write-Error "ERROR: LabTech Services NOT Found $($Error[0])" -ErrorAction Stop;
            } else {
                Write-Error "What If: Stopping: LabTech Services NOT Found" -ErrorAction Stop;
            }
        }

        try {

            if ($ID -or $Location -or $MAC) {

                Stop-LTService;

                if ($ID.IsPresent) {
                    Write-Output ".Removing ID";
                    Remove-ItemProperty -Name ID -Path $Reg -ErrorAction SilentlyContinue;
                }

                if ($Location.IsPresent) {
                    Write-Output ".Removing LocationID";
                    Remove-ItemProperty -Name LocationID -Path $Reg -ErrorAction SilentlyContinue;
                }

                if ($MAC.IsPresent) {
                    Write-Output ".Removing MAC";
                    Remove-ItemProperty -Name MAC -Path $Reg -ErrorAction SilentlyContinue
                }

                Start-LTService;

            }

        } catch {
            Write-Error "ERROR: There was an error during the reset process. $($Error[0])" -ErrorAction Stop;
        }
    }

    End {

        if ($?) {

            if (-NOT $NoWait -and $PSCmdlet.ShouldProcess("LTService", "Discover new settings after Service Start")) {

                $timeout = New-TimeSpan -Minutes 1;
                $sw = [diagnostics.stopwatch]::StartNew();

                $LTSI = Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false;

                Write-Host -NoNewline "Waiting for agent to register.";

                While (-not($LTSI | Select-Object -Expand ID -ErrorAction SilentlyContinue) -or -not($LTSI | Select-Object -Expand LocationID -ErrorAction SilentlyContinue) -or -not($LTSI | Select-Object -Expand MAC -ErrorAction SilentlyContinue) -and $($sw.elapsed) -lt $timeout) {

                    Write-Host -NoNewline '.';
                    Start-Sleep 2;
                    $LTSI = Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false;

                }

                Write-Host "";

                $LTSI = Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false;

                Write-Output "NEW ID: $($LTSI|Select-Object -Expand ID -ErrorAction SilentlyContinue) LocationID: $($LTSI|Select-Object -Expand LocationID -ErrorAction SilentlyContinue) MAC: $($LTSI|Select-Object -Expand MAC -ErrorAction SilentlyContinue)";

            }

        } else {
            $Error[0];
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function Hide-LTAddRemove {
    <#
    .SYNOPSIS
        This function hides the LabTech install from the Add/Remove Programs list.

    .DESCRIPTION
        This function will rename the DisplayName registry key to hide it from the Add/Remove Programs list.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param()

    Begin {

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        $RegRoots = ('HKLM:\SOFTWARE\Classes\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F',
            'HKLM:\SOFTWARE\Classes\Installer\Products\D1003A85576B76D45A1AF09A0FC87FAC');

        $PublisherRegRoots = ('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{58A3001D-B675-4D67-A5A1-0FA9F08CF7CA}',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{58A3001D-B675-4D67-A5A1-0FA9F08CF7CA}',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{3F460D4C-D217-46B4-80B6-B5ED50BD7CF5}',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{3F460D4C-D217-46B4-80B6-B5ED50BD7CF5}');

        $RegEntriesFound = 0;
        $RegEntriesChanged = 0;

    }

    Process {

        try {

            foreach ($RegRoot in $RegRoots) {

                if (Test-Path $RegRoot -ErrorAction SilentlyContinue) {

                    if (Get-ItemProperty $RegRoot -Name HiddenProductName -ErrorAction SilentlyContinue) {

                        if (-not(Get-ItemProperty $RegRoot -Name ProductName -ErrorAction SilentlyContinue)) {

                            Write-Verbose "LabTech found with HiddenProductName value.";

                            try {
                                Rename-ItemProperty $RegRoot -Name HiddenProductName -NewName ProductName;
                            } catch {
                                Write-Error "ERROR: There was an error renaming the registry value. $($Error[0])" -ErrorAction Stop;
                            }

                        } else {

                            Write-Verbose "LabTech found with unused HiddenProductName value.";

                            try {
                                Remove-ItemProperty $RegRoot -Name HiddenProductName -ErrorAction SilentlyContinue -Confirm:$false -WhatIf:$false -Force;
                            } catch {}

                        }
                    }
                }
            }

            foreach ($RegRoot in $PublisherRegRoots) {

                if (Test-Path $RegRoot -ErrorAction SilentlyContinue) {

                    $RegKey = Get-Item $RegRoot -ErrorAction SilentlyContinue;

                    if (-not($null -eq $RegKey)) {

                        $RegEntriesFound++;

                        if ($PSCmdlet.ShouldProcess("$($RegRoot)", "Set Registry Values to Hide $($RegKey.GetValue('DisplayName'))")) {

                            $RegEntriesChanged++;

                            @('SystemComponent') | ForEach-Object {

                                if (($RegKey.GetValue("$($_)")) -ne 1) {

                                    Write-Verbose "Setting $($RegRoot)\$($_)=1";
                                    Set-ItemProperty $RegRoot -Name "$($_)" -Value 1 -Type DWord -WhatIf:$false -Confirm:$false -Verbose:$false;

                                }

                            }-Object
                        }
                    }
                }
            }

        } catch {
            Write-Error "ERROR: There was an error setting the registry values. $($Error[0])" -ErrorAction Stop;
        }
    }

    End {

        if ($WhatIfPreference -ne $true) {

            if ($?) {

                if ($RegEntriesFound -gt 0 -and $RegEntriesChanged -eq $RegEntriesFound) {
                    Write-Output "LabTech is hidden from Add/Remove Programs.";
                } else {
                    Write-Warning "WARNING: LabTech may not be hidden from Add/Remove Programs.";
                }

            } else {
                $Error[0];
            }
        }
        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function Show-LTAddRemove {
    <#
    .SYNOPSIS
        This function shows the LabTech install in the add/remove programs list.

    .DESCRIPTION
        This function will rename the HiddenDisplayName registry key to show it in the add/remove programs list.
        ifthere is not HiddenDisplayName key the function will import a new entry.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param()

    Begin {

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        $RegRoots = ('HKLM:\SOFTWARE\Classes\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F',
            'HKLM:\SOFTWARE\Classes\Installer\Products\D1003A85576B76D45A1AF09A0FC87FAC');

        $PublisherRegRoots = ('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{58A3001D-B675-4D67-A5A1-0FA9F08CF7CA}',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{58A3001D-B675-4D67-A5A1-0FA9F08CF7CA}',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{3F460D4C-D217-46B4-80B6-B5ED50BD7CF5}',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{3F460D4C-D217-46B4-80B6-B5ED50BD7CF5}');

        $RegEntriesFound = 0;
        $RegEntriesChanged = 0;

    }

    Process {

        try {

            foreach ($RegRoot in $RegRoots) {

                if (Test-Path $RegRoot -ErrorAction SilentlyContinue) {

                    if (Get-ItemProperty $RegRoot -Name HiddenProductName -ErrorAction SilentlyContinue) {

                        if (-not(Get-ItemProperty $RegRoot -Name ProductName -ErrorAction SilentlyContinue)) {

                            Write-Verbose "LabTech found with HiddenProductName value.";

                            try {
                                Rename-ItemProperty $RegRoot -Name HiddenProductName -NewName ProductName;
                            } catch {
                                Write-Error "ERROR: There was an error renaming the registry value. $($Error[0])" -ErrorAction Stop;
                            }

                        } else {

                            Write-Verbose "LabTech found with unused HiddenProductName value.";

                            try {
                                Remove-ItemProperty $RegRoot -Name HiddenProductName -ErrorAction SilentlyContinue -Confirm:$false -WhatIf:$false -Force;
                            } catch {}

                        }
                    }
                }
            }

            foreach ($RegRoot in $PublisherRegRoots) {

                if (Test-Path $RegRoot -ErrorAction SilentlyContinue) {

                    $RegKey = Get-Item $RegRoot -ErrorAction SilentlyContinue;

                    if ($RegKey) {

                        $RegEntriesFound++;

                        if ($PSCmdlet.ShouldProcess("$($RegRoot)", "Set Registry Values to Show $($RegKey.GetValue('DisplayName'))")) {

                            $RegEntriesChanged++;

                            @('SystemComponent') | ForEach-Object {

                                if (($RegKey.GetValue("$($_)")) -eq 1) {

                                    Write-Verbose "Setting $($RegRoot)\$($_)=0";
                                    Set-ItemProperty $RegRoot -Name "$($_)" -Value 0 -Type DWord -WhatIf:$false -Confirm:$false -Verbose:$false;

                                }

                            }-Object
                        }
                    }
                }
            }

        } catch {
            Write-Error "ERROR: There was an error setting the registry values. $($Error[0])" -ErrorAction Stop;
        }
    }

    End {

        if ($WhatIfPreference -ne $true) {

            if ($?) {

                if ($RegEntriesFound -gt 0 -and $RegEntriesChanged -eq $RegEntriesFound) {
                    Write-Output "LabTech is visible from Add/Remove Programs.";
                } else {
                    Write-Warning "WARNING: LabTech may not be visible from Add/Remove Programs.";
                }

            } else {
                $Error[0];
            }
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function Test-LTPorts {
    <#
    .SYNOPSIS
    This function will attempt to connect to all required TCP ports.

    .DESCRIPTION
    The function will confirm the LTTray port is available locally.
    It will then test required TCP ports to the Server.

    .PARAMETER Server
    This is the URL to your LabTech server.
    Example: https://lt.domain.com
    ifno server is provided the function will use Get-LTServiceInfo to
    get the server address. ifit is unable to find LT currently installed
    it will try calling Get-LTServiceInfoBackup.

    .PARAMETER TrayPort
    This is the port LTSvc.exe listens on for communication with LTTray.
    It will be checked to verify it is available. ifnot provided the
    default port will be used (42000).

    .PARAMETER Quiet
    This will return a boolean for connectivity status to the Server

    .NOTES
    Update Date:    2024.08.05
    Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string[]]$Server,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [int]$TrayPort,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]$Quiet
    )

    Begin {

        function Private:TestPort {

            Param(
                [parameter(Position = 0)]
                [string]
                $ComputerName,

                [parameter(Mandatory = $false)]
                [System.Net.IPAddress]
                $IPAddress,

                [parameter(Mandatory = $true , Position = 1)]
                [int]
                $Port
            )

            $RemoteServer = if ([string]::IsNullOrEmpty($ComputerName)) { $IPAddress } else { $ComputerName };

            if ([string]::IsNullOrEmpty($RemoteServer)) {

                Write-Error "ERROR: No ComputerName or IPAddress was provided to test." -ErrorAction Stop;
            }

            $test = New-Object System.Net.Sockets.TcpClient;

            try {

                Write-Output "Connecting to $($RemoteServer):$Port (TCP)..";
                $test.Connect($RemoteServer, $Port);
                Write-Output "Connection successful";

            } catch {

                Write-Output "ERROR: Connection failed";
                $Global:PortTestError = 1;

            } finally {
                $test.Close();
            }

        }

        Clear-Variable CleanSvr, svr, proc, processes, port, netstat, line -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false; #Clearing Variables for use
        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        $processes = [System.Collections.Generic.List[string]]::new();

    }

    Process {

        if ((-not ($Server) -and (-not ($TrayPort))) -or (-not ($Quiet))) {

            Write-Verbose 'No Server Input - Checking for names.';
            $Server = Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false | Select-Object -Expand 'Server' -ErrorAction SilentlyContinue;

            if (-not ($Server)) {
                Write-Verbose 'No Server found in installed Service Info. Checking for Service Backup.';
                $Server = Get-LTServiceInfoBackup -ErrorAction SilentlyContinue -Verbose:$false | Select-Object -Expand 'Server' -ErrorAction SilentlyContinue;
            }
        }

        if (-not ($Quiet) -or (($TrayPort) -ge 1 -and ($TrayPort) -le 65530)) {

            if (-not ($TrayPort) -or -not (($TrayPort) -ge 1 -and ($TrayPort) -le 65530)) {

                #Learn LTTrayPort if available.
                $TrayPort = (Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false | Select-Object -Expand TrayPort -ErrorAction SilentlyContinue);
            }

            if (-not ($TrayPort) -or $TrayPort -notmatch '^\d+$') { $TrayPort = 42000 }

            #Get all processes that are using LTTrayPort (Default 42000)
            try {
                $netstat = & "${env:windir}\system32\netstat.exe" -a -o -n 2>'' | Select-String -Pattern " .*[0-9\.]+:$($Port).*[0-9\.]+:[0-9]+ .*?([0-9]+)" -ErrorAction SilentlyContinue;
            } catch {
                Write-Output "Error calling netstat.exe:  $($Error[0])";
                $netstat = $null;
            }

            foreach ($line in $netstat) {
                $processes.Add(($line -split ' {4,}')[-1]);
            }

            $processes = $processes | Where-Object { $_ -gt 0 -and $_ -match '^\d+$' } | Sort-Object | Get-Unique;

            if (-not($null = $processes)) {

                if (-not ($Quiet)) {

                    foreach ($proc In $processes) {

                        if ((Get-Process -Id $proc -ErrorAction SilentlyContinue | Select-Object -Expand ProcessName -ErrorAction SilentlyContinue) -eq 'LTSvc') {
                            Write-Output "TrayPort Port $TrayPort is being used by LTSvc.";
                        } else {
                            Write-Output "Error: TrayPort Port $TrayPort is being used by $(Get-Process -Id $proc|Select-Object -Expand ProcessName -ErrorAction SilentlyContinue).";
                        }
                    }

                } else {
                    return $false;
                }

            } elseif ($Quiet) {

                return $true;

            } else {
                Write-Output "TrayPort Port $TrayPort is available.";
            }
        }

        foreach ($svr in $Server) {

            if ($Quiet) {
                Test-Connection $Svr -Quiet
                return
            }

            if ($Svr -match '^(https?://)?(([12]?[0-9]{1,2}\.){3}[12]?[0-9]{1,2}|[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)*)$') {

                try {

                    $CleanSvr = ($Svr -replace 'https?://', '' | ForEach-Object { $_.Trim() });

                    Write-Output "Testing connectivity to required TCP ports:";

                    TestPort -ComputerName $CleanSvr -Port 70;
                    TestPort -ComputerName $CleanSvr -Port 80;
                    TestPort -ComputerName $CleanSvr -Port 443;

                    TestPort -ComputerName mediator.labtechsoftware.com -Port 8002;

                } catch {
                    Write-Error "ERROR: There was an error testing the ports. $($Error[0])" -ErrorAction Stop;
                }

            } else {
                Write-Warning "WARNING: Server address $($Svr) is not a valid address or is not formatted correctly. Example: https://lt.domain.com";
            }
        }
    }

    End {

        if ($?) {

            if (-not ($Quiet)) {
                Write-Output "Test-LTPorts Finished";
            }

        } else {
            Write-Output $Error[0]
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function Get-LTLogging {
    <#
    .SYNOPSIS
    This function will return the logging level of the LabTech service.

    .NOTES
    Update Date:    2024.08.05
    Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding()]
    Param ()

    Begin {
        Write-Verbose "Checking for registry keys.";
    }

    Process {

        try {
            $Value = (Get-LTServiceSettings | Select-Object -Expand Debuging -ErrorAction SilentlyContinue);
        } catch {
            Write-Error "ERROR: There was a problem reading the registry key. $($Error[0])" -ErrorAction Stop;
        }
    }

    End {

        if ($?) {

            if ($value -eq 1) {

                Write-Output "Current logging level: Normal";

            } elseif ($value -eq 1000) {

                Write-Output "Current logging level: Verbose";

            } else {
                Write-Error "ERROR: Unknown Logging level $($value)";
            }
        }
    }
}

function Set-LTLogging {
    <#
    .SYNOPSIS
        This function will set the logging level of the LabTech service.

    .NOTES
    Update Date:    2024.08.05
    Purpose/Change: Error handling, code readability, performance.
    #>

    Param (
        [switch]$Verbose
    )

    Begin {

        if (-not($Verbose.IsPresent)) {
            Write-Debug "Verbose switch not set. Setting logging value to Normal.";
        }
    }

    Process {

        try {

            Stop-LTService;

            if ($Verbose.IsPresent) {
                Set-ItemProperty HKLM:\SOFTWARE\LabTech\Service\Settings -Name 'Debuging' -Value 1000;
            } else {
                Set-ItemProperty HKLM:\SOFTWARE\LabTech\Service\Settings -Name 'Debuging' -Value 1;
            }

            Start-LTService;

        } catch {
            Write-Error "ERROR: There was a problem writing the registry key. $($Error[0])" -ErrorAction Stop
        }
    }

    End {

        if ($?) {
            Get-LTLogging;
        }
    }
}

function Get-LTProbeErrors {
    <#
    .SYNOPSIS
        This will pull the %ltsvcdir%\LTProbeErrors.txt file into an object.

    .EXAMPLE
        Get-LTProbeErrors | where {(Get-date $_.Time) -gt (get-date).AddHours(-24)}
        Get a list of all errors in the last 24hr

    .EXAMPLE
        Get-LTProbeErrors | Out-Gridview
        Open the log file in a sortable searchable window.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding()]
    Param()

    Begin {

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        $BasePath = $(Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false | Select-Object -Expand BasePath -ErrorAction SilentlyContinue);

        if (-not($BasePath)) {
            $BasePath = "${env:windir}\LTSVC"
        }

        $ObjectArray = [System.Collections.Generic.List[object]]::new();
    }

    Process {

        if (-not(Test-Path -Path "$BasePath\LTProbeErrors.txt" -ErrorAction SilentlyContinue)) {

            Write-Error "ERROR: Unable to find log." -ErrorAction Stop;
        }

        $errors = Get-Content "$BasePath\LTProbeErrors.txt";
        $errors = $errors -join ' ' -split '::: ';

        try {

            foreach ($Line in $Errors) {

                $items = $Line -split "`t" -replace ' - ', '';

                $object = New-Object -TypeName PSObject;
                $object | Add-Member -MemberType NoteProperty -Name ServiceVersion -Value $items[0];
                $object | Add-Member -MemberType NoteProperty -Name Timestamp -Value $(try { [datetime]::Parse($items[1]) } catch {});
                $object | Add-Member -MemberType NoteProperty -Name Message -Value $items[2];

                $ObjectArray.Add($object);
            }

        } catch {
            Write-Error "ERROR: There was an error reading the log. $($Error[0])";
        }
    }

    End {

        if ($?) {

            if ($ObjectArray.Count -gt 0) {
                return $ObjectArray;
            }

        } else {
            Write-Output $($Error[0]);
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function New-LTServiceBackup {
    <#
    .SYNOPSIS
        This function will backup all the reg keys to 'HKLM\SOFTWARE\LabTechBackup'
        This will also backup those files to "$((Get-LTServiceInfo).BasePath)Backup"

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding()]
    Param ()

    Begin {

        Clear-Variable LTPath, BackupPath, Keys, Path, Result, Reg, RegPath -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false; #Clearing Variables for use
        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        $LTPath = "$(Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false | Select-Object -Expand BasePath -ErrorAction SilentlyContinue)";

        if ($null -eq $LTPath) {
            Write-Error "ERROR: Unable to find LTSvc folder path." -ErrorAction Stop;
        }

        $BackupPath = "$($LTPath)Backup";
        $Keys = "HKLM\SOFTWARE\LabTech";
        $RegPath = "$BackupPath\LTBackup.reg";

        Write-Verbose "Checking for registry keys.";

        if (-not(Test-Path ($Keys -replace '^(H[^\\]*)', '$1:') -ErrorAction SilentlyContinue)) {
            Write-Error "ERROR: Unable to find registry information on LTSvc. Make sure the agent is installed." -ErrorAction Stop;
        }

        if (-not(Test-Path -Path $LTPath -PathType Container -ErrorAction SilentlyContinue)) {
            Write-Error "ERROR: Unable to find LTSvc folder path $LTPath" -ErrorAction Stop;
        }

        $null = New-Item $BackupPath -type directory -ErrorAction SilentlyContinue;

        if (-not(Test-Path -Path $BackupPath -PathType Container -ErrorAction SilentlyContinue)) {
            Write-Error "ERROR: Unable to create backup folder path $BackupPath" -ErrorAction Stop;
        }
    }

    Process {

        try {
            Copy-Item $LTPath $BackupPath -Recurse -Force;
        } catch {
            Write-Error "ERROR: There was a problem backing up the LTSvc Folder. $($Error[0])";
        }

        try {

            Write-Debug "Exporting Registry Data";

            $null = & "${env:windir}\system32\reg.exe" export "$Keys" "$RegPath" /y 2>'';

            Write-Debug "Loading and modifying registry key name";

            $Reg = Get-Content $RegPath;
            $Reg = $Reg -replace [Regex]::Escape('[HKEY_LOCAL_MACHINE\SOFTWARE\LabTech'), '[HKEY_LOCAL_MACHINE\SOFTWARE\LabTechBackup';

            Write-Debug "Writing output information";

            $Reg | Out-File $RegPath;

            Write-Debug "Importing Registry data to Backup Path";

            $null = & "${env:windir}\system32\reg.exe" import "$RegPath" 2>'';
            $true | Out-Null #Protection to prevent exit status error

        } catch {
            Write-Error "ERROR: There was a problem backing up the LTSvc Registry keys. $($Error[0])";
        }
    }

    End {

        if ($?) {
            Write-Output "The LabTech Backup has been created.";
        } else {
            Write-Error "ERROR: There was a problem completing the LTSvc Backup. $($Error[0])";
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function Get-LTServiceInfoBackup {
    <#
    .SYNOPSIS
        This function will pull all of the backed up registry data into an object.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding()]
    Param ()

    Begin {

        Write-Verbose "Checking for registry keys.";
        $exclude = "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSPath";

    }

    Process {

        if (-not(Test-Path 'HKLM:\SOFTWARE\LabTechBackup\Service' -ErrorAction SilentlyContinue)) {
            Write-Error "ERROR: Unable to find backup information on LTSvc. Use New-LTServiceBackup to create a settings backup." -ErrorAction Stop;
        }

        try {

            $key = Get-ItemProperty HKLM:\SOFTWARE\LabTechBackup\Service -ErrorAction Stop | Select-Object * -exclude $exclude;

            if ($null -ne $key -and ($key | Get-Member | Where-Object { $_.Name -match 'BasePath' })) {
                $key.BasePath = [System.Environment]::ExpandEnvironmentVariables($key.BasePath) -replace '\\\\', '\';
            }

            if ($null -ne $key -and ($key | Get-Member | Where-Object { $_.Name -match 'Server Address' })) {

                $Servers = ($Key | Select-Object -Expand 'Server Address' -ErrorAction SilentlyContinue).Split('|') | ForEach-Object { $_.Trim() };
                Add-Member -InputObject $key -MemberType NoteProperty -Name 'Server' -Value $Servers -Force;

            }

        } catch {
            Write-Error "ERROR: There was a problem reading the backup registry keys. $($Error[0])" -ErrorAction Stop;
        }
    }

    End {

        if ($?) {
            return $key
        }
    }
}

function Rename-LTAddRemove {
    <#
    .SYNOPSIS
        This function renames the LabTech install as shown in the Add/Remove Programs list.

    .DESCRIPTION
        This function will change the value of the DisplayName registry key to effect Add/Remove Programs list.

    .PARAMETER Name
        This is the Name for the LabTech Agent as displayed in the list of installed software.

    .PARAMETER PublisherName
        This is the Name for the Publisher of the LabTech Agent as displayed in the list of installed software.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true)]
        $Name,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$PublisherName
    )

    Begin {

        $RegRoots = ('HKLM:\SOFTWARE\Classes\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F',
            'HKLM:\SOFTWARE\Classes\Installer\Products\D1003A85576B76D45A1AF09A0FC87FAC');

        $PublisherRegRoots = ('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{58A3001D-B675-4D67-A5A1-0FA9F08CF7CA}',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{58A3001D-B675-4D67-A5A1-0FA9F08CF7CA}',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{3F460D4C-D217-46B4-80B6-B5ED50BD7CF5}',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{3F460D4C-D217-46B4-80B6-B5ED50BD7CF5}');

        $RegNameFound = 0;
        $RegPublisherFound = 0;
    }

    Process {

        try {

            foreach ($RegRoot in $RegRoots) {

                if (Get-ItemProperty $RegRoot -Name ProductName -ErrorAction SilentlyContinue) {

                    if ($PSCmdlet.ShouldProcess("$($RegRoot)\ProductName=$($Name)", "Set Registry Value")) {

                        Write-Verbose "Setting $($RegRoot)\ProductName=$($Name)";
                        Set-ItemProperty $RegRoot -Name ProductName -Value $Name -Confirm:$false;
                        $RegNameFound++;

                    }

                } elseif (Get-ItemProperty $RegRoot -Name HiddenProductName -ErrorAction SilentlyContinue) {

                    if ($PSCmdlet.ShouldProcess("$($RegRoot)\HiddenProductName=$($Name)", "Set Registry Value")) {

                        Write-Verbose "Setting $($RegRoot)\HiddenProductName=$($Name)";
                        Set-ItemProperty $RegRoot -Name HiddenProductName -Value $Name -Confirm:$false;
                        $RegNameFound++;

                    }
                }
            }

        } catch {
            Write-Error "ERROR: There was an error setting the registry key value. $($Error[0])" -ErrorAction Stop
        }

        if (($PublisherName)) {

            try {

                foreach ($RegRoot in $PublisherRegRoots) {

                    if (Get-ItemProperty $RegRoot -Name Publisher -ErrorAction SilentlyContinue) {

                        if ($PSCmdlet.ShouldProcess("$($RegRoot)\Publisher=$($PublisherName)", "Set Registry Value")) {

                            Write-Verbose "Setting $($RegRoot)\Publisher=$($PublisherName)";
                            Set-ItemProperty $RegRoot -Name Publisher -Value $PublisherName -Confirm:$false;
                            $RegPublisherFound++;

                        }
                    }
                }

            } catch {
                Write-Error "ERROR: There was an error setting the registry key value. $($Error[0])" -ErrorAction Stop;
            }
        }
    }

    End {

        if ($WhatIfPreference -ne $true) {

            if ($?) {

                if ($RegNameFound -gt 0) {
                    Write-Output "LabTech is now listed as $($Name) in Add/Remove Programs.";
                } else {
                    Write-Warning "WARNING: LabTech was not found in installed software and the Name was not changed.";
                }

                if (($PublisherName)) {

                    if ($RegPublisherFound -gt 0) {
                        Write-Output "The Publisher is now listed as $($PublisherName).";
                    } else {
                        Write-Warning "WARNING: LabTech was not found in installed software and the Publisher was not changed.";
                    }
                }

            } else {
                $Error[0];
            }
        }
    }
}

function Invoke-LTServiceCommand {
    <#
    .SYNOPSIS
        This function tells the agent to execute the desired command.

    .DESCRIPTION
        This function will allow you to execute all known commands against an agent.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [ValidateSet("Update Schedule",
            "Send Inventory",
            "Send Drives",
            "Send Processes",
            "Send Spyware List",
            "Send Apps",
            "Send Events",
            "Send Printers",
            "Send Status",
            "Send Screen",
            "Send Services",
            "Analyze Network",
            "Write Last Contact Date",
            "Kill VNC",
            "Kill Trays",
            "Send Patch Reboot",
            "Run App Care Update",
            "Start App Care Daytime Patching")][string[]]$Command
    )

    Begin {
        $Service = Get-Service 'LTService';
    }

    Process {

        if ($null -eq $Service) {
            Write-Warning "WARNING: Service 'LTService' was not found. Cannot send service command";
            return;
        }

        if ($Service.Status -ne 'Running') {
            Write-Warning "WARNING: Service 'LTService' is not running. Cannot send service command";
            return;
        }

        foreach ($Cmd in $Command) {

            $CommandID = $null;

            try {

                switch ($Cmd) {

                    'Update Schedule' { $CommandID = 128 }
                    'Send Inventory' { $CommandID = 129 }
                    'Send Drives' { $CommandID = 130 }
                    'Send Processes' { $CommandID = 131 }
                    'Send Spyware List' { $CommandID = 132 }
                    'Send Apps' { $CommandID = 133 }
                    'Send Events' { $CommandID = 134 }
                    'Send Printers' { $CommandID = 135 }
                    'Send Status' { $CommandID = 136 }
                    'Send Screen' { $CommandID = 137 }
                    'Send Services' { $CommandID = 138 }
                    'Analyze Network' { $CommandID = 139 }
                    'Write Last Contact Date' { $CommandID = 140 }
                    'Kill VNC' { $CommandID = 141 }
                    'Kill Trays' { $CommandID = 142 }
                    'Send Patch Reboot' { $CommandID = 143 }
                    'Run App Care Update' { $CommandID = 144 }
                    'Start App Care Daytime Patching' { $CommandID = 145 }
                    default { "Invalid entry" }
                }

                if ($PSCmdlet.ShouldProcess("LTService", "Send Service Command '$($Cmd)' ($($CommandID))")) {

                    if ($null -ne $CommandID) {

                        Write-Debug "Sending service command '$($Cmd)' ($($CommandID)) to 'LTService'";

                        try {

                            $null = & "${env:windir}\system32\sc.exe" control LTService $($CommandID) 2>''
                            Write-Output "Sent Command '$($Cmd)' to 'LTService'";

                        } catch {
                            Write-Output "Error calling sc.exe. Failed to send command.";
                        }
                    }
                }

            } catch {
                Write-Warning ("WARNING: Line $(LINENUM)", $_.Exception);
            }
        }
    }

    End {}

}

function Initialize-LTServiceKeys {
    <#
    .SYNOPSIS
        This function initializes internal variables needed by other functions

    .DESCRIPTION
        This function will set variables for the Agent and Server passwords needed
        for encoding and decoding steps. Nothing is returned.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding()]
    Param(
    )

    Process {

        $LTSI = Get-LTServiceInfo -ErrorAction SilentlyContinue -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false;

        if (($LTSI) -and ($LTSI | Get-Member | Where-Object { $_.Name -eq 'ServerPassword' })) {

            Write-Debug "Decoding Server Password.";
            $Script:LTServiceKeys.ServerPasswordString = $(ConvertFrom-LTSecurity -InputString "$($LTSI.ServerPassword)");

            if ($null -ne $LTSI -and ($LTSI | Get-Member | Where-Object { $_.Name -eq 'Password' })) {

                Write-Debug "Decoding Agent Password.";
                $Script:LTServiceKeys.PasswordString = $(ConvertFrom-LTSecurity -InputString "$($LTSI.Password)" -Key "$($Script:LTServiceKeys.ServerPasswordString)");

            } else {
                $Script:LTServiceKeys.PasswordString = '';
            }

        } else {

            $Script:LTServiceKeys.ServerPasswordString = '';
            $Script:LTServiceKeys.PasswordString = '';
        }
    }

    End {
    }
}

function ConvertFrom-LTSecurity {
    <#
    .SYNOPSIS
        This function decodes an encoded Base64 value

    .DESCRIPTION
        This function decodes the provided string using the specified or default key.

    .PARAMETER InputString
        This is the string to be decoded.

    .PARAMETER Key
        This is the key used for decoding. ifnot provided, default values will be tried.

    .PARAMETER Force
        This forces the function to try alternate key values if decoding fails using provided key.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string[]]$InputString,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        $Key = $null,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [switch]$Force
    )

    Begin {

        $DefaultKey = 'Thank you for using LabTech.';
        $_initializationVector = [byte[]](240, 3, 45, 29, 0, 76, 173, 59);
        $NoKeyPassed = $false;
        $DecodedString = $null;
        $DecodeString = $null;
    }

    Process {

        if ($null -eq $Key) {

            $NoKeyPassed = $true;
            $Key = $DefaultKey;
        }

        if ( $PSCmdlet.ShouldProcess($InputString) ) {

            foreach ($testInput in $InputString) {

                $DecodeString = $null;

                foreach ($testKey in $Key) {

                    if ($null -eq $DecodeString) {

                        if ($null -eq $testKey) {
                            $NoKeyPassed = $true;
                            $testKey = $DefaultKey;
                        }

                        Write-Debug "Attempting Decode for '$($testInput)' with Key '$($testKey)'";

                        try {

                            $numarray = [System.Convert]::FromBase64String($testInput);

                            $ddd = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider;
                            $ddd.key = (New-Object Security.Cryptography.MD5CryptoServiceProvider).ComputeHash([Text.Encoding]::UTF8.GetBytes($testKey));
                            $ddd.IV = $_initializationVector;

                            $dd = $ddd.CreateDecryptor();

                            $DecodeString = [System.Text.Encoding]::UTF8.GetString($dd.TransformFinalBlock($numarray, 0, ($numarray.Length)));
                            $DecodedString += @($DecodeString);

                        } catch { }

                        finally {

                            if ((Get-Variable -Name dd -Scope 0 -ErrorAction SilentlyContinue)) { try { $dd.Dispose() } catch { $dd.Clear() } }
                            if ((Get-Variable -Name ddd -Scope 0 -ErrorAction SilentlyContinue)) { try { $ddd.Dispose() } catch { $ddd.Clear() } }
                        }
                    }
                }

                if ($null -eq $DecodeString) {

                    if ($Force) {

                        if (($NoKeyPassed)) {

                            $DecodeString = ConvertFrom-LTSecurity -InputString "$($testInput)" -Key '' -Force:$false;

                            if (-not ($null -eq $DecodeString)) {
                                $DecodedString += @($DecodeString);
                            }

                        } else {

                            $DecodeString = ConvertFrom-LTSecurity -InputString "$($testInput)";

                            if (-not ($null -eq $DecodeString)) {
                                $DecodedString += @($DecodeString);
                            }
                        }
                    }
                }
            }
        }
    }

    End {

        if ($null -eq $DecodedString) {

            Write-Debug "Failed to Decode string: '$($InputString)'";
            return $null;

        } else {
            return $DecodedString;
        }
    }
}

function ConvertTo-LTSecurity {
    <#
    .SYNOPSIS
        This function encodes a value compatible with LT operations.

    .DESCRIPTION
        This function encodes the provided string using the specified or default key.

    .PARAMETER InputString
        This is the string to be encoded.

    .PARAMETER Key
        This is the key used for encoding. ifnot provided, a default value will be used.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [string[]]$InputString,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        $Key = $null
    )

    Begin {

        $_initializationVector = [byte[]](240, 3, 45, 29, 0, 76, 173, 59);
        $DefaultKey = 'Thank you for using LabTech.';
        $str = @();
    }

    Process {

        if ( $PSCmdlet.ShouldProcess($InputString) ) {

            foreach ($testInput in $InputString) {

                if ($null -eq $Key) {
                    $Key = $DefaultKey
                }

                try {
                    $numarray = [System.Text.Encoding]::UTF8.GetBytes($testInput);
                } catch {

                    try {
                        $numarray = [System.Text.Encoding]::ASCII.GetBytes($testInput);
                    } catch {}
                }

                Write-Debug "Attempting Encode for '$($testInput)' with Key '$($Key)'";

                try {

                    $ddd = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider;
                    $ddd.key = (New-Object Security.Cryptography.MD5CryptoServiceProvider).ComputeHash([Text.Encoding]::UTF8.GetBytes($Key));
                    $ddd.IV = $_initializationVector;

                    $dd = $ddd.CreateEncryptor();
                    $str += [System.Convert]::ToBase64String($dd.TransformFinalBlock($numarray, 0, ($numarray.Length)));

                } catch {

                    Write-Debug "Failed to Encode string: '$($InputString)'";
                    $str += '';

                } finally {
                    if ($dd) { try { $dd.Dispose() } catch { $dd.Clear() } }
                    if ($ddd) { try { $ddd.Dispose() } catch { $ddd.Clear() } }
                }
            }
        }
    }

    End {
        return $str;
    }
}

function Set-LTProxy {
    <#
    .SYNOPSIS
        This function configures module functions to use the specified proxy
        configuration for all operations as long as the module remains loaded.

    .DESCRIPTION
        This function will set or clear Proxy settings needed for function and
        agent operations. ifan agent is already installed, this function will
        set the ProxyUsername, ProxyPassword, and ProxyServerURL values for the
        Agent.
        NOTE: Agent Services will be restarted for changes (if found) to be applied.

    .PARAMETER ProxyServerURL
        This is the URL and Port to assign as the ProxyServerURL for Module
        operations during this session and for the Installed Agent (if present).
        Example: Set-LTProxy -ProxyServerURL 'proxyhostname.fqdn.com'
        Example: Set-LTProxy -ProxyServerURL 'proxyhostname.fqdn.com:8080'
        This parameter may be used with the additional following parameters:
        ProxyUsername, ProxyPassword, EncodedProxyUsername, EncodedProxyPassword

    .PARAMETER ProxyUsername
        This is the plain text Username for Proxy operations.
        Example: Set-LTProxy -ProxyServerURL 'proxyhostname.fqdn.com:8080' -ProxyUsername 'Test-User' -ProxyPassword 'SomeFancyPassword'

    .PARAMETER ProxyPassword
        This is the plain text Password for Proxy operations.

    .PARAMETER EncodedProxyUsername
        This is the encoded Username for Proxy operations. The parameter must be
        encoded with the Agent Password. This Parameter will be decoded using the
        Agent Password, and the decoded string will be configured.
        NOTE: Reinstallation of the Agent will generate a new agent password.
        Example: Set-LTProxy -ProxyServerURL 'proxyhostname.fqdn.com:8080' -EncodedProxyUsername '1GzhlerwMy0ElG9XNgiIkg==' -EncodedProxyPassword 'Duft4r7fekTp5YnQL9F0V9TbP7sKzm0n'

    .PARAMETER EncodedProxyPassword
        This is the encoded Password for Proxy operations. The parameter must be
        encoded with the Agent Password. This Parameter will be decoded using the
        Agent Password, and the decoded string will be configured.
        NOTE: Reinstallation of the Agent will generate a new password.

    .PARAMETER DetectProxy
        This parameter attempts to automatically detect the system Proxy settings
        for Module operations during this session. Discovered settings will be
        assigned to the Installed Agent (if present).
        Example: Set-LTProxy -DetectProxy
        This parameter may not be used with other parameters.

    .PARAMETER ResetProxy
        This parameter clears any currently defined Proxy Settings for Module
        operations during this session. Discovered settings will be assigned
        to the Installed Agent (if present).
        Example: Set-LTProxy -ResetProxy
        This parameter may not be used with other parameters.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string]$ProxyServerURL,

        [parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string]$ProxyUsername,

        [parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [string]$ProxyPassword,

        [parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EncodedProxyUsername,

        [parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EncodedProxyPassword,

        [parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [alias('Detect')]
        [alias('AutoDetect')]
        [switch]$DetectProxy,

        [parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [alias('Clear')]
        [alias('Reset')]
        [alias('ClearProxy')]
        [switch]$ResetProxy
    )

    Begin {

        Clear-Variable LTServiceSettingsChanged, LTSS, LTServiceRestartNeeded, proxyURL, proxyUser, proxyPass, passwd, Svr -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false; #Clearing Variables for use
        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";

        try {
            $LTSS = Get-LTServiceSettings -ErrorAction SilentlyContinue -Verbose:$false -WA 0 -Debug:$false;
        } catch {}

    }

    Process {

        if ((($ResetProxy -eq $true) -and (($DetectProxy -eq $true) -or ($ProxyServerURL) -or ($ProxyUsername) -or ($ProxyPassword) -or ($EncodedProxyUsername) -or ($EncodedProxyPassword))) -or
            (($DetectProxy -eq $true) -and (($ResetProxy -eq $true) -or ($ProxyServerURL) -or ($ProxyUsername) -or ($ProxyPassword) -or ($EncodedProxyUsername) -or ($EncodedProxyPassword))) -or
            ((($ProxyServerURL) -or ($ProxyUsername) -or ($ProxyPassword) -or ($EncodedProxyUsername) -or ($EncodedProxyPassword)) -and (($ResetProxy -eq $true) -or ($DetectProxy -eq $true))) -or
            ((($ProxyUsername) -or ($ProxyPassword)) -and (-not ($ProxyServerURL) -or ($EncodedProxyUsername) -or ($EncodedProxyPassword) -or ($ResetProxy -eq $true) -or ($DetectProxy -eq $true))) -or
            ((($EncodedProxyUsername) -or ($EncodedProxyPassword)) -and (-not ($ProxyServerURL) -or ($ProxyUsername) -or ($ProxyPassword) -or ($ResetProxy -eq $true) -or ($DetectProxy -eq $true)))) {

            Write-Error "ERROR: Set-LTProxy: Invalid Parameter specified" -ErrorAction Stop;
        }

        if (-not (($ResetProxy -eq $true) -or ($DetectProxy -eq $true) -or ($ProxyServerURL) -or ($ProxyUsername) -or ($ProxyPassword) -or ($EncodedProxyUsername) -or ($EncodedProxyPassword))) {

            if ($Args.Count -gt 0) {
                Write-Error "ERROR: Set-LTProxy: Unknown Parameter specified" -ErrorAction Stop;
            } else {
                Write-Error "ERROR: Set-LTProxy: Required Parameters Missing" -ErrorAction Stop;
            }
        }

        try {

            if ($($ResetProxy) -eq $true) {

                Write-Verbose "ResetProxy selected. Clearing Proxy Settings.";

                if ( $PSCmdlet.ShouldProcess("LTProxy", "Clear") ) {

                    $Script:LTProxy.Enabled = $false;
                    $Script:LTProxy.ProxyServerURL = '';
                    $Script:LTProxy.ProxyUsername = '';
                    $Script:LTProxy.ProxyPassword = '';
                    $Script:LTWebProxy = New-Object System.Net.WebProxy;
                    $Script:LTServiceNetWebClient.Proxy = $Script:LTWebProxy;

                }

            } elseif ($($DetectProxy) -eq $true) {

                Write-Verbose "DetectProxy selected. Attempting to Detect Proxy Settings.";

                if ( $PSCmdlet.ShouldProcess("LTProxy", "Detect") ) {

                    $Script:LTWebProxy = [System.Net.WebRequest]::GetSystemWebProxy();
                    $Script:LTProxy.Enabled = $false;
                    $Script:LTProxy.ProxyServerURL = '';

                    $Servers = @($("$($LTSS|Select-Object -Expand 'ServerAddress' -ErrorAction SilentlyContinue)|www.connectwise.com").Split('|') | ForEach-Object { $_.Trim() });

                    foreach ($Svr In $Servers) {

                        if (-not ($Script:LTProxy.Enabled)) {

                            if ($Svr -match '^(https?://)?(([12]?[0-9]{1,2}\.){3}[12]?[0-9]{1,2}|[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)*)$') {

                                $Svr = $Svr -replace 'https?://', '';

                                try {
                                    $Script:LTProxy.ProxyServerURL = $Script:LTWebProxy.GetProxy("http://$($Svr)").Authority;
                                } catch {}

                                if (($null -ne $Script:LTProxy.ProxyServerURL) -and ($Script:LTProxy.ProxyServerURL -ne '') -and ($Script:LTProxy.ProxyServerURL -notcontains "$($Svr)")) {
                                    Write-Debug "Detected Proxy URL: $($Script:LTProxy.ProxyServerURL) on server $($Svr)";
                                    $Script:LTProxy.Enabled = $true
                                }
                            }
                        }
                    }

                    if (-not ($Script:LTProxy.Enabled)) {

                        if (($Script:LTProxy.ProxyServerURL -eq '') -or ($Script:LTProxy.ProxyServerURL -contains '$Svr')) {
                            $Script:LTProxy.ProxyServerURL = netsh winhttp show proxy | Select-String -Pattern '(?i)(?<=Proxyserver.*http\=)([^;\r\n]*)' -ErrorAction SilentlyContinue | ForEach-Object { $_.matches } | Select-Object -Expand value
                        }

                        if (($null -eq $Script:LTProxy.ProxyServerURL) -or ($Script:LTProxy.ProxyServerURL -eq '')) {

                            $Script:LTProxy.ProxyServerURL = '';
                            $Script:LTProxy.Enabled = $false;

                        } else {
                            $Script:LTProxy.Enabled = $true;
                            Write-Debug "Detected Proxy URL: $($Script:LTProxy.ProxyServerURL)";
                        }
                    }

                    $Script:LTProxy.ProxyUsername = '';
                    $Script:LTProxy.ProxyPassword = '';
                    $Script:LTServiceNetWebClient.Proxy = $Script:LTWebProxy;
                }

            } elseif (($ProxyServerURL)) {

                if ( $PSCmdlet.ShouldProcess("LTProxy", "Set") ) {

                    foreach ($ProxyURL in $ProxyServerURL) {

                        $Script:LTWebProxy = New-Object System.Net.WebProxy($ProxyURL, $true);
                        $Script:LTProxy.Enabled = $true
                        $Script:LTProxy.ProxyServerURL = $ProxyURL

                    }

                    Write-Verbose "Setting Proxy URL to: $($ProxyServerURL)";

                    if ((($ProxyUsername) -and ($ProxyPassword)) -or (($EncodedProxyUsername) -and ($EncodedProxyPassword))) {

                        if (($ProxyUsername)) {

                            foreach ($proxyUser in $ProxyUsername) {
                                $Script:LTProxy.ProxyUsername = $proxyUser;
                            }
                        }

                        if (($EncodedProxyUsername)) {

                            foreach ($proxyUser in $EncodedProxyUsername) {
                                $Script:LTProxy.ProxyUsername = $(ConvertFrom-LTSecurity -InputString "$($proxyUser)" -Key ("$($Script:LTServiceKeys.PasswordString)", ''));
                            }
                        }

                        if (($ProxyPassword)) {

                            foreach ($proxyPass in $ProxyPassword) {

                                $Script:LTProxy.ProxyPassword = $proxyPass;
                                $passwd = ConvertTo-SecureString $proxyPass -AsPlainText -Force; ## Website credentials

                            }
                        }

                        if (($EncodedProxyPassword)) {

                            foreach ($proxyPass in $EncodedProxyPassword) {

                                $Script:LTProxy.ProxyPassword = $(ConvertFrom-LTSecurity -InputString "$($proxyPass)" -Key ("$($Script:LTServiceKeys.PasswordString)", ''));
                                $passwd = ConvertTo-SecureString $Script:LTProxy.ProxyPassword -AsPlainText -Force; ## Website credentials

                            }
                        }

                        $Script:LTWebProxy.Credentials = New-Object System.Management.Automation.PSCredential ($Script:LTProxy.ProxyUsername, $passwd);
                    }

                    $Script:LTServiceNetWebClient.Proxy = $Script:LTWebProxy
                }
            }

        } catch {
            Write-Error "ERROR: There was an error during the Proxy Configuration process. $($Error[0])" -ErrorAction Stop;
        }
    }

    End {

        if ($?) {

            $LTServiceSettingsChanged = $false;

            if ($null -ne ($LTSS)) {

                if (($LTSS | Get-Member | Where-Object { $_.Name -eq 'ProxyServerURL' })) {

                    if (($($LTSS | Select-Object -Expand ProxyServerURL -ErrorAction SilentlyContinue) -replace 'https?://', '' -ne $Script:LTProxy.ProxyServerURL) -and (($($LTSS | Select-Object -Expand ProxyServerURL -ErrorAction SilentlyContinue) -replace 'https?://', '' -eq '' -and $Script:LTProxy.Enabled -eq $true -and $Script:LTProxy.ProxyServerURL -match '.+\..+') -or ($($LTSS | Select-Object -Expand ProxyServerURL -ErrorAction SilentlyContinue) -replace 'https?://', '' -ne '' -and ($Script:LTProxy.ProxyServerURL -ne '' -or $Script:LTProxy.Enabled -eq $false)))) {

                        Write-Debug "ProxyServerURL Changed: Old Value: $($LTSS|Select-Object -Expand ProxyServerURL -ErrorAction SilentlyContinue) New Value: $($Script:LTProxy.ProxyServerURL)";
                        $LTServiceSettingsChanged = $true;
                    }

                    if (($LTSS | Get-Member | Where-Object { $_.Name -eq 'ProxyUsername' }) -and ($LTSS | Select-Object -Expand ProxyUsername -ErrorAction SilentlyContinue)) {

                        if ($(ConvertFrom-LTSecurity -InputString "$($LTSS|Select-Object -Expand ProxyUsername -ErrorAction SilentlyContinue)" -Key ("$($Script:LTServiceKeys.PasswordString)", '')) -ne $Script:LTProxy.ProxyUsername) {

                            Write-Debug "ProxyUsername Changed: Old Value: $(ConvertFrom-LTSecurity -InputString "$($LTSS|Select-Object -Expand ProxyUsername -ErrorAction SilentlyContinue)" -Key ("$($Script:LTServiceKeys.PasswordString)",'')) New Value: $($Script:LTProxy.ProxyUsername)";
                            $LTServiceSettingsChanged = $true;
                        }
                    }

                    if ($null -ne ($LTSS) -and ($LTSS | Get-Member | Where-Object { $_.Name -eq 'ProxyPassword' }) -and ($LTSS | Select-Object -Expand ProxyPassword -ErrorAction SilentlyContinue)) {

                        if ($(ConvertFrom-LTSecurity -InputString "$($LTSS|Select-Object -Expand ProxyPassword -ErrorAction SilentlyContinue)" -Key ("$($Script:LTServiceKeys.PasswordString)", '')) -ne $Script:LTProxy.ProxyPassword) {

                            Write-Debug "ProxyPassword Changed: Old Value: $(ConvertFrom-LTSecurity -InputString "$($LTSS|Select-Object -Expand ProxyPassword -ErrorAction SilentlyContinue)" -Key ("$($Script:LTServiceKeys.PasswordString)",'')) New Value: $($Script:LTProxy.ProxyPassword)";
                            $LTServiceSettingsChanged = $true;
                        }
                    }

                } elseif ($Script:LTProxy.Enabled -eq $true -and $Script:LTProxy.ProxyServerURL -match '(https?://)?.+\..+') {

                    Write-Debug "ProxyServerURL Changed: Old Value: NOT SET New Value: $($Script:LTProxy.ProxyServerURL)";
                    $LTServiceSettingsChanged = $true;
                }

            } else {

                $svcRun = ('LTService') | Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | Measure-Object | Select-Object -Expand Count;

                if (($svcRun -gt 0) -and ($($Script:LTProxy.ProxyServerURL) -match '.+')) {
                    $LTServiceSettingsChanged = $true;
                }

            }

            if ($LTServiceSettingsChanged -eq $true) {

                if ((Get-Service 'LTService', 'LTSvcMon' -ErrorAction SilentlyContinue | Where-Object { $_.Status -match 'Running' })) { $LTServiceRestartNeeded = $true; try { Stop-LTService -ErrorAction SilentlyContinue -WA 0 } catch {} }

                Write-Verbose "Updating LabTech\Service\Settings Proxy Configuration.";

                if ( $PSCmdlet.ShouldProcess("LTService Registry", "Update") ) {

                    $Svr = $($Script:LTProxy.ProxyServerURL); if (($Svr -ne '') -and ($Svr -notmatch 'https?://')) { $Svr = "http://$($Svr)" }

                    @{"ProxyServerURL"  = $Svr;
                        "ProxyUserName" = "$(ConvertTo-LTSecurity -InputString "$($Script:LTProxy.ProxyUserName)" -Key "$($Script:LTServiceKeys.PasswordString)")";
                        "ProxyPassword" = "$(ConvertTo-LTSecurity -InputString "$($Script:LTProxy.ProxyPassword)" -Key "$($Script:LTServiceKeys.PasswordString)")"
                    }.GetEnumerator() | ForEach-Object {

                        Write-Debug "Setting Registry value for $($_.Name) to `"$($_.Value)`"";
                        Set-ItemProperty -Path 'HKLM:Software\LabTech\Service\Settings' -Name $($_.Name) -Value $($_.Value) -ErrorAction SilentlyContinue -Confirm:$false;

                    }-Object
                }

                if ($LTServiceRestartNeeded -eq $true) { try { Start-LTService -ErrorAction SilentlyContinue -WA 0 } catch {} }
            }

        } else {
            $Error[0];
        }

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
    }
}

function Get-LTProxy {
    <#
    .SYNOPSIS
        This function retrieves the current agent proxy settings for module functions
        to use the specified proxy configuration for all communication operations as
        long as the module remains loaded.

    .DESCRIPTION
        This function will get the current LabTech Proxy settings from the
        installed agent (if present). ifno agent settings are found, the function
        will attempt to discover the current proxy settings for the system.
        The Proxy Settings determined will be stored in memory for internal use, and
        returned as the function result.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    [CmdletBinding()]
    Param(
    )

    Begin {

        Clear-Variable CustomProxyObject, LTSI, LTSS -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false #Clearing Variables for use

        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)";
        Write-Verbose "Discovering Proxy Settings used by the LT Agent.";

        $null = Initialize-LTServiceKeys;

    }

    Process {

        try {

            $LTSI = Get-LTServiceInfo -ErrorAction SilentlyContinue -WA 0 -Verbose:$false -WhatIf:$false -Confirm:$false -Debug:$false;

            if ($null -ne $LTSI -and ($LTSI | Get-Member | Where-Object { $_.Name -eq 'ServerPassword' })) {

                $LTSS = Get-LTServiceSettings -ErrorAction SilentlyContinue -Verbose:$false -WA 0 -Debug:$false;

                if (-not($null -eq $LTSS)) {

                    if (($LTSS | Get-Member | Where-Object { $_.Name -eq 'ProxyServerURL' }) -and ($($LTSS | Select-Object -Expand ProxyServerURL -ErrorAction SilentlyContinue) -Match 'https?://.+')) {

                        Write-Debug "Proxy Detected. Setting ProxyServerURL to $($LTSS|Select-Object -Expand ProxyServerURL -ErrorAction SilentlyContinue)";
                        $Script:LTProxy.Enabled = $true;
                        $Script:LTProxy.ProxyServerURL = "$($LTSS|Select-Object -Expand ProxyServerURL -ErrorAction SilentlyContinue)";

                    } else {

                        Write-Debug "Setting ProxyServerURL to ";
                        $Script:LTProxy.Enabled = $false;
                        $Script:LTProxy.ProxyServerURL = '';
                    }

                    if ($Script:LTProxy.Enabled -eq $true -and ($LTSS | Get-Member | Where-Object { $_.Name -eq 'ProxyUsername' }) -and ($LTSS | Select-Object -Expand ProxyUsername -ErrorAction SilentlyContinue)) {

                        $Script:LTProxy.ProxyUsername = "$(ConvertFrom-LTSecurity -InputString "$($LTSS|Select-Object -Expand ProxyUsername -ErrorAction SilentlyContinue)" -Key ("$($Script:LTServiceKeys.PasswordString)",''))";
                        Write-Debug "Setting ProxyUsername to $($Script:LTProxy.ProxyUsername)";

                    } else {

                        Write-Debug "Setting ProxyUsername to ";
                        $Script:LTProxy.ProxyUsername = '';
                    }

                    if ($Script:LTProxy.Enabled -eq $true -and ($LTSS | Get-Member | Where-Object { $_.Name -eq 'ProxyPassword' }) -and ($LTSS | Select-Object -Expand ProxyPassword -ErrorAction SilentlyContinue)) {

                        $Script:LTProxy.ProxyPassword = "$(ConvertFrom-LTSecurity -InputString "$($LTSS|Select-Object -Expand ProxyPassword -ErrorAction SilentlyContinue)" -Key ("$($Script:LTServiceKeys.PasswordString)",''))";
                        Write-Debug "Setting ProxyPassword to $($Script:LTProxy.ProxyPassword)";

                    } else {

                        Write-Debug "Setting ProxyPassword to ";
                        $Script:LTProxy.ProxyPassword = ''
                    }
                }

            } else {
                Write-Verbose "No Server password or settings exist. No Proxy information will be available.";
            }

        } catch {
            Write-Error "ERROR: There was a problem retrieving Proxy Information. $($Error[0])";
        }
    }

    End {

        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)";
        return $Script:LTProxy;
    }
}

function Get-CurrentLineNumber {
    $MyInvocation.ScriptLineNumber
}
Set-Alias -Name LINENUM -Value Get-CurrentLineNumber -WhatIf:$false -Confirm:$false -Scope Script;

function Initialize-LTServiceModule {
    <#
    .SYNOPSIS
        This function initializes internal variables needed by other functions

    .DESCRIPTION
        This function will set variables for the Agent and Server passwords needed
        for encoding and decoding steps.

    .NOTES
        Update Date:    2024.08.05
        Purpose/Change: Error handling, code readability, performance.
    #>

    #Populate $Script:LTServiceKeys Object
    $Script:LTServiceKeys = New-Object -TypeName PSObject;
    Add-Member -InputObject $Script:LTServiceKeys -MemberType NoteProperty -Name ServerPasswordString -Value '';
    Add-Member -InputObject $Script:LTServiceKeys -MemberType NoteProperty -Name PasswordString -Value '';

    #Populate $Script:LTProxy Object
    try {

        $Script:LTProxy = New-Object -TypeName PSObject;
        Add-Member -InputObject $Script:LTProxy -MemberType NoteProperty -Name ProxyServerURL -Value '';
        Add-Member -InputObject $Script:LTProxy -MemberType NoteProperty -Name ProxyUsername -Value '';
        Add-Member -InputObject $Script:LTProxy -MemberType NoteProperty -Name ProxyPassword -Value '';
        Add-Member -InputObject $Script:LTProxy -MemberType NoteProperty -Name Enabled -Value '';

        #Populate $Script:LTWebProxy Object
        $Script:LTWebProxy = New-Object System.Net.WebProxy;

        #Initialize $Script:LTServiceNetWebClient Object
        $Script:LTServiceNetWebClient = New-Object System.Net.WebClient;
        $Script:LTServiceNetWebClient.Proxy = $Script:LTWebProxy;

    } catch {
        Write-Error "ERROR: Failed Initializing internal Proxy Objects/Variables.";
    }

    $null = Get-LTProxy -ErrorAction Continue;
}

#endregion functions

$Publicfunctions = @(((@"
ConvertFrom-LTSecurity
ConvertTo-LTSecurity
Get-LTErrors
Get-LTLogging
Get-LTProbeErrors
Get-LTProxy
Get-LTServiceInfo
Get-LTServiceInfoBackup
Get-LTServiceSettings
Hide-LTAddRemove
Install-LTService
Invoke-LTServiceCommand
New-LTServiceBackup
Redo-LTService
Rename-LTAddRemove
Reset-LTService
Restart-LTService
Set-LTLogging
Set-LTProxy
Show-LTAddRemove
Start-LTService
Stop-LTService
Test-LTPorts
Uninstall-LTService
Update-LTService
"@) -replace "[`r`n,\s]+", ',') -split ',')

$PublicAlias = @(((@"
Get-LTError
ReInstall-LTService
"@) -replace "[`r`n,\s]+", ',') -split ',')

if (($MyInvocation.Line -match 'Import-Module' -or $MyInvocation.MyCommand -match 'Import-Module') -and -not ($MyInvocation.Line -match $ModuleGuid -or $MyInvocation.MyCommand -match $ModuleGuid)) {
    # Only export module members when being loaded as a module
    Export-ModuleMember -Function $Publicfunctions -Alias $PublicAlias -ErrorAction SilentlyContinue -WA 0

    <#
#   Just a small code block to use when developing new features to ensure new functions are not missed.
#   Here just so that I don't need to track it down when I want it. - DJW

$UnPublicfunctions=(Get-Content 'Script Source' | Select-String -Pattern '(?<=^function )[-\w]+' -AllMatches | Select-Object -expand matches) | ForEach-Object {if ($Publicfunctions -notcontains $_.value) {$_.value}};
    if ($UnPublicfunctions) {Write-Debug "Not publishing functions: $(($UnPublicfunctions) -join ',')"}
#>

}

$null = Initialize-LTServiceModule

#SneakyRun - Save as FUNCTION.ps1 and call FUNCTION.ps1, and it will be treated as if you called FUNCTION directly.
#Maybe it's not that special. You can dot-source the script and call any function directly.
#Example: Name it "Install-LTService.ps1", then you can call it as the file and it will run that function.

if ($PSCommandPath -like '*.ps1' -and $PSCommandPath -like "*$($MyInvocation.MyCommand)") {

    $LabTechfunction = $MyInvocation.MyCommand.ToString() -replace '\.ps1', '';

    if ($Publicfunctions -contains $LabTechfunction) {

        Write-Debug "Script Name $LabTechfunction.ps1 matches a defined function. Calling $LabTechfunction $($args|ConvertTo-Json -Depth 1 -Compress)";
        & $LabTechfunction @args;

    } else {
        Write-Debug "Script Name $LabTechfunction.ps1 does not match a defined function for this module.";
    }
}