function Get-TimeStamp {
    <#
        .SYNOPSIS
            Get a time stamp

        .DESCRIPTION
            Get a time date and time to create a custom time stamp

        .EXAMPLE
            None

        .NOTES
            Internal function
    #>

    [cmdletbinding()]
    param()
    return "[{0:MM/dd/yy} {0:HH:mm:ss}] -" -f (Get-Date)
}

function Save-Output {
    <#
    .SYNOPSIS
        Save output

    .DESCRIPTION
        Overload function for Write-Output

    .PARAMETER FailureObject
        Inbound failure log objects to be exported to csv

    .PARAMETER InputObject
        Inbound objects to be exported to csv

    .PARAMETER RegistryObject
        Inbound registry objects to be exported to csv

    .PARAMETER SaveFileOutput
        Flag for exporting the file object

    .PARAMETER SaveFailureOutput
        Flag for exporting the failure objects

    .PARAMETER StringObject
        Inbound object to be printed and saved to log

    .EXAMPLE
        None

    .NOTES
        None
    #>

    [cmdletbinding()]
    param(
        [PSCustomObject]
        $FailureObject,

        [Object]
        $InputObject,

        [PSCustomObject]
        $RegistryObject,

        [switch]
        $SaveFileOutput,

        [switch]
        $SaveFailureOutput,

        [Parameter(Mandatory = $True, Position = 0)]
        [string]
        $StringObject
    )

    process {
        try {
            Write-Output $StringObject
            if ($RegistryObject -and $SaveFileOutput.IsPresent) {
                $RegistryObject | Export-Csv -Path (Join-Path -Path $LoggingDirectory -ChildPath $RegistrySaveFileName) -Append -NoTypeInformation -ErrorAction Stop
                return
            }

            if ($FailureObject -and $SaveFailureOutput.IsPresent) {
                $FailureObject | Export-Csv -Path (Join-Path -Path $LoggingDirectory -ChildPath $FailureLogSaveFileName) -Append -NoTypeInformation -ErrorAction Stop
                return
            }

            if ($InputObject -and $SaveFileOutput.IsPresent) {
                $InputObject | Export-Csv -Path (Join-Path -Path $LoggingDirectory -ChildPath $EventLogSaveFileName) -Append -NoTypeInformation -ErrorAction Stop
                return
            }

            # Console and log file output
            Out-File -FilePath (Join-Path -Path $LoggingDirectory -ChildPath $LoggingFileName) -InputObject $StringObject -Encoding utf8 -Append -ErrorAction Stop
        }
        catch {
            Save-Output "$(Get-TimeStamp) ERROR: $_"
            return
        }
    }
}

function Get-AppInstallStatus {
    <#
    .SYNOPSIS
        Check for application installation status

    .DESCRIPTION
        Check a machine to make sure installation of applications complete before sending the Autopilot device to an end user

    .PARAMETER Computers
        The computers you want to connect to

    .PARAMETER DisplayResultsOnConsole
        Shows all results to the console (noisy!)

    .PARAMETER DomainComputers
        Search the entire domain for all computers to be scanned

    .PARAMETER EnableConsoleOutput
        Enable computer connection output to the console (noisy!)

    .PARAMETER EventViewerLogName
        Name of the event log we are scanning

    .PARAMETER EventLogSaveFileName
        Event log save file name

    .PARAMETER RegistrySaveFileName
        Registry event save file name

    .PARAMETER FailureLogSaveFileName
        Failure log save file name

    .PARAMETER LoggingDirectory
        Logging directory can be a local file share or network share with the necessary write permissions

    .PARAMETER LoggingFileName
        Script execution log file

    .PARAMETER SaveDataToDisk
        Switch to indicate you want to save results to a local or network location

    .PARAMETER UseCredentials
        Indicate that we need to pass administrator credentials

    .EXAMPLE
        Get-AppInstallStatus -DisplayErrors -SaveDataToDisk -Computers Computer1, Computer2

        This will connect to Computer1 and Computer2 to search the event logs for events and display any warnings / errors found

    .EXAMPLE
        Get-AppInstallStatus -DomainComputers -SaveDataToDisk

        This will connect to to a domain controller and search for all computers based on filter and save the logs to a local or network share

    .NOTES
        To search a domain this must be executed on a computer that has access to a domain controller or has RSAT installed to run Get-ADComputer
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
    [OutputType([Object[]])]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [object]
        $Computers,

        [switch]
        $DisplayResultsOnConsole,

        [switch]
        $DomainComputers,

        [switch]
        $EnableConsoleOutput,

        [string]
        $EventViewerLogName = "Application",

        [string]
        $EventLogSaveFileName = "AppInstallStatusEventLogs.csv",

        [string]
        $RegistrySaveFileName = "AppInstallStatusRegistryLogs.csv",

        [string]
        $Filter = "*",

        [string]
        $FailureLogSaveFileName = "FailuresLog.txt",

        [string]
        $LoggingDirectory = 'C:\AppInstallStatus',

        [string]
        $LoggingFileName = 'ScriptExecutionLogging.txt',

        [switch]
        $SaveDataToDisk,

        [Parameter(ParameterSetName = 'UseCredentials')]
        [switch]
        $UseCredentials,

        [Parameter(ParameterSetName = 'UseCredentials')]
        [string]
        $UserName = "Computer\User"
    )

    begin {
        $parameters = $PSBoundParameters
        [System.Collections.ArrayList]$failureEntries = @()
        [System.Collections.ArrayList]$completedEntries = @()
        if (-NOT( Test-Path -Path $LoggingDirectory )) {
            try {
                $null = New-Item -Path $LoggingDirectory -Type Directory -ErrorAction Stop
                Save-Output "$(Get-TimeStamp) Directory not found. Creating $($LoggingDirectory)"
            }
            catch {
                Save-Output "$(Get-TimeStamp) ERROR: $_"
                return
            }
        }

        $scriptBlock = {
            param(
                [string]
                $EventViewerLogName
            )
            [System.Collections.ArrayList] $results = @()
            $UninstallKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            foreach ($UninstallKey in $UninstallKeys) {
                $gciParams = @{
                    Path          = $UninstallKey
                    ErrorAction   = 'SilentlyContinue'
                    ErrorVariable = 'Failed'
                }

                Get-ChildItem @gciParams | ForEach-Object {
                    $validate = Get-ItemProperty -Path $_.PSPath

                    if ($validate.DisplayName) {
                        $item = [PSCustomObject]@{
                            DisplayName     = $validate.DisplayName
                            Publisher       = $validate.Publisher
                            DisplayVersion  = $validate.DisplayVersion
                            UninstallString = $validate.UninstallString
                        }
                        $null = $results.Add($item)
                    }
                }
            }

            $events = Get-EventLog -LogName $EventViewerLogName | Where-Object { $_.Source -eq 'MsiInstaller' }

            # Send back a PSCustomObject to be processed client side with both registry and event log entries
            [PSCustomObject]@{
                EventsResults   = $events
                RegistryResults = $results
            }
        }

        Save-Output "$(Get-TimeStamp) Starting process"
    }

    process {
        try {
            Save-Output "$(Get-TimeStamp) Setting event log to: $($EventViewerLogName)"

            if ($parameters.ContainsKey('DomainComputers')) {
                $computersFound = Get-AdComputer -Filter $Filter
            }
            else {
                if (-NOT $Computers) {
                    Save-Output "$(Get-TimeStamp) ERROR: You did not specify a computer(s) to connect to"
                    return
                }
                else {
                    $computersFound = $Computers
                }
            }

            foreach ($computer in $computersFound) {
                # Checking to see if we passed a manual list or a domain found list
                if ($computer.Name) { $computer = $computer.Name }

                if ($parameters.ContainsKey('EnableConsoleOutput')) { Save-Output "$(Get-TimeStamp) Grabbing registry and event log information from $($computer)" }

                try {
                    if ($parameters.ContainsKey('UseCredentials')) {
                        $password = ConvertTo-SecureString "YourAdminPassword" -AsPlainText -Force
                        $credentials = New-Object System.Management.Automation.PSCredential ($UserName, $password)
                        $result = Invoke-Command -ComputerName $computer -ScriptBlock $scriptBlock -ArgumentList $EventViewerLogName -Credential $credentials -ErrorAction SilentlyContinue -ErrorVariable Failed
                    }
                    else {
                        $result = Invoke-Command -ComputerName $computer -ScriptBlock $scriptBlock -ArgumentList $EventViewerLogName -ErrorAction SilentlyContinue -ErrorVariable Failed
                    }

                    # processing the event log client side
                    $completeEvents = $result.EventsResults | select-string -InputObject { $_.Message } -Pattern "Installation completed successfully"

                    # Return type is Microsoft.PowerShell.Commands.MatchInfo and we just need the Line info so constructing a PSCustomObject to hold our information we want to display
                    foreach ($completedEvent in $completeEvents) {
                        $entry = [PSCustomObject]@{
                            Result = $completedEvent.Line
                        }
                        $null = $completedEntries.add($entry)
                    }

                    if ($Failed) {
                        $failedEntry = [PSCustomObject]@{
                            ComputerName = $Failed.OriginInfo.PSComputerName
                            Time         = (Get-Date)
                            Action       = $Failed.CategoryInfo.Activity
                            Reason       = $Failed.CategoryInfo.Reason
                        }
                        $null = $failureEntries.add($failedEntry)
                    }
                }
                catch {
                    Save-Output "$(Get-TimeStamp) ERROR: $_"
                    return
                }

                if ($parameters.ContainsKey('SaveDataToDisk')) {
                    if ($SaveLogLocation -eq 'Default') {
                        Save-Output "$(Get-TimeStamp) ERROR: You did not specify a save location. Unable to save search results."
                        return
                    }
                    else {
                        Save-Output "$(Get-TimeStamp) Exporting event logs to $(Join-Path -Path $LoggingDirectory -ChildPath $EventLogSaveFileName). Please wait!" -InputObject $completedEntries -SaveFileOutput:$True
                        Save-Output "$(Get-TimeStamp) Exporting registry logs to $(Join-Path -Path $LoggingDirectory -ChildPath $RegistrySaveFileName). Please wait!" -RegistryObject $result.RegistryResults -SaveFileOutput:$True
                    }
                }

                if ($parameters.ContainsKey('DisplayResultsOnConsole')) {
                    Save-Output "$(Get-TimeStamp) Install registry events"
                    $completedEntries
                    Save-Output "$(Get-TimeStamp) Install events logs events"
                    $result.RegistryResults | Format-Table
                }
            }

            if ($failureEntries.count -gt 0) {
                Save-Output "$(Get-TimeStamp) WARNINGS / ERRORS: No logs found on some computers!" -FailureObjects $failureEntries -SaveFailureOutput:$True
                Save-Output "$(Get-TimeStamp) Please check $(Join-Path -Path $LoggingDirectory -ChildPath $LoggingFileName) for more information."
            }
        }
        catch {
            Save-Output "$(Get-TimeStamp) ERROR: $_"
            return
        }
    }

    end {
        Save-Output "$(Get-TimeStamp) Finished! "
    }
}