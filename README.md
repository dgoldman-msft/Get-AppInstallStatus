# Get-AppInstallStatus

Check a machine to make sure installation of applications complete before sending the Autopilot device to an end user

> EXAMPLE 1: Get-AppInstallStatus -DisplayErrors -SaveDataToDisk -Computers Computer1, Computer2

- This will connect to Computer1 and Computer2 to search the event logs and registry for events and display any warnings / errors found

>EXAMPLE 2: Get-AppInstallStatus -DomainComputers -SaveDataToDisk

- This will connect to to a domain controller and search for all computers based on filter and save the logs to a local or network share

> NOTE: All logs will be saved to the following variable -> $EventLogSaveLocation = 'c:\AppInstallStatus'. This can be a local share or a network share with the correct write permissions
