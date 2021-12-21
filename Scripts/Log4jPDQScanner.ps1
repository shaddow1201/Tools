<#
.SYNOPSIS
Scan a list of drives against a identified file system vulnerability of vulnerabilities
#>  
<#
.DESCRIPTION
allowing network(will) and local drive(does) scanning.

.PARAMETER Test_MachineName - when using a network machine
.PARAMETER LocationsToScan_Array
.PARAMETER FolderExclusions
.PARAMETER LocalMachine
.PARAMETER VulnerabilityName
.PARAMETER VulnerabilityDetectionStyle
.PARAMETER VulnerableIdentifierLocation
.PARAMETER ScanPattern
.PARAMETER RecursiveDriveScan
.PARAMETER LogResultsToFile
.PARAMETER LogDirectory
.PARAMETER LogDirectory

.Example
$hashTable = @{
    Key1 = 'Value1'
}
$hashTable.Add("Key2", "Value2")
$hashTable

.NOTES
    Author: Richard Noordam
    Tech Attribution: https://www.pdq.com/blog/log4j-vulnerability-cve-2021-44228/
    Created on 12/20/2021

.EXAMPLE Log4jPDQScanner.ps1 
 to scan local drives.

.EXAMPLE
 to scan network drives (TODO)
#>
 param (
    [parameter(Mandatory=$false)][string]$Test_MachineName = "",
    [Parameter(Mandatory=$false)]$LocationsToScan_Array = @(),
    [Parameter(Mandatory=$false)][string]$FolderExclusions = "",
    [Parameter(Mandatory=$false)][string]$LocalMachine = "Y",
    [Parameter(Mandatory=$false)][string]$VulnerabilityName = "Log4j_Vulnerability",
    [Parameter(Mandatory=$false)][string]$VulnerabilityDetectionStyle = "sha256sums",
    [Parameter(Mandatory=$false)][string]$VulnerableIdentifierLocation = "https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes/raw/main/sha256sums.txt",
    [Parameter(Mandatory=$false)][string]$ScanPattern = "log4j*.jar",
    [Parameter(Mandatory=$false)][string]$RecursiveDriveScan = "Y",
    [Parameter(Mandatory=$false)][string]$LogResultsToFile = "Y",
    [Parameter(Mandatory=$false)][string]$LogDirectory = "D:\Tools\Scripts\"

 )
function Catch-WebFailure {
    $global:helpme = $body
    $global:helpmoref = $moref
    $global:result = $_.Exception.Response.GetResponseStream()
    $global:reader = New-Object System.IO.StreamReader($global:result)
    $global:responseBody = $global:reader.ReadToEnd();
    Write-Host -BackgroundColor:Black -ForegroundColor:Red "Status: A system exception was caught."
    Write-Host -BackgroundColor:Black -ForegroundColor:Red $global:responsebody
    Write-Message "Status: A system exception was caught." 0
    Write-Message "$($global:responsebody)" 0
    break
}
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}
function Write-Message ($Message, $MessageLevel) {
    $BuildMessage = $Level + " " + $Message
    if($($LogResultsToFile) -eq "Y"){
        # placeholder for file output.
        Write-Output "$(Get-TimeStamp) $($BuildMessage)" | Out-file "$($LogFile)" -append
    }
        write-host $BuildMessage
}
function Set-LogFileName (){
    # .Set-LogFileName in Directory/VulnerabilityName.txt format
    $retVal = "$($LogDirectory)$($VulnerabilityName).txt"
    Write-Message "$($retVal)" 0
    return $retVal
}
function Show-DrivesToBeScanned(){
    if ($LocationsToScan_Array.Count -eq 0){
        $Drives = Get-PSDrive -PSProvider 'FileSystem'
        Write-Message "Local Drives Scan Results:` $($Drives.Count)" 0
    } else {
        $Drives = $LocationsToScan_Array
        Write-Message "Local Drives Requested: $($LocationsToScan_Array.Count)" 0
    }
    return $Drives
}
function Get-SystemConditions (){
    if ($Test_MachineName.Length -gt 0){
        if ($LocalMachine -ne $($env:COMPUTERNAME)){
            Write-Host "Remote Machine: $($Test_MachineName) Selected for Scanning"
            <#
                To check the drives on a remote computer, add the ComputerName parameter.
                For example, to list all physical drives and their free space on a machine called: ContosoWS1
                    
                Get-WmiObject Win32_LogicalDisk -ComputerName SEA-SRV-01 | Format-Table
            #>
            $retVal = ""
            exit
        } else {
            Write-Message "Local Machine: $($env:COMPUTERNAME) Selected for Scanning" 0
            $retVal = Show-DrivesToBeScanned
        } else {
            Write-Message "Network Machine Scan:" 0
        }
    } else {
        Write-Message "Local Machine: $($env:COMPUTERNAME) Selected for Scanning" 0
        $retVal = Show-DrivesToBeScanned
    }
    return $retVal
}
function Get-VulnerabilityDetails (){
    $VulnerableDetails = ""
    switch ( $VulnerabilityDetectionStyle ){
        # Handles the Log4J pattern
        "sha256sums" { 
            if ($ScanPattern -eq "log4j*.jar"){
                Write-Message "sha256sums Identified Vulnerability Set." 0
                try {
                    $VulnerableDetails = -split $(Invoke-WebRequest $($VulnerableIdentifierLocation) -UseBasicParsing).content | Where-Object {$_.length -eq 64} -ErrorAction Continue 
                } catch {
                    $VulnerableDetails = ""
                    Catch-WebFailure
                    Write-Message "Web Failure Detected, exiting program." 0
                    exit
                }
            }
            # Add Additional Types here as we Identify
    
            if ($VulnerableDetails.Count -eq 0) {
                Write-Message "###########################################################################" 0
                Write-Message "## Vunerability Resources not detected, CRITICAL FAILURE, exiting program." 0
                Write-Message "###########################################################################" 0
                exit
            }
        }
        # Allows easy to add patterns/breakdowns of additional sources.
    }
    return $VulnerableDetails
}
function Scan-DrivesForVulnerabilities (){
    foreach($Drive in $SearchDriveArray) {
      $localMessage = "Scanning: {0}   Location: {1}" -f $Drive.Name, $Drive.Root
      Write-Message "$($Drive.Root)$($ScanPattern)" 0
      if ($RecursiveDriveScan -eq "Y"){
        if ($LocalMachine -eq "Y"){
          try {
            $Details = get-childitem "$($Drive.Root)$($ScanPattern)" -file -Recurse -ErrorVariable $ErrorCaught | Select-Object Fullname, @{Name = "Hash"; Expression = {(Get-FileHash -Path $key.FullName).Hash}} 
            Write-Message "$($Drive.Root)$($ScanPattern) Scanned."
          } catch {
            write-message "$($ErrorCaught)" 0
          }
          if(-not($null -eq $Details)){
            $BadHash = Compare-Object -ReferenceObject $VulnerableDetails -DifferenceObject $Details.Hash -ExcludeDifferent -IncludeEqual -ErrorAction SilentlyContinue
          }
        } Else {
          # Network scan TODO/Test
          cd c: #THIS IS THE CRITICAL LINE
          try {
            Write-Message "$($Drive.Root)$($ScanPattern) Scanned."
            $Details = get-childitem "$($Drive.Root)$($ScanPattern)" -file -Recurse -ErrorVariable $ErrorCaught | Select-Object Fullname, @{Name = "Hash"; Expression = {(Get-FileHash -Path $Drive.Root.FullName).Hash}} 
          } catch {
            write-message "$($ErrorCaught)" 0
          }
          if(-not($null -eq $Details)){
            $BadHash = Compare-Object -ReferenceObject $VulnerableDetails -DifferenceObject $Details.Hash -ExcludeDifferent -IncludeEqual  -ErrorAction SilentlyContinue 
          }
        }
      } else {
        if ($LocalMachine -eq "N"){
          try {
            $Details = get-childitem "$($Drive.Root)$($ScanPattern)" -file -ErrorVariable $ErrorCaught | Select-Object Fullname, @{Name = "Hash"; Expression = {(Get-FileHash -Path $key.FullName).Hash}} 
            Write-Message "$($Drive.Root)$($ScanPattern) Scanned."
          } catch {
            write-message "$($ErrorCaught)" 0
          }
          if(-not($null -eq $Details)){
            $BadHash = Compare-Object -ReferenceObject $VulnerableDetails -DifferenceObject $Details.Hash -ExcludeDifferent -IncludeEqual  -ErrorAction SilentlyContinue
          }
        } else {
          # Network scan TODO/Test
          cd c: #THIS IS THE CRITICAL LINE
          try {
            Write-Message "$($Drive.Root)$($ScanPattern) Scanned."
            $Details = get-childitem "$($Drive.Root)$($ScanPattern)" -file -ErrorVariable $ErrorCaught | Select-Object Fullname, @{Name = "Hash"; Expression = {(Get-FileHash -Path $Drive.Root.FullName).Hash}}  
          } catch {
            write-message "$($ErrorCaught)" 0
          }
          if(-not($null -eq $Details)){
            $BadHash = Compare-Object -ReferenceObject $VulnerableDetails -DifferenceObject $Details.Hash -ExcludeDifferent -IncludeEqual  -ErrorAction SilentlyContinue
          }
        }
      }
      #        foreach ($Matcherror in $errors){
      #            Write-Message "Trapped Errors: $($error)" 0
      #        }                
      foreach($Entry in $Details){
        if($BadHash.InputObject -contains $Entry.Hash){
             += $Entry
        }
      }
    }
    return $result
}

################################################
##
##  Begin Program.
##
#################################################
#
Clear-Host
# 1. Get variable for scan locations.
Write-Message "The Scanner will look at the following locations:" 0
$SearchDriveArray = Get-SystemConditions

# 2.SetLogFileName
$LogFile = Set-LogFileName

# 3. Get and Process Vulnerability Type
$errors
$VulnerableDetails = Get-VulnerabilityDetails

# 4. Use Drive list passed in and then process scan list in loop manner.
#
# TODO: file directories exclusions to be added.
$result = Scan-DrivesForVulnerabilities
#Return FileLocation and hash for each vulnerable result

# 5. Detail out Results.

if($null -eq $result){
    [pscustomobject]@{
        FullName = "No Vulnerable Files"
        Hash = " "
    }
}Else{
    [pscustomObject]$result
}


