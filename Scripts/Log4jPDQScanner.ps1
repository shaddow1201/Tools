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
  [Parameter(Mandatory=$false)][array] $LocationsToScan_Array = @(),
  [Parameter(Mandatory=$false)][array] $DriveExclusions = @("I:\","J:\","K:\"),
  [Parameter(Mandatory=$false)][array] $FolderExclusions = @("C:\Program Files\Windows Defender Advanced Threat Protection\Classification\Configuration\","C:\Windows\CSC\v2.0.6\","C:\Windows\System32\LogFiles\WMI\RtBackup\"),
  [Parameter(Mandatory=$false)][string]$LocalMachine = "Y",
  [Parameter(Mandatory=$false)][string]$VulnerabilityName = "Log4j_Vulnerability",
  [Parameter(Mandatory=$false)][string]$VulnerabilityDetectionStyle = "sha256sums",
  [Parameter(Mandatory=$false)][string]$VulnerableIdentifierLocation = "https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes/raw/main/sha256sums.txt",
  [Parameter(Mandatory=$false)][string]$ScanPattern = "log4j*.jar",
  [Parameter(Mandatory=$false)][string]$RecursiveDriveScan = "Y",
  [Parameter(Mandatory=$false)][string]$LogResultsToFile = "Y",
  [Parameter(Mandatory=$false)][string]$LogDirectory = "D:\Tools\Scripts\"
)
function Get-WebFailure {
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
function Write-Message ($Message) {
  if($($LogResultsToFile) -eq "Y"){
    # placeholder for file output.
    Write-Output "$(Get-TimeStamp) $($Message)" | Out-file "$($LogFile)" -append
  }
  write-host $Message
}
function Set-LogFileName (){
  # .Set-LogFileName in Directory/VulnerabilityName.txt format
  $retVal = "$($LogDirectory)$($VulnerabilityName).txt"
  Write-Message "$($retVal)"
  return $retVal
}
function Show-DrivesToBeScanned(){
  $RetArray =@()
  if ($LocationsToScan_Array.Count -eq 0){
    $Drives = Get-PSDrive -PSProvider 'FileSystem'
    # Exclusion Array matched against drives
    foreach ($Drive in $Drives){
      if (!($DriveExclusions -contains $Drive.Root) -and !($RetArray -contains $Drive.Root)){
        $RetArray += $Drive
      }
    }
  } else {
    $Drives = $LocationsToScan_Array
    Write-Message "Local Drives Requested: $($LocationsToScan_Array.Count)"
    foreach ($Drive in $Drives){
      if (!($DriveExclusions -contains $Drive.Root) -and !($RetArray -contains $Drive.Root)){
        $RetArray += $Drive
      }
    }
  }
  Write-Message "Drives Set to Scan: $($RetArray)"
  return $RetArray
}
function Get-SystemConditions (){
  if ($Test_MachineName.Length -gt 0){
    if ($LocalMachine -ne $($env:COMPUTERNAME)){
      Write-Host "Scan Host: $($Test_MachineName)"
      <#
          To check the drives on a remote computer, add the ComputerName parameter.
          For example, to list all physical drives and their free space on a machine called: ContosoWS1
                    
          Get-WmiObject Win32_LogicalDisk -ComputerName SEA-SRV-01 | Format-Table
      #>
      $retVal = ""
      exit
    } else {
      Write-Message "Scan Host: $($env:COMPUTERNAME)" 
      $retVal = Show-DrivesToBeScanned
    } else {
      Write-Message "Scan Host: Remote" 
    }
  } else {
    Write-Message "Host: $($env:COMPUTERNAME)" 
    $retVal = Show-DrivesToBeScanned
  }
  Write-Message "Scan Drives: $($retVal)"
  return $retVal
}
function Get-VulnerabilityDetails (){
  $VulnerableDetails = ""
  switch ( $VulnerabilityDetectionStyle ){
    # Handles the Log4J pattern
    "sha256sums" { 
      if ($ScanPattern -eq "log4j*.jar"){
        Write-Message "sha256sums Identified Vulnerability Set."
        try {
          $VulnerableDetails = -split $(Invoke-WebRequest $($VulnerableIdentifierLocation) -UseBasicParsing).content | Where-Object {$_.length -eq 64} -ErrorAction Continue 
        } catch {
          $VulnerableDetails = ""
          Get-WebFailure
          Write-Message "Web Failure Detected, exiting program."
          exit
        }
      }
      # Add Additional Types here as we Identify
    
      if ($VulnerableDetails.Count -eq 0) {
        Write-Message "###########################################################################"
        Write-Message "## Vunerability Resources not detected, CRITICAL FAILURE, exiting program."
        Write-Message "###########################################################################"
        exit
      }
    }
    # Allows easy to add patterns/breakdowns of additional sources.
  }
  return $VulnerableDetails
}
function Get-DriveVulnerabilities (){
  foreach($Drive in $SearchDriveArray) {
    $localMessage = "Scanning: {0}   Location: {1}" -f $Drive.Name, $Drive.Root
    Write-Message "$($Drive.Root)$($ScanPattern)"
    if ($RecursiveDriveScan -eq "Y"){
      if ($LocalMachine -eq "Y"){
        try {
          $Details = get-childitem "$($Drive.Root)$($ScanPattern)" -file -Recurse -ErrorVariable $ErrorCaught | Select-Object Fullname, @{Name = "Hash"; Expression = {(Get-FileHash -Path $key.FullName).Hash}} 
          Write-Message "$($Drive.Root)$($ScanPattern) Scanned."
        } catch {
          write-message "$($ErrorCaught)"
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
          write-message "$($ErrorCaught)"
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
          write-message "$($ErrorCaught)"
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
          write-message "$($ErrorCaught)"
        }
        if(-not($null -eq $Details)){
          $BadHash = Compare-Object -ReferenceObject $VulnerableDetails -DifferenceObject $Details.Hash -ExcludeDifferent -IncludeEqual  -ErrorAction SilentlyContinue
        }
      }
    }
    #        foreach ($Matcherror in $errors){
    #            Write-Message "Trapped Errors: $($error)"
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
# 1. Show system conditions
Write-Message "The Zero Day Vulnerability Scanner"
Write-Message "When all you have is a jackknife, "
Write-Message "and a description of a vulnerability."
Write-Message " "
Write-Message "Computer and Drives to be Scanned: "
$SearchDriveArray = Get-SystemConditions
Write-Message " "
Write-Message "Drive Exclusions: $($DriveExclusions)"
Write-Message " "
# 2.SetLogFileName
$LogFile = Set-LogFileName

# 3. Get and Process Vulnerability Type
$VulnerableDetails = Get-VulnerabilityDetails

# 4. Use Drive list passed in and then process scan list in loop manner.
# TODO: file directories exclusions to be added.
$results = Get-DriveVulnerabilities

# 5. Detail out Results.
if($null -eq $results){
  [pscustomobject]@{
    FullName = "No Vulnerable Files"
    Hash = " "
  }
}Else{
  [pscustomObject]$results
}


