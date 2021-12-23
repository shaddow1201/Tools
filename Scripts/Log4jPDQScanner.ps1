<#
    .SYNOPSIS
    Scan a list of drives/locations against a identified file system 
    vulnerabilities, and see if there are:
    A) Vulnerabilities 
    B) Active Exploits

    .DESCRIPTION
    allowing network(will) and local drive(does) scanning.
    .PARAMETER Test_MachineName - when using a network machine
    .PARAMETER LocationsToScan_Array
    .PARAMETER DriveExclusions
    .PARAMETER FolderExclusions
    .PARAMETER VulnerabilityName
    .PARAMETER VulnerabilityDetectionStyle
    .PARAMETER VulnerableIdentifierLocation
    .PARAMETER ScanPattern
    .PARAMETER RecursiveDriveScan
    .PARAMETER MessagingLevel
    .PARAMETER LogResultsToFile
    .PARAMETER LogDirectorys
  
    .NOTES
    Author: Richard Noordam
    Tech Attribution: https://www.pdq.com/blog/log4j-vulnerability-cve-2021-44228/
    Created on 12/20/2021

    .EXAMPLE Log4jPDQScanner.ps1 
    to scan local drives.

    .EXAMPLE
    to scan network drives (TODO)
#>
[CmdletBinding()]
param (
  [string]$Test_MachineName = '',
  [array] $LocationsToScan_Array = @(),
  [array] $DriveExclusions = @('I:\','J:\'),
  [array] $FolderExclusions = @('C:\Program Files\Windows Defender Advanced Threat Protection\Classification\Configuration\','C:\Windows\CSC\v2.0.6\','C:\Windows\System32\LogFiles\WMI\RtBackup\'),
  [string]$VulnerabilityName = 'Log4j_Vulnerability',
  [string]$VulnerabilityDetectionStyle = 'sha256sums',
  [string]$VulnerableIdentifierLocation = 'https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes/raw/main/sha256sums.txt',
  [string]$ScanPattern = "log4j*.jar",
  [boolean]$RecursiveDriveScan = $true,
  [string]$MessagingLevel = '4',
  [string]$LogResultsToFile = 'Y',
  [string]$LogDirectory = 'D:\Tools\Scripts\'
)
#region Function Area - System Setup
[string]$LogFileString="$($LogDirectory)$($VulnerabilityName).txt"
$Tab = [char]9 
function Get-TimeStampNonFilename {
  #.SYNOPSIS TimeStamp usable for files

  return '[{0:MM/dd/yy} {0:HH:mm:ss}]' -f (Get-Date)
}
function Get-FileNameTimeSTamp {
  #.SYNOPSIS Logfile TimeStamp 
  $Date = '{0:MMddyy}{0:HHmmss}' -f (Get-Date)
  #$Date.Replace(')','').Replace('(','') 
  return $Date
}
function Write-Message {
  #.SYNOPSIS Messaging and Logging, with configurable level notations.
  [CmdletBinding()]
  param (
    [string]$Message='', 
    [int]$MessageLevel=0,
    [int]$Severity=1
  )
  $SeverityMessage = ''
  switch($Severity){
      2 { $SeverityMessage = 'WARNING: ' }
      3 { $SeverityMessage = 'ERROR: ' }
  }
  $Tab = [char]9
  if($script:MessagingLevel -ge $MessageLevel){
    $level = switch ($MessageLevel)
    {
      0 {""} # basic info
      1 {""} # additional info
      2 {"$Tab"} # second level objects
      3 {"$Tab$Tab"} # third level objects
      4 {"$Tab$Tab$Tab"} # more? usually just more detail.
    }
    $BuildMessage = $level + $Message
    if($($global:LogResultsToFile) -eq 'Y'){
      # placeholder for file output.
      Write-Output "$(Get-TimeStampNonFilename)$Tab$($BuildMessage)" | Out-file "$($global:LogFileString)" -append
    }
    switch($Severity){
      1 {
        write-Host "$($BuildMessage)"
      }
      2 {
        Write-Warning "$($BuildMessage)"
      }
      3 {
        Write-Error "$($BuildMessage)"
      }
    }
  }
}
Write-Message "#########################################################################" 1 1
Write-Message "LogFile will be located at: $($LogFileString)" 1 1
function Set-LogFileName{
  #.SYNOPSIS Set and Return the LogFileName
  [string]$LogDirectory=$script:LogDirectory, 
  [string]$VulnerabilityName=$script:VulnerabilityName
  # .Set-LogFileName in Directory/VulnerabilityName.txt format
  Write-Message "LogFile Directory and Name set: $($LogDirectory)$($VulnerabilityName).txt" 1 1
}
function Show-LocalDrivesToBeScanned {
  #.SYNOPSIS Resolve Local Drive Requests
  $Tab = [char]9
  $retDriveArray =@()
  # if nothing passed in look at local system and apply exclusions
  if ($script:LocationsToScan_Array.Count -eq 0){
    $Drives = Get-PSDrive -PSProvider 'FileSystem'
    # Exclusion Array matched against drives
    foreach ($Drive in $Drives){
      if (!($DriveExclusions -contains $Drive.Root) -and !($retDriveArray -contains $Drive.Root)){
        $retDriveArray += $Drive
      }
    }
  } else {
    $Drives = $LocationsToScan_Array
    foreach ($Drive in $Drives){
      if (!($DriveExclusions -contains $Drive.Root) -and !($retDriveArray -contains $Drive.Root)){
        $retDriveArray += $Drive
      }
    }
  }
  return $retDriveArray
}
function Get-SystemConditions {
  #.SYNOPSIS Determine Script Posture (Local/Network) and display resources to scan.
  $Tab = [char]9
  $retDriveArray =@()
  if ($script:Test_MachineName.Length -gt 0){
    if ($script:Test_MachineName -ne "$($env:COMPUTERNAME)"){
      Write-Message "Scan Host: $($script:Test_MachineName)" 1 1
      <#
          To check the drives on a remote computer, add the ComputerName parameter.
          For example, to list all physical drives and their free space on a machine called: ContosoWS1
                    
          Get-WmiObject Win32_LogicalDisk -ComputerName SEA-SRV-01 | Format-Table
      #>
      $retDriveArray = ''
      exit
    } else {
      Write-Message "Scan Host:$Tab $($env:COMPUTERNAME)" 1 1
      $retDriveArray = Show-LocalDrivesToBeScanned
    }
  } else {
    Write-Message "Scan Host:$Tab $($env:COMPUTERNAME)" 1 1
    $retDriveArray = Show-LocalDrivesToBeScanned
  }
  Write-Message "Scan Drives:$Tab $($retDriveArray)" 1 1
  return $retDriveArray
}
#endregion
#region Start and setup
# .Welcome_Message
Write-Message "#########################################################################" 0 1
Write-Message '  ' 0 1
Write-Message 'The Zero Day Vulnerability Scanner' 0 1
Write-Message 'When all you have is a jackknife, ' 0 1
Write-Message 'and a description of a vulnerability.' 0 1
Write-Message "#########################################################################" 0 1
# Reason: Need based to assess potential threats, and even maybe 
# a hack on the fly. I will extend some functionality 
# to do so hash based SQL Server data checking. 
#
Write-Message 'Computer and Locations to be scanned' 0 1
Write-Message "#########################################################################" 0 1
# .DrivesAndLocations

$SearchDriveArray = Get-SystemConditions
Write-Message ' ' 0 1
#  a) Volume Exclusions - works and is shown.
#  b) Directory Set Exclusion - a WIP
Write-Message "Drive Exclusions: $($DriveExclusions)" 0 1
Write-Message ' ' 0 1
Write-Message "#########################################################################" 0 1
#endregion
#region Function Area - Processing Functions
function Get-VulnerabilityDetails {
  #.SYNOPSIS Retrieve Vulnerability Resources
  $Tab = [char]9
  write-message "Vulnerability Detail Location: $( $script:VulnerableIdentifierLocation)" 1 1
  Write-Message ' ' 1 1
  switch ($script:VulnerabilityDetectionStyle){
    # Handles the Log4J pattern
    'sha256sums' { 
      Write-Message "Vulnerability Type Identified:$Tab$Tab sha256sums" 1 1
      if ($script:ScanPattern -eq 'log4j*.jar'){
        Write-Message "Specific Vulnerability Identified:$Tab Log4j*.jar" 1 1
        try {
          # yanks out objects of 64 length
          $VulnerableSums = -split $(Invoke-WebRequest $VulnerableIdentifierLocation -UseBasicParsing).content | Where-Object {$_.length -eq 64} -ErrorAction Continue 
        } catch {
          $VulnerableSums = @()
          Write-Message '###########################################################################' 0 3
          Write-Message " " 0 3
          Write-Message 'Web Failure Detected, exiting program.' 0 2
          Write-Message " " 0 3
          Write-Message '###########################################################################' 0 3
          exit
        }
        Write-Message "sha256sum File Signatures Acquired:$Tab $($VulnerableSums.Count)" 0 1
      }
      # Add Additional Types here as we Identify
      if ($VulnerableSums.Count -eq 0) {
        Write-Message '###########################################################################' 0 3
        Write-Message '## Vunerability Resources not detected, CRITICAL FAILURE, exiting program.' 0 3
        Write-Message '###########################################################################' 0 3
        exit
      }
      $VulnerableObjects = $VulnerableSums
    }
    # Allows easy to add patterns/breakdowns of additional sources.
  }
  return $VulnerableObjects
}
function Get-SingleDriveVulnerability([string]$Drive){
  #.SYNOPSIS Handle failures related to retreiving web resources.
  write-message "DriveRoot: $($Drive)" 2 1
  write-message "ScanPattern: $($script:ScanPattern)" 2 1
  [boolean]$RecursiveDriveScan=$script:RecursiveDriveScan
  [array]$FileErrorsArray = @()
  if ($Test_MachineName.Length -eq 0){
    ## Where-Object -FilterScript { !($FolderExclusions -contains (get-item $_).parent) }
    $DriveSearchSums = get-childitem "$($Drive)$($script:ScanPattern)" -file -recurse:$RecursiveDriveScan -ErrorVariable $FileErrors | Select-Object FullName, @{Name = 'Hash'; Expression = {(Get-FileHash -Path $_.FullName).Hash}} 
    $FileErrors = [String]$FileErrors
    $FileErrorArray = [string]$FileErrors.Split(".").TrimStart()
    foreach ($FileError in $FileErrorArray){
      Write-Message "File Scan Error: $($FileError)" 0 2
    } 
    if ($FileErrorArray.Count -gt 0){
      Write-Message "Total Errors: $($FileErrorArray.Count)" 2 2
    } else {
      Write-Message "No FileScan Errors." 2 1
    }
  } else {
    # Network scan TODO/Test
    cd c: #THIS IS THE CRITICAL LINE
    Write-Message "$($Drive)$($script:ScanPattern) Scanned." 2 1
    $DriveSearchSums = get-childitem "$($Drive)$($script:ScanPattern)" -file -recurse:$RecursiveDriveScan | Select-Object FullName, @{Name = 'Hash'; Expression = {(Get-FileHash -Path $_.FullName).Hash}}  
  }
  if ($DriveSearchSums.Count -gt 0){
    write-message "Get Single Drive matching file Sums from $($Drive)$($script:ScanPattern) Found: $($DriveSearchSums.Count)" 2 2
  } else {
    write-message "Get Single Drive matching file Sums from $($Drive)$($script:ScanPattern) Found: $($DriveSearchSums.Count)" 2 1
  }
  return $DriveSearchSums
}
function Get-Vulnerabilities{
  #.SYNOPSIS Search Each Drive for issues.
  [CmdletBinding()]
  param (
    [array]$SearchDriveArray 
  )
  [string]$ScanPattern=$script:ScanPattern
  $DriveSearchSums = @{}
  $DriveSearchSumsFound = @()
  $resultHash = @{}    
  $totalVulnerabilitiesFound = 0
  $Tab = [char]9
  foreach($Drive in $SearchDriveArray) {
    write-Message "Data Collection Starting: $($Drive.Root)$($script:ScanPattern)" 1 1
    $DriveSearchSumsArray = Get-SingleDriveVulnerability "$($Drive.Root)"
    Write-Message "Data Collection Complete: ($($Drive.Root)$($script:ScanPattern))" 1 1
    if(-not($null -eq $DriveSearchSumsArray)){
      $DriveSearchSumsFound += $DriveSearchSumsArray
      Write-message "Vulnerable Objects Found $($DriveSearchSumsArray.Count)" 1 2
      Write-Message "###############################################################################################################" 0 2
      Write-Message " " 0 2
      Write-Message "ATTENTION: LOCATION CONTAINS NON-COMPROMISED HIGH-RISK FILES: $($DriveSearchSumsArray.Count) " 0 2
      foreach($Entry in $DriveSearchSumsArray){
        write-message "VULNERABLE FILE FOUND: $Tab $($Entry.FullName) $Tab$Tab$Tab -Hash: $($Entry.Hash)" 0 2
      }
      Write-Message "ATTENTION: LOCATION CONTAINS NON-COMPROMISED HIGH-RISK FILES: $($DriveSearchSumsArray.Count)" 0 2
      Write-Message " "        
      Write-Message "###############################################################################################################" 0 2
      $VulnerableSums = Compare-Object -ReferenceObject $script:VulnerableObjects -DifferenceObject $DriveSearchSumsArray.Hash -ExcludeDifferent -IncludeEqual -ErrorAction Continue
      if(-not($null -eq $VulnerableSums)){
        # if Vulnerable Files Found based File Pattern Search, note as vulnerable, 
        # and add to counter of vulnerabilities hashes against, to see if they are
        # still valid in our system
        $checkCounter = 0
        # hashes should match beteen vulnerabilities and our systems, and count the same # 
        # or there is a possilbe breach.
        foreach ($Entry in $DriveSearchSumsArray){
          if($VulnerableSums.InputObject -contains $Entry.Hash){
            $resultHash.Add($Entry.FullName, $Entry.Hash)
            $checkCounter++
          }
        }
        if ($checkCounter -ne $DriveSearchSumsArray.Count){
          Write-Message "###############################################################################################################" 0 3
          Write-Message "###############################################################################################################" 0 3
          Write-Message "## WARNING POSSIBLE BREACH: Vulnerable Number of Vulnerable Hashes: $($DriveSearchSumsArray.Count) does not Match!!" 0 3
          Write-Message "## WARNING POSSIBLE BREACH: Vulnerable Number of Vulnerable Hashes: $($DriveSearchSumsArray.Count) does not Match!!" 0 3
          Write-Message "## WARNING POSSIBLE BREACH: Vulnerable Number of Vulnerable Hashes: $($DriveSearchSumsArray.Count) does not Match!!" 0 3
          Write-Message "## WARNING POSSIBLE BREACH: MISING HASH VALUES SUGGEST BREACH, AND LIKELY ACTIVITY." 0 3
          Write-Message "###############################################################################################################" 0 3
          Write-Message "###############################################################################################################" 0 3
        }
      }
      $totalVulnerabilitiesFound = $totalVulnerabilitiesFound + $DriveSearchSumsArray.Count
      write-Message "Total Vulnerabilities found during scan: $($totalVulnerabilitiesFound)" 1
    } else {
      Write-Message "###########################################" 0 1
      Write-Message " " 0 1
      Write-Message "NO VULNERABLE FILES Detected on $($Drive.Root)$($script:ScanPattern) during scan." 0 1
      Write-Message "###########################################" 0 1
    }
  }
  return $DriveSearchSumsFound
}
function Get-MitigationDetails{
  [CmdletBinding()]
  param (
    [string]$VulnerabilityName
  )
  $Tab = [char]9
  write-Message "Vulnerability Type: $($VulnerabilityName)" 0 1
  switch ($VulnerabilityName){
    "Log4j_Vulnerability" {
      Write-Message "Vulnerability Notice:$Tab https://nvd.nist.gov/vuln/detail/CVE-2021-44228#match-7275032" 0 1
      Write-Message " " 0 1
      Write-Message "Detection/Mitigation Possible:$Tab Microsoft Defender Detection and More: https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/" 0 1
      Write-Message "Mitigation Possible??:$Tab Detect and possilbe mitigation technique: https://www.deepwatch.com/blog/3-steps-to-detect-patch-log4j-log4shell-vulnerability/" 0 1
    }
  }
}
#endregion
#region Main Body
################################################
##
##  Begin Program. Log4J Testing
##
#################################################
# clear screen and begin.
# Clear-Host
#
# .IMPORTANT
#
#   All issues are preceeded by either WARNING: and a tab delimited format after that
#   for easy master script aggregation for analysis.
#
# TODO: 
#   -Capture Access Denied errors
#   -Folder Location Exclustion
#   -Network Location Scan
#   -Network Folder Exclusions
#
#  Idea List - abstract  
#  1. Attack Types
#  2. Links to currently updated sources
#  3. Network Scans.
#  4. Auto-Scan
#  5. Interactive-Scan, 
#       a) with possible remedies, 
#       b) and information links.
#       c) latest updated repository data pulls, predefined or auto
#  6. Add multi threading to allow multi computers and/or threats to be
#     assessed at a time.
#
# .Vulnerability Retreival
$VulnerableObjects = Get-VulnerabilityDetails
Write-Message " " 0 1
write-Message "Retrieved $($VulnerableObjects.Count) Vulnerable Object Definitions" 0 1
Write-Message " " 0 1
foreach($VulnerableObject in $VulnerableObjects){
  Write-Message "$($VulnerableObject)" 0 1
}

Write-Message " " 0 1
# 4. Use Drive list passed in and then process scan list in loop manner.
# TODO: file directories exclusions to be added.
# .Location Scans
#Write-Message "Search Locations- $($SearchDriveArray)" 0 1
$SearchedForVulnerabilityArray = Get-Vulnerabilities $SearchDriveArray 
#Write-Message "Display File Vulnerabilties Found: $($SearchedForVulnerabilityArray.Count)" 0 1
foreach($VulnerableHash in $SearchedForVulnerabilityArray){
  Write-Message "FileName and Location:$Tab$($VulnerableHash.FullName)$Tab-File HashValue:$Tab$($VulnerableHash.Hash)" 0 2
}
Write-Message ' ' 0 1
Write-Message "#########################################################################" 0 1
Write-Message ' ' 0 1

# if we have found potential issues.  we can point at resources or even auto fix them, if there is a way.
if ($SearchedForVulnerabilityArray.Count -gt 0){
  Get-MitigationDetails $script:VulnerabilityName
}
# .End of Script
#endregion

