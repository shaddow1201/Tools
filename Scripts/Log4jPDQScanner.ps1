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
Write-Message "#########################################################################" 1
Write-Message "LogFile will be located at: $($LogFileString)" 1

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
function Set-LogFileName{
  #.SYNOPSIS Set and Return the LogFileName
  [string]$LogDirectory=$script:LogDirectory, 
  [string]$VulnerabilityName=$script:VulnerabilityName
  # .Set-LogFileName in Directory/VulnerabilityName.txt format
  Write-Message "LogFile Directory and Name set: $($LogDirectory)$($VulnerabilityName).txt" 1
}
function Show-LocalDrivesToBeScanned {
  #.SYNOPSIS Resolve Local Drive Requests
  $RetArray =@()
  # if nothing passed in look at local system and apply exclusions
  if ($script:LocationsToScan_Array.Count -eq 0){
    $Drives = Get-PSDrive -PSProvider 'FileSystem'
    # Exclusion Array matched against drives
    foreach ($Drive in $Drives){
      if (!($DriveExclusions -contains $Drive.Root) -and !($RetArray -contains $Drive.Root)){
        $RetArray += $Drive
      }
    }
  } else {
    $Drives = $LocationsToScan_Array
    Write-Message "Local Drives Requested: $($Drives.Count)" 2
    foreach ($Drive in $Drives){
      if (!($DriveExclusions -contains $Drive.Root) -and !($RetArray -contains $Drive.Root)){
        $RetArray += $Drive
      }
    }
  }
  Write-Message "Scan Locations Requested: $($RetArray.Count)" 2
  return $RetArray
}
function Get-SystemConditions {
  #.SYNOPSIS Determine Script Posture (Local/Network) and display resources to scan.
  if ($script:Test_MachineName.Length -gt 0){
    if ($script:Test_MachineName -ne "$($env:COMPUTERNAME)"){
      Write-Message "Scan Host: $($script:Test_MachineName)" 1
      <#
          To check the drives on a remote computer, add the ComputerName parameter.
          For example, to list all physical drives and their free space on a machine called: ContosoWS1
                    
          Get-WmiObject Win32_LogicalDisk -ComputerName SEA-SRV-01 | Format-Table
      #>
      $retVal = ''
      exit
    } else {
      Write-Message "Scan Host: $($env:COMPUTERNAME)" 1
      $retVal = Show-LocalDrivesToBeScanned
    }
  } else {
    Write-Message "Scan Host: $($env:COMPUTERNAME)" 1
    $retVal = Show-LocalDrivesToBeScanned
  }
  Write-Message "Scan Drives: $($retVal)" 1
  return $retVal
}
#endregion
#region Start and setup
# .Welcome_Message
Write-Message '####################################' 0
Write-Message '#  ' 0
Write-Message 'The Zero Day Vulnerability Scanner' 0
Write-Message 'When all you have is a jackknife, ' 0
Write-Message 'and a description of a vulnerability.' 0
Write-Message '####################################' 0
# Reason: Need based to assess potenital threats, and even maybe 
# a hack on the fly. I will extend some functionality 
# to do so hash based SQL Server data checking. 
#
 

Write-Message 'Computer and Locations to be scanned' 0
Write-Message '####################################' 0
# .DrivesAndLocations
Write-Message 'Accessing Scaning Details.' 0
$SearchDriveArray = Get-SystemConditions
Write-Message "$($SearchDriveArray)"
Write-Message 'Resolved Scaning Details.' 0
Write-Message '####################################' 0
Write-Message 'Accessing Exclusions Details.' 0
#  a) Volume Exclusions - works and is shown.
#  b) Directory Set Exclusion - a WIP
Write-Message ' ' 0
Write-Message "Drive Exclusions: $($DriveExclusions)" 0
Write-Message ' ' 0
Write-Message 'Resolved Exclusions Details.' 0
#endregion
#region Function Area - Processing Functions
function Write-Message {
  #.SYNOPSIS Messaging and Logging, with configurable level notations.
  [CmdletBinding()]
  param (
    [string]$Message='', 
    [int]$MessageLevel=0
  )
  if($script:MessagingLevel -ge $MessageLevel){
    $level = switch ($MessageLevel)
    {
      0 {""}
      1 {""}
      2 {"-- "}
      3 {"--**"}
      4 {"--**--"}
    }
    $BuildMessage = $level + $Message
    if($($global:LogResultsToFile) -eq 'Y'){
      # placeholder for file output.
      Write-Output "$(Get-TimeStampNonFilename) $($BuildMessage)" | Out-file "$($global:LogFileString)" -append
    }
    write-host $BuildMessage
  }
}
function Get-VulnerabilityDetails {
  #.SYNOPSIS Retrieve Vulnerability Resources
  write-message "Location: $( $script:VulnerableIdentifierLocation)"
  switch ($script:VulnerabilityDetectionStyle){
    # Handles the Log4J pattern
    'sha256sums' { 
      Write-Message '## sha256sums Identified Vulnerability Set.' 1
        Write-Message '###########################################################################' 1
      if ($script:ScanPattern -eq 'log4j*.jar'){
        Write-Message '#### Log4j*.jar Vulnerability Selection Identified.' 1
        Write-Message '###########################################################################' 1
        try {
          # yanks out objects of 64 length
          $VulnerableSums = -split $(Invoke-WebRequest $VulnerableIdentifierLocation -UseBasicParsing).content | Where-Object {$_.length -eq 64} -ErrorAction Continue 
        } catch {
          $VulnerableSums = @()
          Write-Message "#######################################" 0
          Write-Message " " 0
          Write-Message 'Web Failure Detected, exiting program.' 0
          Write-Message " " 0
          Write-Message "#######################################" 0
          exit
        }
        Write-Message "sha256sum File Signatures Acquired: $($VulnerableSums.Count)" 1
      }
      # Add Additional Types here as we Identify
      if ($VulnerableSums.Count -eq 0) {
        Write-Message '###########################################################################' 0
        Write-Message '## Vunerability Resources not detected, CRITICAL FAILURE, exiting program.' 0
        Write-Message '###########################################################################' 0
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
  write-message "DriveRoot: $($Drive)" 2
  write-message "ScanPattern: $($script:ScanPattern)" 2
  [boolean]$RecursiveDriveScan=$script:RecursiveDriveScan 
  if ($Test_MachineName.Length -eq 0){
    write-message "Get-SingleDriveVulnerability: $($Drive.Root)$($script:ScanPattern)" 2
    ## Where-Object -FilterScript { !($FolderExclusions -contains (get-item $_).parent) }
    $DriveSearchSums = get-childitem "$($Drive)$($script:ScanPattern)" -file -recurse:$RecursiveDriveScan | Select-Object FullName, @{Name = 'Hash'; Expression = {(Get-FileHash -Path $_.FullName).Hash}} 
  } else {
    # Network scan TODO/Test
    cd c: #THIS IS THE CRITICAL LINE
    Write-Message "$($Drive)$($script:ScanPattern) Scanned." 2
    $DriveSearchSums = get-childitem "$($Drive)$($script:ScanPattern)" -file -recurse:$RecursiveDriveScan | Select-Object FullName, @{Name = 'Hash'; Expression = {(Get-FileHash -Path $_.FullName).Hash}}  
  }
  write-message "Get Single Drive matching file Sums from $($Drive)$($script:ScanPattern) Found: $($DriveSearchSums.Count)" 2
  return $DriveSearchSums
}
function Get-Vulnerabilities{
  #.SYNOPSIS Search Each Drive for issues.
  [CmdletBinding()]
  param (
    [array]$SearchDriveArray=$SearchDriveArray 
  )
  [string]$ScanPattern=$script:ScanPattern
  $DriveSearchSums = @{}
  $resultHash = @{}    
  $totalVulnerabilitiesFound = 0
  foreach($Drive in $SearchDriveArray) {
    write-Message "Data Collection Starting: $($Drive.Root)$($script:ScanPattern)" 1
    $DriveSearchSums = Get-SingleDriveVulnerability "$($Drive.Root)"
    Write-Message "Data Collection Complete: ($($Drive.Root)$($script:ScanPattern))" 1
    if(-not($null -eq $DriveSearchSums)){
      Write-message "Vulnerable Objects Found $($DriveSearchSums.Count)" 1
      if ($DriveSearchSums.Count -gt 0){
        Write-Message "###############################################################################################################" 0
        Write-Message " "        
        Write-Message "ATTENTION: LOCATION CONTAINS NON-COMPROMISED HIGH-RISK FILES: $($DriveSearchSums.Count) " 0
        foreach($Entry in $DriveSearchSums){
          write-message "VULNERABLE FILE FOUND: ` $($Entry.FullName) ```` -Hash: $($Entry.Hash)" 0
        }
        Write-Message "ATTENTION: LOCATION CONTAINS NON-COMPROMISED HIGH-RISK FILES: $($DriveSearchSums.Count)" 0
        Write-Message " "        
        Write-Message "###############################################################################################################" 0
      } else {
        Write-Message "###########################################" 0
        Write-Message " "        
        Write-Message 'NO VULNERABLE FILES Detected during scan.' 0
        Write-Message "###########################################" 0
      }
      $VulnerableSums = Compare-Object -ReferenceObject $script:VulnerableObjects -DifferenceObject $DriveSearchSums.Hash -ExcludeDifferent -IncludeEqual -ErrorAction Continue
      if(-not($null -eq $VulnerableSums)){
        # if Vulnerable Files Found based File Pattern Search, note as vulnerable, 
        # and add to counter of vulnerabilities hashes against, to see if they are
        # still valid in our system
        $checkCounter = 0
        # hashes should match beteen vulnerabilities and our systems, and count the same # 
        # or there is a possilbe breach.
        foreach ($Entry in $DriveSearchSums){
          if($VulnerableSums.InputObject -contains $Entry.Hash){
            $resultHash.Add($Entry.FullName, $Entry.Hash)
            $checkCounter++
          }
        }
        if ($checkCounter -ne $DriveSearchSums.Count){
          Write-Message "###############################################################################################################" 0
          Write-Message "###############################################################################################################" 0
          Write-Message "## WARNING POSSIBLE BREACH: Vulnerable Number of Vulnerable Hashes: $($DriveSearchSums.Count) does not Match!!" 0
          Write-Message "## WARNING POSSIBLE BREACH: Vulnerable Number of Vulnerable Hashes: $($DriveSearchSums.Count) does not Match!!" 0
          Write-Message "## WARNING POSSIBLE BREACH: Vulnerable Number of Vulnerable Hashes: $($DriveSearchSums.Count) does not Match!!" 0
          Write-Message "## WARNING POSSIBLE BREACH: MISING HASH VALUES SUGGEST BREACH, AND LIKELY ACTIVITY." 0
          Write-Message "###############################################################################################################" 0
          Write-Message "###############################################################################################################" 0
        }
      }
      $totalVulnerabilitiesFound = $totalVulnerabilitiesFound + $DriveSearchSums.Count
      write-Message "Total Vulnerabilities found during scan: $($totalVulnerabilitiesFound)" 1
    }

  }

  return $resultHash
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
# TODO: 
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
#Write-Message 'Accessing Vulnerability Definition.' 0
$VulnerableObjects = Get-VulnerabilityDetails
Write-Message " " 0
write-Message 'Vulnerible List of Objects: ' 0 
foreach ($Vulnerability in $VulnerableObjects){
  write-message "$($Vulnerability)" 0
}
Write-Message " " 1
#Write-Message "Resolved Vulnerability Details." 0

# 4. Use Drive list passed in and then process scan list in loop manner.
# TODO: file directories exclusions to be added.
# .Location Scans
#Write-Message 'Accessing Scan Locations.' 0
Get-Vulnerabilities -SearchDriveArray $SearchDriveArray 
#Write-Message 'Resolved Scaning Locations.' 0
# .End of Script
#endregion

