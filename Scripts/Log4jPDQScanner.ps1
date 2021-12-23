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
  [string]$ScanMachine = '',
  [array] $NetworkScanLocations = @(),
  [array] $DriveExclusions = @('C:\','D:\','E:\','F:\','G:\','I:\','I:\','J:\','Z:\'),
  [array] $FolderExclusions = @('C:\Program Files\Windows Defender Advanced Threat Protection\Classification\Configuration\','C:\Windows\CSC\v2.0.6\','C:\Windows\System32\LogFiles\WMI\RtBackup\'),
  [string]$VulnerabilityName = 'CVE-2021-44228',
  [string]$VulnerabilityDetectionStyle = 'SHA256',
  [string]$VulnerabilityDefinitionLocation = 'https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes/raw/main/sha256sums.txt',
  [string]$VulnerabilityFilePattern = "log4j*.jar",
  [boolean]$RecursiveScans = $true,
  [string]$MessagingLevel = '4',
  [string]$LogDirectory = 'D:\Tools\Scripts\'
)
#region Function Area - System Setup
[string]$LogFileString="$($script:LogDirectory)$($script:VulnerabilityName).txt"
$Tab = [char]9 
#.SYNOPSIS TimeStamp usable for files
function Get-TimeStampNonFilename {

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
    [Parameter(Mandatory=$true)][string]$Message, 
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
    Write-Output "$(Get-TimeStampNonFilename)$Tab$($SeverityMessage)$Tab$($BuildMessage)" | Out-file "$($global:LogFileString)" -append
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
Write-Message "#########################################################################" 1
Write-Message " " 1 
Write-Message "LogFile: $($LogFileString)" 1 
function Show-LocalDrivesToBeScanned {
  #.SYNOPSIS Resolve Local Drive Requests
  param
  (
    [string]$ScanMachine='',
    [array]$DriveExclusions=@(),
    [array]$NetworkScanLocations=@()
  )
  $Tab = [char]9
  $retDriveArray =@()
  # if nothing passed in look at local system and apply exclusions
  if ($NetworkScanLocations.Count -eq 0){
    $Drives = Get-PSDrive -PSProvider 'FileSystem'
    # Exclusion Array matched against drives
    foreach ($Drive in $Drives){
      if (!($DriveExclusions -contains $Drive.Root) -and !($retDriveArray -contains $Drive.Root)){
        $retDriveArray += $Drive
      }
    }
  } else {
    $Drives = $ScanMachine
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
  param
  (
    [string]$ScanMachine='',
    [array]$DriveExclusions=@(),
    [array]$NetworkScanLocations=@()
  )
  $Tab = [char]9
  $retDriveArray =@()
  if ($ScanMachine.Length -gt 0){
    if ($ScanMachine -ne "$($env:COMPUTERNAME)"){
      Write-Message "Scan Host: $($ScanMachine)" 1
      <#
          To check the drives on a remote computer, add the ComputerName parameter.
          For example, to list all physical drives and their free space on a machine called: ContosoWS1
                    
          Get-WmiObject Win32_LogicalDisk -ComputerName SEA-SRV-01 | Format-Table
      #>
      $retDriveArray = ''
      exit
    } else {
      Write-Message "Scan Host:$Tab $($env:COMPUTERNAME)" 1 
      $retDriveArray = Show-LocalDrivesToBeScanned $ScanMachine $DriveExclusions $NetworkScanLocations
    }
  } else {
    Write-Message "Scan Host:$Tab $($env:COMPUTERNAME)" 1
    $retDriveArray = Show-LocalDrivesToBeScanned $ScanMachine $DriveExclusions $NetworkScanLocations
  }
  Write-Message "Scan Drives:$Tab $($retDriveArray)" 1
  return $retDriveArray
}
#endregion
#region Start and setup
# .Welcome_Message
Write-Message "#########################################################################"
Write-Message '  '
Write-Message 'The Zero Day Vulnerability Scanner'
Write-Message 'When all you have is a jackknife, '
Write-Message 'and a description of a vulnerability.'
Write-Message "#########################################################################"
# Reason: Need based to assess potential threats, and even maybe 
# a hack on the fly. I will extend some functionality 
# to do so hash based SQL Server data checking. 
#
Write-Message 'Computer and Locations to be scanned'
Write-Message "#########################################################################"
# .DrivesAndLocations

$SearchDriveArray = Get-SystemConditions $ScanMachine $DriveExclusions $NetworkScanLocations
Write-Message ' ' 
#  a) Volume Exclusions - works and is shown.
#  b) Directory Set Exclusion - a WIP
Write-Message "Drive Exclusions: $($DriveExclusions)"
Write-Message ' ' 
Write-Message "#########################################################################"
#endregion
#region Function Area - Processing Functions
function Get-VulnerabilityDetails {
  #.SYNOPSIS Retrieve Vulnerability Resources
  param
  (
    [Parameter(Mandatory=$true)][string]$VulnerabilityDefinitionLocation,
    [Parameter(Mandatory=$true)][string]$VulnerabilityDetectionStyle,
    [Parameter(Mandatory=$true)][string]$VulnerabilityFilePattern
  )
  $Tab = [char]9
  write-message "Vulnerability Detail Location: $( $VulnerabilityDefinitionLocation)" 1 
  Write-Message ' ' 1
  switch ($VulnerabilityDetectionStyle){
    # Handles the Log4J pattern
    'SHA256' { 
      Write-Message "HASH TYPE:$Tab SHA256" 1
      if ($VulnerabilityFilePattern -eq 'log4j*.jar'){
        Write-Message "Specific Vulnerability Identified:$Tab Log4j*.jar" 1
        try {
          # yanks out objects of 64 length
          $VulnerableHashes = -split $(Invoke-WebRequest $VulnerabilityDefinitionLocation -UseBasicParsing).content | Where-Object {$_.length -eq 64} -ErrorAction Continue 
        } catch {
          $VulnerableHashes = @()
          Write-Message '###########################################################################' 0 3
          Write-Message " " 0 3
          Write-Message 'Web Failure Detected, exiting program.' 0 2
          Write-Message " " 0 3
          Write-Message '###########################################################################' 0 3
          exit
        }
        Write-Message "sha256sum File Signatures Acquired:$Tab $($VulnerableHashes.Count)" 0 1
      }
      # Add Additional Types here as we Identify
      if ($VulnerableHashes.Count -eq 0) {
        Write-Message '###########################################################################' 0 3
        Write-Message '## Vunerability Resources not detected, CRITICAL FAILURE, exiting program.' 0 3
        Write-Message '###########################################################################' 0 3
        exit
      }
      $VulnerableObjects = $VulnerableHashes
    }
    # Allows easy to add patterns/breakdowns of additional sources.
    'SHA1' {
      Write-Message "HASH TYPE:$Tab SHA1" 1
    }
    'SHA512' {
      Write-Message "HASH TYPE:$Tab SHA512" 1
    }
    'SHA384' {
      Write-Message "HASH TYPE:$Tab SHA384" 1
    }
    'MD5'  {
      Write-Message "HASH TYPE:$Tab MD5" 1 
    }
  }
  return $VulnerableObjects
}
function Get-Vulnerabilities{
  #.SYNOPSIS Search Each Drive for issues.
  param
  (
    [string]$ScanMachine='',
    [Parameter(Mandatory=$true)][array]$SearchDriveArray,
    [Parameter(Mandatory=$true)][bool]$RecursiveScans,
    [Parameter(Mandatory=$true)][string]$VulnerabilityFilePattern
    
  )
  function Get-SingleDriveVulnerability{
    #.SYNOPSIS Handle failures related to retreiving web resources.
    param
    (
      [string]$ScanMachine='',
      [Parameter(Mandatory=$true)][string]$CurrDrive
    )
    write-message "DriveRoot: $($CurrDrive)" 2
    write-message "ScanPattern: $($VulnerabilityFilePattern)" 2
    $FileErrors = ""
    if ($ScanMachine.Length -eq 0){
      ## Where-Object -FilterScript { !($FolderExclusions -contains (get-item $_).parent) }
      $FileErrors=''
      $DriveFoundSums = get-childitem "$($CurrDrive)$($VulnerabilityFilePattern)" -file -recurse:$RecursiveScans -ErrorVariable +=$FileErrors | Select-Object FullName, @{Name = 'Hash'; Expression = {(Get-FileHash -Path $_.FullName).Hash}} 
      #$FileErrors = [String]$FileErrors
      #$FileErrorArray = [string]$FileErrors.Split(".").TrimStart()
      #foreach ($FileError in $FileErrorArray){
      #  Write-Message "File Scan Error: $($FileError)" 0 2
      #} 
      #if ($FileErrorArray.Count -gt 0){
      #  Write-Message "Total Errors: $($FileErrorArray.Count)" 2 2
      #} else {
      #  Write-Message "No FileScan Errors." 2
      #}
    } else {
      # Network scan TODO/Test
      cd c: #THIS IS THE CRITICAL LINE
      Write-Message "$($CurrDrive)$($VulnerabilityFilePattern) Scanned." 2 1
      $DriveFoundSums = get-childitem "$($CurrDrive)$($VulnerabilityFilePattern)" -file -recurse:$RecursiveScans | Select-Object FullName, @{Name = 'Hash'; Expression = {(Get-FileHash -Path $_.FullName).Hash}}  
    }
    return $DriveFoundSums
  }
  $resultHash = @{}    
  $totalVulnerabilitiesFound = 0
  $Tab = [char]9
  foreach($Drive in $SearchDriveArray) {
    $DriveFoundHashes = @()
    write-Message "Data Collection Starting: $($Drive.Root)$($VulnerabilityFilePattern)" 1
    $DriveFoundHashes = Get-SingleDriveVulnerability $($ScanMachine) "$($Drive.Root)"
    write-Message "$($DriveFoundHashes.Count)"
    Write-Message "Data Collection Complete: ($($Drive.Root)$($VulnerabilityFilePattern))" 1
    if(-not($null -eq $DriveFoundHashes)){
      $DriveSearchSumsFound += $DriveFoundHashes
      Write-message "Vulnerable Objects Found $($DriveFoundHashes.Count)" 1 2
      Write-Message "###############################################################################################################" 0 2
      Write-Message " " 0 2
      Write-Message "ATTENTION: LOCATION CONTAINS NON-COMPROMISED HIGH-RISK FILES: $($DriveFoundHashes.Count) " 0 2
      foreach($Entry in $DriveFoundHashes){
        write-message "VULNERABLE FILE FOUND: $Tab $($Entry.FullName) $Tab$Tab$Tab -Hash: $($Entry.Hash)" 0 2
      }
      Write-Message "ATTENTION: LOCATION CONTAINS NON-COMPROMISED HIGH-RISK FILES: $($DriveFoundHashes.Count)" 0 2
      Write-Message " "        
      Write-Message "###############################################################################################################" 0 2
      $VulnerableSums = Compare-Object -ReferenceObject $VulnerableObjects -DifferenceObject $DriveFoundHashes.Hash -ExcludeDifferent -IncludeEqual -ErrorAction Continue
      if(-not($null -eq $VulnerableSums)){
        # if Vulnerable Files Found based File Pattern Search, note as vulnerable, 
        # and add to counter of vulnerabilities hashes against, to see if they are
        # still valid in our system
        $checkCounter = 0
        # hashes should match beteen vulnerabilities and our systems, and count the same # 
        # or there is a possilbe breach.
        foreach ($Entry in $DriveFoundHashes){
          if($VulnerableSums.InputObject -contains $Entry.Hash){
            $resultHash.Add($Entry.FullName, $Entry.Hash)
            $checkCounter++
          }
        }
        if ($checkCounter -ne $DriveFoundHashes.Count){
          Write-Message "###############################################################################################################" 0 3
          Write-Message "###############################################################################################################" 0 3
          Write-Message "## WARNING POSSIBLE BREACH: Vulnerable Number of Vulnerable Hashes: $($DriveFoundHashes.Count) does not Match!!" 0 3
          Write-Message "## WARNING POSSIBLE BREACH: Vulnerable Number of Vulnerable Hashes: $($DriveFoundHashes.Count) does not Match!!" 0 3
          Write-Message "## WARNING POSSIBLE BREACH: Vulnerable Number of Vulnerable Hashes: $($DriveFoundHashes.Count) does not Match!!" 0 3
          Write-Message "## WARNING POSSIBLE BREACH: MISING HASH VALUES SUGGEST BREACH, AND LIKELY ACTIVITY." 0 3
          Write-Message "###############################################################################################################" 0 3
          Write-Message "###############################################################################################################" 0 3
        }
      }
      $totalVulnerabilitiesFound = $totalVulnerabilitiesFound + $DriveFoundHashes.Count
    } else {
      Write-Message "###########################################"
      Write-Message " "
      Write-Message "NO VULNERABLE FILES Detected on $($Drive.Root)$($VulnerabilityFilePattern) during scan."
      Write-Message "###########################################"
    }
  }
  return $DriveSearchSumsFound
}
function Get-MitigationDetails{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$true)][string]$VulnerabilityName
  )
  $Tab = [char]9
  write-Message "Vulnerability Type: $($VulnerabilityName)"
  switch ($VulnerabilityName){
    "CVE-2021-44228" {
      Write-Message "Vulnerability Notice:$Tab https://nvd.nist.gov/vuln/detail/CVE-2021-44228#match-7275032"
      Write-Message "Vulnerability Guidance:$Tab https://github.com/cisagov/log4j-affected-db"
      Write-Message " " 0 1
      Write-Message "Detection/Mitigation Possible:$Tab Microsoft Defender Detection and More: https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/" 
      Write-Message "Mitigation Possible??:$Tab Detect and possilbe mitigation technique: https://www.deepwatch.com/blog/3-steps-to-detect-patch-log4j-log4shell-vulnerability/"
    }
  }
}
#endregion
#region Instructions/Detail
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
#endregion
#region MainBody
# .Vulnerability Retreival
#   Details Retreival
$VulnerableObjects = Get-VulnerabilityDetails $VulnerabilityDefinitionLocation $VulnerabilityDetectionStyle $VulnerabilityFilePattern
Write-Message ' '
write-Message "Retrieved $($VulnerableObjects.Count) Vulnerable Object Definitions"
Write-Message ' '
if ($VulnerableObjects.Count -gt 0){
  foreach($VulnerableObject in $VulnerableObjects){
    Write-Message "$($VulnerableObject)"
  }
} else {
  Write-Message "An Error Occured, No Definitions were found.  Exiting Program" 0 3
}
Write-Message ' '
# 4. Use Drive list passed in and then process scan list in loop manner.
# TODO: file directories exclusions to be added.
# .Location Scans
if ($SearchDriveArray.Count -gt 0){
  Write-Message ' '
  Write-Message "#########################################################################"
  Write-Message ' '
  $SearchedForVulnerabilityArray = Get-Vulnerabilities $ScanMachine $SearchDriveArray $RecursiveScans $VulnerabilityFilePattern 
  foreach($VulnerableHash in $SearchedForVulnerabilityArray){
    Write-Message "FileName and Location:$Tab$($VulnerableHash.FullName)$Tab-File HashValue:$Tab$($VulnerableHash.Hash)"
  }
  Write-Message ' '
  Write-Message "#########################################################################"
  Write-Message ' '

  # if we have found potential issues.  we can point at resources or even auto fix them, if there is a way.
  if ($SearchedForVulnerabilityArray.Count -gt 0){
    Get-MitigationDetails $script:VulnerabilityName
  }

}
# .End of Script
#endregion

