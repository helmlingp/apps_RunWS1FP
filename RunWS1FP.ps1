<#	
  .Synopsis
    This powershell script runs the WS1 DropShip Provisioning Tool with a PPKG and UNATTEND.XML and runs SYSPREP before quiting, if the files exist. The tool will also copy an AutoPilotConfigurationFile.json and place in the C:\Windows\Provisioning\Autopilot folder if it exists.
    If $AutoPilotHash set to $true, will generate the AutoPilot hash file for manual device registration. Requires Get-WindowsAutopilotInfo. Run the following to download the latest version:
	Install-Script -Name Get-WindowsAutopilotInfo -Force
	
	For use with Microsoft Deployment Toolkit (MDT) as a Command Line Application.
  .NOTES
	  Created:   	    June, 2020
	  Updated:			November, 2023
	  Created by:	    Phil Helmling, @philhelmling
	  Organization:   	VMware, Inc.
	  Filename:       	RunWS1FP.ps1
	.DESCRIPTION
	  Runs Workspace ONE DropShip Provisioning Tool when used in a MDT Task Sequence
  .EXAMPLE
    powershell.exe -ep bypass -file .\RunWS1FP.ps1 -WindowStyle Hidden
	
  .EXAMPLE
    powershell.exe -ep bypass -file .\RunWS1FP.ps1 -WindowStyle Hidden -AutoPilotHash -AutoPilotPath "\\Server\Share$"
    Add the -AutoPilotHash option AND the -AutoPilotPath with path to capture the AutoPilot Hash of the machine to import into AutoPilot.
#>
param (
    [string]$AutoPilotPath,
    [bool]$AutoPilotHash
)
  
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = "C:\Temp";
}
function Copy-TargetResource {
  param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$File,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$FiletoCopy
  )

  if (!(Test-Path -LiteralPath $Path)) {
    try {
      New-Item -Path $Path -ItemType Directory -ErrorAction Stop | Out-Null #-Force
    }
    catch {
      Write-Error -Message "Unable to create directory '$Path'. Error was: $_" -ErrorAction Stop
    }
    "Successfully created directory '$Path'."
  }
  Write-Host "Copying $FiletoCopy to $Path\$File"
  Copy-Item -Path "$FiletoCopy" -Destination "$Path\$File" -Force
}

# Variables
$ws1fptool = "VMwareWS1ProvisioningTool.exe"
$AUTOAPPLY = "C:\Recovery\AutoApply"
$unattendfile = "unattend.xml"
$localunattend = "$AUTOAPPLY\$file"
$CustomPATH = "C:\Recovery\Customizations"
$localppkgfile = "$CustomPATH\$ppkgfile"
$AutoPilotPATH = "C:\Windows\Provisioning\Autopilot"
$AutoPilotFile = "AutoPilotConfigurationFile.json"

# Get PPKG and unattend.xml files
$ppkg = Get-ChildItem -Path $current_path -Include *.ppkg -Recurse -ErrorAction SilentlyContinue
$ppkgfile = $ppkg.Name
$unattend = Get-ChildItem -Path $current_path -Include *unattend*.xml -Recurse -ErrorAction SilentlyContinue
$AutoPilotConfigurationFile = Get-ChildItem -Path $current_path -Include $AutoPilotFile -Recurse -ErrorAction SilentlyContinue

# Copy unattend ready for Push Button Reset or Device Wipe with Provisioning Data
if($unattend){
	Copy-TargetResource -Path $AUTOAPPLY -File $unattendfile -FiletoCopy $unattend
}

# Copy PPKG ready for Push Button Reset or Device Wipe with Provisioning Data
if($ppkg){
	#Remove existing PPKG
	if(Test-Path -Path "$CustomPATH\$file"){		
		write-host "Removing existing PPKG"
		Remove-Item -Path $CustomPATH -Include *.ppkg* -Recurse -ErrorAction SilentlyContinue;
	}
	Copy-TargetResource -Path $CustomPATH -File $ppkgfile -FiletoCopy $ppkg
}

# Copy AutoPilotConfigurationFile.json
if($AutoPilotConfigurationFile){
	Copy-TargetResource -Path $AutoPilotPATH -File $AutoPilotFile -FiletoCopy $AutoPilotConfigurationFile
}

# Create AutoPilot Hash file to import into Intune/AutoPilot
if($AutoPilotHash){
	$SN = Get-WMIObject Win32_bios -ComputerName $env:computername -ea SilentlyContinue
	$SN = $SN.SerialNumber
	
	#Fix drive mapping
	New-PSDrive -Name "temp" -PSProvider "FileSystem" -Root $AutoPilotPath
	$autopilotdir = Get-Item -Path "temp:\"
	if(Test-Path -Path $autopilotdir){
		$OutputFile = "$autopilotdir$SN.csv" -replace '(^\s+|\s+$)','' -replace '\s+',''
		if(Test-Path -Path $OutputFile){
			Remove-Item -Path $OutputFile -Force
		}
		
		Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
		Start-Process -FilePath "$current_path\Get-WindowsAutopilotInfo.ps1" -ArgumentList "-OutputFile `"$OutputFile`""
	}
}

if($unattend -and $ppkg){
	# Run the WS1 Provisioning Tool and deploy apps and unattend
	#Start-Process -Filepath "$current_path\$ws1fptool" -ArgumentList "-a full -p `"$ppkg`" -u `"$unattend`" -q -g" -wait
	Start-Process -Filepath "$current_path\$ws1fptool" -ArgumentList "-a full -p `"$CustomPATH\$ppkgfile`" -u `"$AUTOAPPLY\$unattendfile`" -q -g" -wait
	
	#Move C:\Temp\PpkgInstaller\PpkgInstallerLog.txt & delete remnant folder
	Copy-TargetResource -Path "$env:ProgramData\Airwatch\UnifiedAgent\Logs" -File "PpkgInstallerLog.txt" -FiletoCopy "C:\Temp\PpkgInstaller\PpkgInstallerLog.txt"
}elseif(!$unattend -and $ppkg){
	# Run the WS1 Provisioning Tool and deploy apps only
	Start-Process -Filepath "$current_path\$ws1fptool" -ArgumentList "-a appsonly -p `"$CustomPATH\$ppkgfile`" -q -g" -wait
	
	# Run sysprep generalize
	Start-Process -FilePath "$env:WINDIR\system32\sysprep\sysprep.exe" -ArgumentList "/generalize /oobe /quit" -wait

	#Move C:\Temp\PpkgInstaller\PpkgInstallerLog.txt & delete remnant folder
	Copy-TargetResource -Path "$env:ProgramData\Airwatch\UnifiedAgent\Logs" -File "PpkgInstallerLog.txt" -FiletoCopy "C:\Temp\PpkgInstaller\PpkgInstallerLog.txt"
}elseif($unattend -and !$ppkg){
	# Run sysprep generalize with unattend.xml
	Start-Process -FilePath "$env:WINDIR\system32\sysprep\sysprep.exe" -ArgumentList "/generalize /oobe /quit /unattend:$AUTOAPPLY\$unattendfile" -wait
}else{
	# Run sysprep generalize only
	Start-Process -FilePath "$env:WINDIR\system32\sysprep\sysprep.exe" -ArgumentList "/generalize /oobe /quit" -wait
}
