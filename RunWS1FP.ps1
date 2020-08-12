<#	
  .Synopsis
    This powershell script runs the WS1 Factory Provisioning Tool with a PPKG and UNATTEND.XML
    and runs SYSPREP then quits.
    For use with Microsoft Deployment Toolkit (MDT) as a Command Line Application.
  .NOTES
	  Created:   	    June, 2020
	  Created by:	    Phil Helmling, @philhelmling
	  Organization:   VMware, Inc.
	  Filename:       RunWS1FP.ps1
	.DESCRIPTION
	  Runs Workspace ONE Factory Provisioning Tool when used in a MDT Task Sequence
  .EXAMPLE
    powershell.exe -ep bypass -file .\RunWS1FP.ps1
#>

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = "C:\Temp";
}

$ppkg = Get-ChildItem -Path $current_path -Include *.ppkg* -Recurse -ErrorAction SilentlyContinue
$unattend = Get-ChildItem -Path $current_path -Include *.xml* -Recurse -ErrorAction SilentlyContinue

$ws1fptool = "VMwareWS1ProvisioningTool.exe"
Start-Process -filepath $current_path\$ws1fptool -ArgumentList "-a full -p `"$ppkg`" -u `"$unattend`" -q -g" -wait

#Move C:\Temp\PpkgInstaller\PpkgInstallerLog.txt & delete remnant folder
Copy-Item -Path "C:\Temp\PpkgInstaller\PpkgInstallerLog.txt" -Destination "$env:ProgramData\Airwatch\UnifiedAgent\Logs\PpkgInstallerLog.txt"
Remove-Item -Path "C:\Temp" -Recurse -Force

#Create Autopilot directory and get device serial number to create file if running this manually and in conjunction with autopilot.
<#$autopilotdir = Get-Item -Path "$current_path\Autopilot"
if (!$autopilotdir) {
  New-Item -Path "$current_path\Autopilot" -ItemType Directory
}
$SN = Get-WMIObject Win32_bios -ComputerName $env:computername -ea SilentlyContinue
$SN = $SN.SerialNumber
Invoke-Expression "& `"$current_path\Get-WindowsAutoPilotInfo.ps1`" -OutputFile D:\Autopilot\$SN.csv"#>
