function Invoke-M365SATLogger
{
	param(
		[string]$RootDirectory,
		[string]$OS
	)
	
	if ($RootDirectory.Contains('\')){
		Write-Host $RootDirectory
		Start-Logger -FilePath "$RootDirectory\log\$($DateNow)_M365SAT.log" -Console -MinimumLevel Warning
		Write-WarningLog "Program Started!"
	}
	elseif ($RootDirectory.Contains('/')) {
		Write-Host $RootDirectory
		Start-Logger -FilePath "$RootDirectory/log/$($DateNow)_M365SAT.log" -Console -MinimumLevel Warning
		Write-WarningLog "Program Started!"
	}
}
