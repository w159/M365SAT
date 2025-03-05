function Invoke-M365SATLogger
{
	param(
		[string]$RootDirectory
	)
	
	if ($RootDirectory.Contains('\')){
		# Dirty-way of checking Windows
		Write-Host $RootDirectory
		Start-Logger -FilePath "$RootDirectory\log\$($DateNow)_M365SAT.log" -Console -MinimumLevel Warning
		Write-WarningLog "Program Started!"
	}
	elseif ($RootDirectory.Contains('/')) {
		# Dirty-way of checking Linux
		Write-Host $RootDirectory
		Start-Logger -FilePath "$RootDirectory/log/$($DateNow)_M365SAT.log" -Console -MinimumLevel Warning
		Write-WarningLog "Program Started!"
	}
}
