# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx631
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx631"
        ID               = "6.3.1"
        Title            = "(L2) Ensure users installing Outlook add-ins is not allowed"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "Users can Install Outlook Add-ins"
        ExpectedValue    = "Users cannot Install Outlook Add-ins"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing users to install Outlook add-ins without oversight can introduce vulnerabilities, as attackers may exploit these add-ins to gain access to sensitive data or execute malicious actions."
        Impact           = "Implementing this change will impact both end users and administrators. End users will be unable to integrate third-party applications they desire, and administrators may receive requests to grant permission for necessary third-party apps."
        Remediation	 	 = 'New-RoleAssignmentPolicy -Name "Restrict Add-ins" -Roles $revisedRoles'
        References       = @(
            @{ 'Name' = 'Specify who can install and manage add-ins for Outlook in Exchange Online'; 'URL' = "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/add-ins-for-outlook/specify-who-can-install-and-manage-add-ins?source=recommendations" },
            @{ 'Name' = 'Role assignment policies in Exchange Online'; 'URL' = "https://learn.microsoft.com/en-us/exchange/permissions-exo/role-assignment-policies" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx631
{
	try
	{
		$InstallationOutlookAddInsData = @()
		# $Policy = (Get-EXOMailbox | Select-Object -Unique RoleAssignmentPolicy | ForEach-Object { Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | Where-Object { $_.AssignedRoles -like "*Apps*" } } | Select-Object Identity, @{ Name = "AssignedRoles"; Expression = { Get-Mailbox | Select-Object -Unique RoleAssignmentPolicy | ForEach-Object { Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | Select-Object -ExpandProperty AssignedRoles | Where-Object { $_ -like "*Apps*" } } } })
		$Policy = (Get-Mailbox | Select-Object -Unique RoleAssignmentPolicy | ForEach-Object { Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | Where-Object { $_.AssignedRoles -like "*Apps*" } } | Select-Object Identity, @{ Name = "AssignedRoles"; Expression = { Get-Mailbox | Select-Object -Unique RoleAssignmentPolicy | ForEach-Object { Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | Select-Object -ExpandProperty AssignedRoles | Where-Object { $_ -like "*Apps*" } } } })
		foreach ($AssignedRole in $Policy.AssignedRoles)
		{
			if ($AssignedRole -match "My Custom Apps")
			{
				$InstallationOutlookAddInsData += "Policy contains My Custom Apps!"
			}
			if ($AssignedRole -match "My Marketplace Apps")
			{
				$InstallationOutlookAddInsData += "Policy contains My Marketplace Apps!"
			}
			if ($AssignedRole -match "My ReadWriteMailboxApps")
			{
				$InstallationOutlookAddInsData += "Policy contains My ReadWriteMailboxApps!"
			}
		}
		if ($InstallationOutlookAddInsData.Count -igt -0)
		{
			$InstallationOutlookAddInsData | Format-List | Out-File -FilePath "$path\CISMEx631-InstallationOutlookAddInsData.txt"
			$endobject = Build-CISMEx631 -ReturnedValue ($InstallationOutlookAddInsData) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx631 -ReturnedValue "Users cannot install Outlook Add-Ins" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx631 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx631