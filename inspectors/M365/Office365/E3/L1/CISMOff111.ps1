# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff111
{
	param(
		$ReturnedValue,
		$Status,
		$RiskScore,
		$RiskRating
	)
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		UUID			 = "CISMOff111"
		ID				 = "1.1.1"
		Title		     = "(L1) Ensure Administrative accounts are separate and cloud-only"
		ProductFamily    = "Microsoft Office 365"
		DefaultValue	 = "-"
		ExpectedValue    = "0"
		ReturnedValue    = $ReturnedValue
		Status			 = $Status
		RiskScore	     = $RiskScore
		RiskRating		 = $RiskRating
		Description	     = "In a hybrid environment, having separate accounts will help ensure that in the event of a breach in the cloud, that the breach does not affect the on-prem environment and vice versa."
		Impact			 = "Administrative users will have to switch accounts and utilizing login/logout functionality when performing administrative tasks, as well as not benefiting from SSO. This will require a migration process from the 'daily driver' account to a dedicated admin account. When migrating permissions to the admin account, both M365 and Azure RBAC roles should be migrated as well. Once the new admin accounts are created both of these permission sets should be moved from the daily driver account to the new admin account. Failure to migrate Azure RBAC roles can cause an admin to not be able to see their subscriptions/resources while using their admin accounts."
		Remediation		 = 'https://admin.microsoft.com/'
		References	     = @(@{ 'Name' = 'Add users and assign licenses at the same time'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/add-users?view=o365-worldwide" },
		@{ 'Name' = 'Step 2. Protect your Microsoft 365 privileged accounts'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/enterprise/protect-your-global-administrator-accounts?view=o365-worldwide" },
		@{ 'Name' = 'Use cloud native accounts for Microsoft Entra roles'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices#9-use-cloud-native-accounts-for-microsoft-entra-roles" },
		@{ 'Name' = 'What is Microsoft Entra ID?'; 'URL' = "https://learn.microsoft.com/en-us/entra/fundamentals/whatis" },
		@{ 'Name' = 'Microsoft Entra built-in roles'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference" })
	}
	return $inspectorobject
}

function Audit-CISMOff111
{
	try
	{
		$DirectoryRoles = Get-MgDirectoryRole
		$PrivilegedRoles = $DirectoryRoles | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader"}
		$RoleMembers = $PrivilegedRoles | ForEach-Object { Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id } | Select-Object Id -Unique
		$PrivilegedUsers = $RoleMembers | ForEach-Object { Get-MgUser -UserId $_.Id -Property UserPrincipalName, DisplayName, Id, OnPremisesSyncEnabled }
		$NonCloudMFAAdmins = $PrivilegedUsers | Where-Object { $_.OnPremisesSyncEnabled -eq $true } | Select-Object DisplayName,UserPrincipalName,OnPremisesSyncEnabled
		if ($NonCloudMFAAdmins.Count -igt 0)
		{
			$endobject = Build-CISMOff111 -ReturnedValue $NonCloudMFAAdmins.Count -Status "FAIL" -RiskScore "12" -RiskRating "High"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMOff111 -ReturnedValue $NonCloudMFAAdmins.Count -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISMOff111 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		Return $endobject
	}
}

return Audit-CISMOff111