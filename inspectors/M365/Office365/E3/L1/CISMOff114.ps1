# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff114
{
	param(
		$ReturnedValue,
		$Status,
		$RiskScore,
		$RiskRating
	)
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		UUID			 = "CISMOff114"
		ID				 = "1.1.4"
		Title		     = "(L1) Ensure administrative accounts use licenses with a reduced application footprint"
		ProductFamily    = "Microsoft Office 365"
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $ReturnedValue
		Status			 = $Status
		RiskScore	     = $RiskScore
		RiskRating		 = $RiskRating
		Description	     = "Ensuring administrative accounts do not use licenses with applications assigned to them will reduce the attack surface of high privileged identities in the organization's environment. Granting access to a mailbox or other collaborative tools increases the likelihood that privileged users might interact with these applications, raising the risk of exposure to social engineering attacks or malicious content. These activities should be restricted to an unprivileged 'daily driver' account."
		Impact		     = "Administrative users will have to switch accounts and utilize login/logout functionality when performing administrative tasks, as well as not benefiting from SSO."
		Remediation		 = 'https://admin.microsoft.com/'
		References	     = @(@{ 'Name' = 'Add users and assign licenses at the same time'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/add-users?view=o365-worldwide" },
		@{ 'Name' = 'Step 2. Protect your Microsoft 365 privileged accounts'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/enterprise/protect-your-global-administrator-accounts?view=o365-worldwide" },
		@{ 'Name' = 'Use cloud native accounts for Microsoft Entra roles'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices#9-use-cloud-native-accounts-for-microsoft-entra-roles" },
		@{ 'Name' = 'What is Microsoft Entra ID?'; 'URL' = "https://learn.microsoft.com/en-us/entra/fundamentals/whatis" },
		@{ 'Name' = 'Microsoft Entra built-in roles'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference" })
	}
	return $inspectorobject
}

function Audit-CISMOff114
{
	Try
	{
		$DirectoryRoles = Get-MgDirectoryRole
		$PrivilegedRoles = $DirectoryRoles | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader" }
		$RoleMembers = $PrivilegedRoles | ForEach-Object { Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id } | Select-Object Id -Unique
		$PrivilegedUsers = $RoleMembers | ForEach-Object { Get-MgUser -UserId $_.Id -Property UserPrincipalName, DisplayName, Id }
		$Report = [System.Collections.Generic.List[Object]]::new()
		foreach ($Admin in $PrivilegedUsers) {
			$License = $null
			$License = (Get-MgUserLicenseDetail -UserId $Admin.Id).SkuPartNumber -join ", "
			$Object = [PSCustomObject][ordered]@{
				DisplayName = $Admin.DisplayName
				UserPrincipalName = $Admin.UserPrincipalName
				License = $License
			}
			if ($Object.License.Count -igt 0){
				$Report.Add($Object)
			}
		}

		
		If ($Report.Count -igt 0)
		{
			$Report | Format-Table -AutoSize UserPrincipalName, UserType | Out-File "$path\CISMOff114-AdministrativeAccountsReport.txt"
			$endobject = Build-CISMOff114 -ReturnedValue $Report.Count -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMOff114 -ReturnedValue $Report.Count -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		
	}
	catch
	{
		$endobject = Build-CISMOff114 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Audit-CISMOff114


