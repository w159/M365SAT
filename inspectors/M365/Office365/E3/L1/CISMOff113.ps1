# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff113
{
	param(
		$ReturnedValue,
		$Status,
		$RiskScore,
		$RiskRating
	)

	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		UUID			 = "CISMOff113"
		ID				 = "1.1.3"
		Title		     = "(L1) Ensure that between two and four global admins are designated"
		ProductFamily    = "Microsoft Office 365"
		DefaultValue	 = "1"
		ExpectedValue    = "Between 2 and 4"
		ReturnedValue    = $ReturnedValue
		Status			 = $Status
		RiskScore	     = $RiskScore
		RiskRating		 = $RiskRating
		Description	     = "If there is only one global tenant administrator, he or she can perform malicious activity without the possibility of being discovered by another admin. If there are numerous global tenant administrators, the more likely it is that one of their accounts will be successfully breached by an external attacker."
		Impact		     = "The potential impact associated with ensuring compliance with this requirement is dependent upon the current number of global administrators configured in the tenant. If there is only one global administrator in a tenant, an additional global administrator will need to be identified and configured. If there are more than four global administrators, a review of role requirements for current global administrators will be required to identify which of the users require global administrator access."
		Remediation		 = 'https://admin.microsoft.com/'
		References	     = @(@{ 'Name' = 'Manage emergency access accounts in Microsoft Entra ID'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access" },
			@{ 'Name' = 'Securing privileged access for hybrid and cloud deployments in Microsoft Entra ID'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning#stage-1-critical-items-to-do-right-now" })
	}
	return $inspectorobject
}

function Audit-CISMOff113
{
	Try
	{
		$global_admins = (Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").id | ForEach-Object { Get-MgDirectoryObjectById -Ids $_.id }).AdditionalProperties.userPrincipalName
		$num_global_admins = ($global_admins | Measure-Object).Count
		
		If ($num_global_admins -lt 2 -or $num_global_admins -igt 4)
		{
			$endobject = Build-CISMOff113 -ReturnedValue $num_global_admins -Status "FAIL" -RiskScore "12" -RiskRating "High"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMOff113 -ReturnedValue $num_global_admins -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		
	}
	catch
	{
		$endobject = Build-CISMOff113 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Audit-CISMOff113


