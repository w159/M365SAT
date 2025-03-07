# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5151
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5151"
        ID               = "5.1.5.1"
        Title            = "(L2) Ensure user consent to apps accessing company data on their behalf is not allowed"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "UI - Allow user consent for apps"
        ExpectedValue    = "UI - Do not allow user consent"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Attackers may leverage custom applications to deceive users into granting access to sensitive company data. Disabling user consent for apps limits this risk, requiring all future consent actions to be conducted by administrators, thereby decreasing the attack surface."
        Impact           = "If user consent is disabled, previous consent grants will still be honored but all future consent operations must be performed by an administrator. Tenant-wide admin consent can be requested by users through an integrated administrator consent request workflow or through organizational support processes."
        Remediation 	 = '$params = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } }; Update-MgPolicyAuthorizationPolicy -BodyParameter $params'
        References       = @(
            @{ 'Name' = 'Configure how users consent to applications'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent?tabs=azure-portal&pivots=portal' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5151
{
	try
	{
		# Actual Script
		$UserConsentSetting = (Get-MgPolicyAuthorizationPolicy -Property "defaultUserRolePermissions").DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
		
		# Validation
		if (-not [string]::IsNullOrEmpty($UserConsentSetting) -and $UserConsentSetting -eq "ManagePermissionGrantsForSelf.microsoft-user-default-low")
		{
			$UserConsentSetting | Format-Table -AutoSize | Out-File "$path\CISMAz5151-Get-MgPolicyAuthorizationPolicy.txt"
			$endobject = Build-CISMAz5151 -ReturnedValue ($UserConsentSetting) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5151 -ReturnedValue ($UserConsentSetting) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5151 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5151