# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5225
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5225"
        ID               = "5.2.2.5"
        Title            = "(L2) Ensure 'Phishing-resistant MFA strength' is required for Administrators"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A policy enforcing phishing-resistant MFA for all administrative roles"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "As MFA usage becomes more widespread, attackers increasingly target it. Phishing-resistant MFA methods, such as FIDO2 security keys, certificate-based authentication, or Windows Hello for Business, offer robust protection by eliminating passwords and using public/private key exchanges between trusted devices and identity providers."
        Impact           = "If administrators aren't pre-registered for a strong authentication method prior to a conditional access policy being created, then a condition could occur where a user can't register for strong authentication because they don't meet the conditional access policy requirements and therefore are prevented from signing in. Additionally, Internet Explorer based credential prompts in PowerShell do not support prompting for a security key. Implementing phishing-resistant MFA with a security key may prevent admins from running their existing sets of PowerShell scripts. Device Authorization Grant Flow can be used as a workaround in some instances."
        Remediation 	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
        References       = @(
            @{ 'Name' = 'Passwordless authentication options for Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless#fido2-security-keys' },
            @{ 'Name' = 'Enable passwordless security key sign-in'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key' },
            @{ 'Name' = 'Conditional Access authentication strength'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless#fido2-security-keys' },
            @{ 'Name' = 'How To: Configure the Microsoft Entra multifactor authentication registration policy'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-mfa-policy' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5225
{
	try
	{
		# Actual Script
		$Violation = @()
		# Actual Script
		$DirectoryRoles = Get-MgRoleManagementDirectoryRoleDefinition
		$PrivilegedRoles = ($DirectoryRoles | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader"}).TemplateId

		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {((-not ($PrivilegedRoles | Compare-Object $_.Conditions.Users.IncludeRoles) -as [bool]) -eq $true) -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and $_.GrantControls.AuthenticationStrength.Id -eq '00000000-0000-0000-0000-000000000004' -and $_.GrantControls.authenticationStrength.requirementsSatisfied -eq 'mfa'}
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz5225-PhishingResistantConditionalAccessPolicy.txt"
		if ($PolicyExistence.Count -ne 0)
		{
			foreach ($Policy in $PolicyExistence)
			{
				if ($Policy.State -ne "enabled")
				{
					$Violation += $Policy.Id
				}
			}
		}
		else
		{
			$Violation += "No Conditional Access Policy (Correctly) Configured!"
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISMAz5225 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5225 -ReturnedValue "Conditional Access Policy is Correctly Configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5225 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5225