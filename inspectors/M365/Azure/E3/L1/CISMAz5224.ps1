# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5224
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5224"
        ID               = "5.2.2.4"
        Title            = "(L1) Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Policy, default sign-in frequency is a rolling window of 90 days"
        ExpectedValue    = "persistentBrowserMode: never, isEnabled: true, signInFrequencyValue: between 4 and 24 hours, clientAppTypes: All, applicationsIncludeApplications: All"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Forcing a timeout for multi-factor authentication (MFA) and ensuring that browser sessions are not persistent enhances security. It prevents long-lived session cookies and mitigates the risk of drive-by attacks or session hijacking in web browsers."
        Impact           = "Users with Administrative roles will be prompted at the frequency set for MFA."
        Remediation      = "Configure a Conditional Access policy in the Azure portal's Conditional Access blade to enforce sign-in frequency and prevent persistent browser sessions."
        PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
        References       = @(
            @{ 'Name' = 'Configure adaptive session lifetime policies'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5224
{
	try
	{
		# Actual Script
		$Violation = @()
		$DirectoryRoles = Get-MgRoleManagementDirectoryRoleDefinition
		$PrivilegedRoles = ($DirectoryRoles | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader"}).TemplateId
		# This are the administrator roles and members that should be added to this policy

		# Here we should determine if the tenant is an E3 or E5 tenant. 
		$SignInFrequencyValue = 4

		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {((-not ($PrivilegedRoles | Compare-Object $_.Conditions.Users.IncludeRoles) -as [bool]) -eq $true) -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.SessionControls.SignInFrequency.IsEnabled -eq $true -and $_.SessionControls.SignInFrequency.Type -eq 'hours' -and $_.SessionControls.SignInFrequency.Value -ile $SignInFrequencyValue) -and $_.SessionControls.PersistentBrowser.IsEnabled -eq $true -and $_.SessionControls.PersistentBrowser.Mode -eq 'never'}
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz5224-SignInFrequencyConditionalAccessPolicy.txt"
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
			$endobject = Build-CISMAz5224 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5224 -ReturnedValue "Conditional Access Policy is Correctly Configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5224 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5224