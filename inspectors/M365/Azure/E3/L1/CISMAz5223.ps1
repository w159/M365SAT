# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5223
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5223"
        ID               = "5.2.2.3"
        Title            = "(L1) Enable Conditional Access policies to block legacy authentication"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Policy, but basic authentication is disabled by default as of January 2023."
        ExpectedValue    = "A Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Legacy authentication protocols do not support modern security features like multi-factor authentication (MFA). Attackers often exploit these protocols due to their weaker security posture. Implementing Conditional Access policies to block legacy authentication mitigates this risk."
        Impact           = "Enabling this setting will prevent users from connecting with older versions of Office, ActiveSync or using protocols like IMAP, POP or SMTP and may require upgrades to older versions of Office, and use of mobile mail clients that support modern authentication. This will also cause multifunction devices such as printers from using scan to e-mail function if they are using a legacy authentication method."
        Remediation  	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
        References       = @(
            @{ 'Name' = 'Disable Basic authentication in Exchange Online'; 'URL' = 'https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online' },
            @{ 'Name' = 'Set up a multifunction device or application to send emails'; 'URL' = 'https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365' },
            @{ 'Name' = 'Deprecation of Basic authentication in Exchange Online'; 'URL' = 'https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5223
{
	try
	{
		# Actual Script
		$Violation = @()
		$OptimalPolicy = Get-MgIdentityConditionalAccessPolicy |  Where-Object { ($_.Conditions.Users.IncludeUsers -eq 'All') -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -and "other") -and $_.GrantControls.BuiltInControls -eq "block"}
		if ([string]::IsNullOrEmpty($OptimalPolicy))
		{
			$Violation += "No Conditional Access Policy (Correctly) Configured to block Legacy Authentication"
		}
		elseif ($OptimalPolicy.State -ne 'enabled') {
			$Violation += "Conditional Access Policy is Disabled or not Enforced"
		}
		else
		{
			$OptimalPolicy | Format-Table -AutoSize | Out-File "$path\CISMAz5223-Get-BlockLegacyAuthConditionalAccessPolicy.txt"
		}
		
		# Verify if Exchange does not have Legacy Auth enabled
		$AuthPolicy = Get-AuthenticationPolicy | Format-Table Name -Auto
		$AuthPolicy | Format-Table -AutoSize | Out-File "$path\CISMAz5223-Get-BlockLegacyAuthConditionalAccessPolicy.txt" -Append
		if ($AuthPolicy -contains $null)
		{
			$Violation += "No Conditional Access Policy (Correctly) Configured!"
		}
		else
		{
			$BasicAuthList = Get-AuthenticationPolicy | ForEach-Object { Get-AuthenticationPolicy $_.Name | Select-Object AllowBasicAuth* }
			foreach ($BasicAuthObj in $BasicAuthList)
			{
				if ($BasicAuthObj -ne $False)
				{
					$Violation += "$BasicAuthObj : False"
				}
			}
		}
		
		# Validation

		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISMAz5223 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5223 -ReturnedValue "A Conditional Access Policy (Correctly) Configured to block Legacy Authentication" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5223 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5223