#Requires -module Az.Accounts
# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5235
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5235"
        ID               = "5.2.3.5"
        Title            = "(L1) Ensure weak authentication methods are disabled"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "SMS : Disabled \n Voice Call : Disabled \n Email OTP : Enabled"
        ExpectedValue    = "SMS : Disabled \n Voice Call : Disabled \n Email OTP : Disabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The SMS and Voice call methods are vulnerable to SIM swapping, which could allow an attacker to gain unauthorized access to Microsoft 365 accounts. Disabling these methods significantly reduces the risk of such attacks."
        Impact           = "Disabling Email OTP will prevent one-time pass codes from being sent to unverified guest users accessing Microsoft 365 resources on the tenant. They will be required to use a personal Microsoft account, a managed Microsoft Entra account, be part of a federation or be configured as a guest in the host tenant's Microsoft Entra ID."
        Remediation 	 = 'https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection'
        References       = @(
            @{ 'Name' = 'Manage authentication methods for Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage' },
            @{ 'Name' = 'Email one-time passcode authentication for B2B guest users'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/one-time-passcode' },
            @{ 'Name' = 'What is SIM swapping & how does the hijacking scam work?'; 'URL' = 'https://www.microsoft.com/en-us/microsoft-365-life-hacks/privacy-and-safety/what-is-sim-swapping' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5235
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$AuthenticationMethodPolicy = [PSCustomObject]@{}
		(Get-MgBetaPolicyAuthenticationMethodPolicy).AuthenticationMethodConfigurations | ForEach-Object {$AuthenticationMethodPolicy | Add-Member -NotePropertyName $_.Id -NotePropertyValue $_.State }
		# Validation
		if ($AuthenticationMethodPolicy.Sms -ne 'disabled')
		{
			$AffectedOptions += "Sms: $($AuthenticationMethodPolicy.Sms)"
		}
		if ($AuthenticationMethodPolicy.Voice -eq 'disabled')
		{
			$AffectedOptions += "Voice: $($AuthenticationMethodPolicy.Voice)"
		}
		if ($AuthenticationMethodPolicy.Email -eq 'disabled')
		{
			$AffectedOptions += "Email: $($AuthenticationMethodPolicy.Email)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$AffectedOptions | Format-Table -AutoSize | Out-File "$path\CISMAz5235-PasswordPolicy.txt"
			$endobject = Build-CISMAz5235 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5235 -ReturnedValue "All Settings are Enabled and correctly configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5235 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

return Audit-CISMAz5235