# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz214
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz214"
        ID               = "2.1.4"
        Title            = "(L1) Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Disabled"
        ExpectedValue    = "Disabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Remembering Multi-Factor Authentication (MFA) for devices and browsers allows users to bypass MFA for a set number of days after a successful sign-in. While this can enhance usability, it poses a security risk if an account or device is compromised. Disabling this feature ensures that MFA is always required, increasing authentication security."
        Impact           = "For every login attempt, the user will be required to perform multi-factor authentication."
        Remediation      = "Disable the 'Remember Multi-Factor Authentication' setting via the Microsoft Entra admin portal."
        References       = @(
            @{ 'Name' = 'Configure Microsoft Entra multifactor authentication settings'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings#remember-multi-factor-authentication-for-devices-that-users-trust' },
            @{ 'Name' = 'IM-6: Use strong authentication controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-6-use-strong-authentication-controls' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz214
{
	try
	{
		
		$finalobject = Build-CISAz214 -ReturnedValue ("Check the value here: https://account.activedirectory.windowsazure.com/UserManagement/MfaSettings.aspx") -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN" 
		return $finalobject
	}
	catch
	{
		$finalobject = Build-CISAz214 -ReturnedValue ("Check the value here: https://account.activedirectory.windowsazure.com/UserManagement/MfaSettings.aspx") -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN" 
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $finalobject
	}
}
return Audit-CISAz214