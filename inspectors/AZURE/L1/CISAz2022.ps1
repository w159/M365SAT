# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz2022
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz2022"
        ID               = "2.22"
        Title            = "(L1) Ensure that 'Require Multifactor Authentication to register or join devices with Microsoft Entra' is set to 'Yes'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "0 (No)"
        ExpectedValue    = "1 (Yes)"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Multi-Factor Authentication (MFA) should be required when users register or join devices to Microsoft Entra ID. Without MFA, a compromised user account could be used to enroll rogue devices, potentially leading to security breaches."
        Impact           = "A slight impact of additional overhead, as Administrators will now have to approve every access to the domain."
        Remediation      = "To enforce MFA for device registration. Make sure that under Microsoft Entra join and registration settings, the 'Require Multifactor Authentication to register or join devices' with Microsoft Entra is set to 'Yes': https://portal.azure.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings/menuId~/null"
        References       = @(
            @{ 'Name' = 'Azure MFA for Enrollment in Intune and Azure AD Device registration explained'; 'URL' = 'https://learn.microsoft.com/en-us/archive/blogs/janketil/azure-mfa-for-enrollment-in-intune-and-azure-ad-device-registration-explained' },
            @{ 'Name' = 'IM-6: Use strong authentication controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-6-use-strong-authentication-controls' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz2022
{
	try
	{
		$AffectedObject = @()
		# Actual Script
		$DeviceRegistrationPolicy = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy")
		
		# Validation
		if ($DeviceRegistrationPolicy.multiFactorAuthConfiguration -eq 0)
		{
			$endobject = Build-CISAz2022 -ReturnedValue ("multiFactorAuthConfiguration: $($DeviceRegistrationPolicy.multiFactorAuthConfiguration)") -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz2022 -ReturnedValue ($DeviceRegistrationPolicy.multiFactorAuthConfiguration) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz2022 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz2022