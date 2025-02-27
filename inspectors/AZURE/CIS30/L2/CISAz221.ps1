# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz221
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz221"
        ID               = "2.2.1"
        Title            = "(L2) Ensure 'Trusted Locations' are defined and enabled as Trusted"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Defining trusted source IP addresses or ranges helps organizations enforce Conditional Access policies. Users authenticating from trusted IPs may have fewer access restrictions compared to users authenticating from untrusted locations, reducing the risk of unauthorized access."
        Impact           = "When configuring Named locations, the organization can create locations using Geographical location data or by defining source IP addresses or ranges. Configuring Named locations using a Country location does not provide the organization the ability to mark those locations as trusted, and any Conditional Access policy relying on those Countries location setting will not be able to use the All trusted locations setting within the Conditional Access policy. They instead will have to rely on the Select locations setting. This may add additional resource requirements when configuring and will require thorough organizational testing. In general, Conditional Access policies may completely prevent users from authenticating to Microsoft Entra ID, and thorough testing is recommended. To avoid complete lockout, a 'Break Glass' account with full Global Administrator rights is recommended in the event all other administrators are locked out of authenticating to Microsoft Entra ID. This 'Break Glass' account should be excluded from Conditional Access Policies and should be configured with the longest pass phrase feasible in addition to a FIDO2 security key or certificate kept in a very secure physical location. This account should only be used in the event of an emergency and complete administrator lockout."
        Remediation      = "Define and enable trusted locations in Conditional Access policies via Microsoft Entra admin portal or use the PowerShell script."
        References       = @(
            @{ 'Name' = 'Conditional Access: Network assignment'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network' },
            @{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' },
            @{ 'Name' = 'Manage emergency access accounts in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz221
{
	try
	{
		# Actual Script
		$NamedLocations = (Get-MgIdentityConditionalAccessNamedLocation).AdditionalProperties
		$NamedLocationInput = @()
		foreach ($Location in $NamedLocations)
		{
			$NamedLocationInput += "$($NamedLocations.ipRanges.cidrAddress): isTrusted: $($NamedLocations.isTrusted)"
		}
		
		# Validation
		if ($NamedLocationInput.count -igt 0)
		{
			$finalobject = Build-CISAz221 -ReturnedValue ($NamedLocationInput) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $finalobject
		}else {
			$finalobject = Build-CISAz221 -ReturnedValue ($NamedLocationInput) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $finalobject
		}
		return $null
	}
	catch
	{
		$finalobject = Build-CISAz221 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $finalobject
	}
}
return Audit-CISAz221