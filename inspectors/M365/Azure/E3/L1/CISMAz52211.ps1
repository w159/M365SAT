# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMAz52211
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz52211"
        ID               = "5.2.2.11"
        Title            = "(L1) Ensure a managed device is required for MFA registration"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A Correctly Configured Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Requiring registration on a managed device significantly reduces the risk of bad actors using stolen credentials to register security information. Accounts that are created but never registered with an MFA method are particularly vulnerable to this type of attack. Enforcing this requirement reduces the attack surface for fake registrations and ensures legitimate users register using trusted devices with additional security measures."
        Impact           = "The organization will be required to have a mature device management process. New devices provided to users will need to be pre-enrolled in Intune, auto-enrolled or be Entra hybrid joined. Otherwise, the user will be unable to complete registration, requiring additional resources from I.T. This could be more disruptive in remote worker environments where the MDM maturity is low. In these cases where the person enrolling in MFA (enrollee) doesn't have physical access to a managed device, a help desk process can be created using a Teams meeting to complete enrollment using: 1) a durable process to verify the enrollee's identity including government identification with a photograph held up to the camera, information only the enrollee should know, and verification by the enrollee's direct manager in the same meeting; 2) complete enrollment in the same Teams meeting with the enrollee being granted screen and keyboard access to the help desk person's InPrivate Edge browser session."
        Remediation = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
        References       = @(
            @{ 'Name' = 'Require device to be marked as compliant'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant' },
            @{ 'Name' = 'Microsoft Entra hybrid joined devices'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/devices/concept-hybrid-join' },
            @{ 'Name' = 'Enrollment guide: Microsoft Intune enrollment'; 'URL' = 'https://learn.microsoft.com/en-us/mem/intune/fundamentals/deployment-guide-enrollment' },
            @{ 'Name' = 'User actions'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#user-actions' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz52211
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {($_.Conditions.Users.IncludeUsers -eq "All") -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeUserActions -eq 'urn:user:registersecurityinfo') -and ($_.GrantControls.BuiltInControls -contains "domainJoinedDevice") -and $Policy.GrantControls.Operator -eq "OR"}
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz52211-CompliantDevicesConditionalAccessPolicy.txt"
		if ($PolicyExistence.Count -ne 0)
		{
			foreach ($Policy in $PolicyExistence)
			{
				if ($Policy.State -eq "disabled")
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
			$endobject = Build-CISMAz52211 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz52211 -ReturnedValue "Conditional Access Policy is Correctly Configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz52211 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz52211