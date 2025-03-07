# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMAz52210
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz52210"
        ID               = "5.2.2.10"
        Title            = "(L1) Ensure a managed device is required for authentication"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A Correctly Configured Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Managed devices provide enhanced security through configuration hardening, centralized management, and monitoring tools like Intune or Group Policy. Enforcing this policy ensures users can only authenticate using trusted devices, significantly reducing risks posed by compromised credentials."
        Impact           = "Unmanaged devices will not be permitted as a valid authenticator. As a result this may require the organization to mature their device enrollment and management."
        Remediation = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
        References       = @(
            @{ 'Name' = 'Require device to be marked as compliant'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant' },
            @{ 'Name' = 'Microsoft Entra hybrid joined devices'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/devices/concept-hybrid-join' },
            @{ 'Name' = 'Enrollment guide: Microsoft Intune enrollment'; 'URL' = 'https://learn.microsoft.com/en-us/mem/intune/fundamentals/deployment-guide-enrollment' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz52210
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {($_.Conditions.Users.IncludeUsers -eq "All") -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.GrantControls.BuiltInControls -contains "compliantDevice" -and $_.GrantControls.BuiltInControls -contains "domainJoinedDevice") -and $Policy.GrantControls.Operator -eq "OR"}
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz52210-CompliantDevicesConditionalAccessPolicy.txt"
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
			$endobject = Build-CISMAz52210 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz52210 -ReturnedValue "Conditional Access Policy is Correctly Configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz52210 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz52210