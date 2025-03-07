# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz2016
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz2016"
        ID               = "2.16"
        Title            = "(L2) Ensure that 'Guest invite restrictions' is set to 'Only users assigned to specific admin roles can invite guest users'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "everyone"
        ExpectedValue    = "adminsAndGuestInviters"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Restricting invitations to users with specific administrator roles ensures that only authorized accounts have access to cloud resources. This helps to maintain 'Need to Know' permissions and prevents inadvertent access to data. By default, the setting is 'Anyone in the organization can invite guest users', which allows anyone within the organization, including guests and non-admins, to invite new guests, posing a security risk."
        Impact           = "With the option of Only users assigned to specific admin roles can invite guest users selected, users with specific admin roles will be in charge of sending invitations to the external users, requiring additional overhead by them to manage user accounts. This will mean coordinating with other departments as they are onboarding new users."
        Remediation      = 'Use the following PowerShell script to restrict guest invitations to only authorized admins and guest inviters: Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom  "adminsAndGuestInviters"'
        References       = @(
            @{ 'Name' = 'Configure external collaboration settings'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure' },
            @{ 'Name' = 'PA-3: Manage lifecycle of identities and entitlements'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements' },
            @{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
            @{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz2016
{
	try
	{
		# Actual Script
		$Policy = Get-MgPolicyAuthorizationPolicy
		
		# Validation
		if ($Policy.AllowInvitesFrom -ne 'adminsAndGuestInviters')
		{
			$endobject = Build-CISAz2016 -ReturnedValue ($Policy.AllowInvitesFrom) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz2016 -ReturnedValue ($Policy.AllowInvitesFrom) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz2016 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz2016