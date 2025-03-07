# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz2025
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz2025"
        ID               = "2.25"
        Title            = "(L2) Ensure That 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering Microsoft Entra tenant' Is Set To 'Permit no one'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "False (Access granted to Everyone)"
        ExpectedValue    = "True (Restricted to Admins)"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Permissions to move subscriptions in and out of a Microsoft Entra tenant must only be granted to appropriate administrative personnel. If unrestricted, a subscription could be moved into a Microsoft Entra tenant where other users have elevated permissions, increasing the risk of unauthorized modifications or data loss."
        Impact           = "Subscriptions will need to have these settings turned off to be moved."
        Remediation      = "To restrict subscription movement ensure 'Subscription leaving Microsoft Entra tenant and Subscription entering Microsoft Entra tenant' are set to 'Permit no one' here: https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade"
        References       = @(
            @{ 'Name' = 'Manage Azure subscription policies'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/manage-azure-subscription-policy' },
            @{ 'Name' = 'Associate or add an Azure subscription to your Microsoft Entra tenant'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/how-subscriptions-associated-directory' },
            @{ 'Name' = 'IM-2: Protect identity and authentication systems'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-2-protect-identity-and-authentication-systems' }
        )
    }
    return $inspectorobject
}
#10high

function Audit-CISAz2025
{
	try
	{
		$SubscriptionSettings = @()
		# Actual Script
		$Setting1 = ((Invoke-AzRestMethod -Method GET -Path '/providers/Microsoft.Subscription/policies/default?api-version=2021-01-01-privatepreview').content | ConvertFrom-Json | Select-Object properties).properties.blockSubscriptionsLeavingTenant
		$Setting2 = ((Invoke-AzRestMethod -Method GET -Path '/providers/Microsoft.Subscription/policies/default?api-version=2021-01-01-privatepreview').content | ConvertFrom-Json | Select-Object properties).properties.blockSubscriptionsIntoTenant
		
		if ($Setting1 -eq $false)
		{
			$SubscriptionSettings += "blockSubscriptionsLeavingTenant: $($Setting1)"
		}
		if ($Setting2 -eq $false)
		{
			$SubscriptionSettings += "blockSubscriptionsIntoTenant: $($Setting2)"
		}
		
		if ($SubscriptionSettings.Count -igt 0)
		{
			$endobject = Build-CISAz2025 -ReturnedValue ($SubscriptionSettings) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz2025 -ReturnedValue ("blockSubscriptionsLeavingTenant: $($Setting1) blockSubscriptionsIntoTenant: $($Setting2)") -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz2025 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz2025