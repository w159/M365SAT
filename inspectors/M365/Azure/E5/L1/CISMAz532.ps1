# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz532
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz532"
        ID               = "5.3.2"
        Title            = "(L1) Ensure 'Access reviews' for Guest Users are configured"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, access reviews are not configured."
        ExpectedValue    = "A Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Access to groups and applications for guest users can change over time. If a guest user's access goes unnoticed, they may unintentionally gain access to sensitive data as new files are added. Access reviews can mitigate this risk by periodically requiring a review of access permissions, ensuring outdated assignments are removed, and offering a fail-closed mechanism for non-responsive reviewers."
        Impact           = "Access reviews that are ignored may cause guest users to lose access to resources temporarily."
        Remediation  	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/Controls/fromNav/Identity'
        References       = @(
            @{ 'Name' = 'Create an access review of groups and applications in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-governance/create-access-review' },
            @{ 'Name' = 'What are access reviews?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview' }
        )
    }
    return $inspectorobject
}


function Audit-CISMAz532
{
	try
	{
		# Actual Script
		$AccessReviews = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions") | Where-Object { $_.value.scope.query -match 'Guest'}
		
		# Validation
		if ([string]::IsNullOrEmpty($AccessReviews))
		{
			$AccessReviews | Format-Table -AutoSize | Out-File "$path\CISMAz532-AccessReviews.txt"
			$endobject = Build-CISMAz532 -ReturnedValue "Access Reviews is not configured!" -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz532 -ReturnedValue "Access Reviews is configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz532 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz532