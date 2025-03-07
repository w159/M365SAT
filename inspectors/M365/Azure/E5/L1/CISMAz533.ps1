# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz533
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz533"
        ID               = "5.3.3"
        Title            = "(L1) Ensure 'Access reviews' for privileged roles are configured"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, access reviews are not configured."
        ExpectedValue    = "A Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Regular review of critical high privileged roles in Entra ID will help identify role drift, or potential malicious activity. This will enable the practice and application of 'separation of duties' where even non-privileged users like security auditors can be assigned to review assigned roles in an organization. Furthermore, if configured these reviews can enable a fail-closed mechanism to remove access to the subject if the reviewer does not respond to the review."
        Impact           = "Access reviews that are ignored may cause guest users to lose access to resources temporarily."
        Remediation  	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/Controls/fromNav/Identity'
        References       = @(
            @{ 'Name' = 'Create an access review of groups and applications in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-governance/create-access-review' },
            @{ 'Name' = 'What are access reviews?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview' }
        )
    }
    return $inspectorobject
}


function Audit-CISMAz533
{
	try
	{
        $Violation = @()
        $PrivilegedRoles = @("f28a1f50-f6e7-4571-818b-6a12f2af6b6c","29232cdf-9323-42fd-ade2-1d097af3e4de","62e90394-69f5-4237-9190-012177145e10","69091246-20e8-4a56-aa4d-066075b2a7a8","194ae4cb-b126-40b2-bd5b-6091b380977d")
		# Actual Script
        foreach ($role in $PrivilegedRoles){
            $AccessReviews = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions") | Where-Object { $_.value.scope.resourceScopes.query -match $role}
            if ([string]::IsNullOrEmpty($AccessReviews)){
                $Violation += "Role: $($role) is missing Access Review"
            }
        }
		
		# Validation
		if ($Violation.count -igt 0)
		{
			$AccessReviews | Format-Table -AutoSize | Out-File "$path\CISMAz533-AccessReviews.txt"
			$endobject = Build-CISMAz533 -ReturnedValue "Access Reviews is not configured!" -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz533 -ReturnedValue "Access Reviews is configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz533 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz533