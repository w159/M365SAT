# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz534
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz534"
        ID               = "5.3.4"
        Title            = "(L1) Ensure approval is required for Global Administrator role activation"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, Require approval to activate is unchecked."
        ExpectedValue    = "Require approval to activate is checked."
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Requiring approval for Global Administrator role activation enhances visibility and accountability every time this highly privileged role is used. This process reduces the risk of an attacker elevating a compromised account to the highest privilege level, as any activation must first be reviewed and approved by a trusted party."
        Impact           = "Approvers do not need to be assigned the same role or be members of the same group. It's important to have at least two approvers and an emergency access (break-glass) account to prevent a scenario where no Global Administrators are available. For example, if the last active Global Administrator leaves the organization, and only eligible but inactive Global Administrators remain, a trusted approver without the Global Administrator role or an emergency access account would be essential to avoid delays in critical administrative tasks."
        Remediation  	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/Controls/fromNav/Identity'
        References       = @(
            @{ 'Name' = 'Create an access review of groups and applications in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-governance/create-access-review' },
            @{ 'Name' = 'What are access reviews?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview' }
        )
    }
    return $inspectorobject
}


function Audit-CISMAz534
{
	try
	{
        $Violation = @()
        $PrivilegedRoles = "62e90394-69f5-4237-9190-012177145e10" #Global Administrator Static Id

        $DirectoryId = (Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'Directory'" | where-object {$_.RoleDefinitionId -eq $PrivilegedRoles}).PolicyId
        $PIMRoleSetting = (Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $DirectoryId) | Where-Object {$_.Id -eq 'Approval_EndUser_Assignment'}
		# Actual Script
        if ($PIMRoleSetting.AdditionalProperties.setting.isApprovalRequired -ne $true){
            $Violation += "Approval is not required for Global Administrator Role"
        }
        if ($PIMRoleSetting.AdditionalProperties.setting.approvalStages.primaryApprovers.userId.count -ilt 2){
            $Violation += "Less than 2 approvers are assigned to Global Administrator Role"
        }
		
		# Validation
		if ($Violation.count -igt 0)
		{
			$AccessReviews | Format-Table -AutoSize | Out-File "$path\CISMAz534-AccessReviews.txt"
			$endobject = Build-CISMAz534 -ReturnedValue $Violation -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz534 -ReturnedValue "Access Reviews for Global Administrator Role is correctly configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz534 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz534