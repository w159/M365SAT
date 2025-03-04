# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5162
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5162"
        ID               = "5.1.6.2"
        Title            = "(L1) Ensure that guest user access is restricted"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "PowerShell: 10dae51f-b6af-4016-8d66-8c2a99b929b3"
        ExpectedValue    = "PowerShell: 10dae51f-b6af-4016-8d66-8c2a99b929b3 or 2af84b1e-32c8-42b7-82bc-daa82404023b"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "By limiting guest access to the most restrictive state, you prevent malicious actors from conducting reconnaissance (the first step in the Cyber Kill Chain), reducing the likelihood of a successful targeted attack on your Microsoft 365 environment."
        Impact           = "Failure to restrict guest user access could lead to unauthorized enumeration of groups and objects, increasing the risk of advanced targeted attacks."
        Remediation	 	 = 'Update-MgPolicyAuthorizationPolicy -GuestUserRoleId "10dae51f-b6af-4016-8d66-8c2a99b929b3" or Update-MgPolicyAuthorizationPolicy -GuestUserRoleId "2af84b1e-32c8-42b7-82bc-daa82404023b"'
        References       = @(
            @{ 'Name' = 'Restrict guest access permissions in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions' },
            @{ 'Name' = 'The Cyber Kill Chain'; 'URL' = 'https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5162
{
	try
	{
		# Actual Script
		$AuthPolicy = Get-MgPolicyAuthorizationPolicy
		
		
		# Validation
		if ($AuthPolicy.GuestUserRoleId -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970')
		{
			$AuthPolicy | Format-List | Out-File "$path\CISMAz5162-AuthorizationPolicy.txt"
			$endobject = Build-CISMAz5162 -ReturnedValue ($AuthPolicy.GuestUserRoleId) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5162 -ReturnedValue ($AuthPolicy.GuestUserRoleId) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5162 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5162