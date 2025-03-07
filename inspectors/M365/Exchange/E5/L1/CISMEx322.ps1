# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx322
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx322"
        ID               = "3.2.2"
        Title            = "(L1) Ensure DLP policies are enabled for Microsoft Teams"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "All Policies State: Enable"
        ExpectedValue    = "All Policies State: Enable"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling Data Loss Prevention (DLP) policies for Microsoft Teams helps to safeguard sensitive information by preventing unintentional sharing or exposure within Teams conversations and channels. DLP policies are crucial for maintaining the confidentiality of organizational data, reducing the risk of data leakage."
        Impact           = "End-users may be prevented from sharing certain types of content, which may require them to adjust their behavior or seek permission from administrators to share specific content. Administrators may receive requests from end-users for permission to share certain types of content or to modify the policy to better fit the needs of their teams."
        Remediation		 = 'New-DlpCompliancePolicy -Name "SSN Teams Policy" -Comment "SSN Teams Policy" -TeamsLocation All -Mode Enable'
        References       = @(
            @{ 'Name' = 'Learn about data loss prevention'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/dlp-learn-about-dlp?view=o365-worldwide" },
            @{ 'Name' = 'Create, test, and tune a DLP policy'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/create-test-tune-dlp-policy?view=o365-worldwide" }
        )
    }
    return $inspectorobject
}

Function Audit-CISMEx322
{
	Try
	{
		try
		{
			$dlpPolicies = Get-DlpCompliancePolicy | Where-Object { $_.Mode -notlike "Enable" }
			
			$policies = @()
			$IncorrectDLPPolicy = 0
			if (-not [string]::IsNullOrEmpty($dlpPolicies))
			{
				foreach ($policy in $dlpPolicies)
				{
					$policies += "$($policy.Name) state is $($policy.mode)"
					$Validate = Get-DlpCompliancePolicy -Identity $policy.Name | Select-Object TeamsLocation*
					if ($Validate.count -eq 0 -or $Validate.TeamsLocation -eq 0 -or $Validate.TeamsLocationException -igt 0)
					{
						$IncorrectDLPPolicy++
					}
				}
			}
			else{
				$dlpPolicies = (Get-DlpCompliancePolicy | Where-Object { $_.Mode -like "Enable" }).Count
			}
			If ($IncorrectDLPPolicy -igt 0)
			{
				$dlpPolicies | Format-Table -AutoSize | Out-File "$path\CISMEx322-DLPCompliancePolicy.txt"
				$endobject = Build-CISMEx322 -ReturnedValue $policies -Status "FAIL" -RiskScore "2" -RiskRating "Low"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMEx322 -ReturnedValue $dlpPolicies -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
			
		}
		catch
		{
			$endobject = Build-CISMEx322 -ReturnedValue "No DLP Compliance Policy" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
			return $endobject
		}
		
		
	}
	catch
	{
		$endobject = Build-CISMEx322 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}
return Audit-CISMEx322