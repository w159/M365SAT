# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz31010
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz31010"
        ID               = "3.1.10"
        Title            = "(L1) Ensure that Microsoft Defender Recommendation for 'Apply system updates' status is 'Completed'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = ">0"
        ExpectedValue    = "0"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Windows and Linux virtual machines should always be kept up-to-date to mitigate security vulnerabilities. Microsoft Defender for Cloud retrieves available security and critical updates from Windows Update, WSUS, or the appropriate package manager for Linux VMs. If a VM is missing security updates, Defender for Cloud will generate a recommendation to apply them."
        Impact           = "Running Microsoft Defender for Cloud incurs additional charges for each resource monitored. Please see attached reference for exact charges per hour."
        Remediation      = 'To apply missing system updates: https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/5'
        References       = @(
            @{ 'Name' = 'Apply system updates recommendation'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference#apply-system-updates' },
            @{ 'Name' = 'Azure Security Benchmark - System Updates'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-security-controls#system-updates' },
            @{ 'Name' = 'Microsoft Defender for Cloud recommendations'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference' },
            @{ 'Name' = 'Security alerts and incidents'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz31010
{
	try
	{
		$Violation = @()
		# Actual Script
		$Recommendations = Get-AzSecurityTask | Where-Object {$_.RecommendationType -match "system updates"}
		ForEach ($Recommendation in $Recommendations){
			$Violation += "$($Recommendation.RecommendationType) : $($Recommendation.ResourceId)"
		}
		
		# Validation
		if ($Violation.Count -igt 0)
		{
			$endobject = Build-CISAz31010 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz31010 -ReturnedValue "Microsoft Defender Recommendation for 'Apply system updates' status is 'Completed'" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz31010 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz31010