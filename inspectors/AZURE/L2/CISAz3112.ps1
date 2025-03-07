# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz3112
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz3112"
        ID               = "3.1.1.2"
        Title            = "(L2) Ensure that Microsoft Defender for Cloud Apps integration with Microsoft Defender for Cloud is Selected"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "On (if licensed)"
        ExpectedValue    = "On"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Microsoft Defender for Cloud offers additional security by analyzing Azure Resource Manager (ARM) events, which control all resource interactions within Azure. This capability detects unusual or potentially harmful operations across Azure subscriptions. By integrating with Microsoft Defender for Cloud Apps (formerly Microsoft Cloud App Security), additional advanced analytics become available. To enable this feature, a valid Cloud App Security license is required."
        Impact           = "Microsoft Defender for Cloud Apps works with Standard pricing tier Subscription. Choosing the Standard pricing tier of Microsoft Defender for Cloud incurs an additional cost per resource."
        Remediation      = 'To enable Microsoft Defender for Cloud Apps integration: Set-AzSecuritySetting -SettingName "MCAS" -SettingKind "DataExportSettings" -Enabled $true'        
		References       = @(
            @{ 'Name' = 'What is Microsoft Defender for Cloud?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction#azure-management-layer-azure-resource-manager-preview' },
            @{ 'Name' = 'IM-9: Secure user access to existing applications'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-9-secure-user-access-to--existing-applications' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz3112
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecuritySetting | Select-Object name,enabled |where-object {$_.name -eq "MCAS"}
		
		# Validation
		if ($AzSecuritySetting.Enabled -eq $False)
		{
			$endobject = Build-CISAz3112 -ReturnedValue ($AzSecuritySetting.Enabled) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz3112 -ReturnedValue ($AzSecuritySetting.Enabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz3112 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz3112