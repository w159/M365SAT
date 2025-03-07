# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz31015
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz31015"
        ID               = "3.1.15"
        Title            = "(L2) EEnsure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Not Configured"
        ExpectedValue    = "Configured"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Microsoft Defender External Attack Surface Management (EASM) helps organizations monitor externally exposed resources, gain valuable insights, and export findings for use in vulnerability management, red teaming, and purple teaming exercises."
        Impact           = 'Microsoft Defender EASM workspaces are currently available as Azure Resources with a 30-day free trial period but can quickly accrue significant charges. The costs are calculated daily as (Number of billable inventory items) x (item cost per day; approximately: $0.017).'
        Remediation      = 'To configure EASM: New-AzResourceGroup -Name "DefenderEASMGroup" -Location "West EU"; New-AzResource -ResourceType "Microsoft.Easm/workspaces" -ResourceGroupName "DefenderEASMGroup" -Name "DefenderEASMWorkspace" -Location "West EU"'
        References       = @(
            @{ 'Name' = 'Defender External Attack Surface Management'; 'URL' = 'https://learn.microsoft.com/en-us/azure/external-attack-surface-management/' },
            @{ 'Name' = 'Create a Defender EASM Azure resource'; 'URL' = 'https://learn.microsoft.com/en-us/azure/external-attack-surface-management/deploying-the-defender-easm-azure-resource' },
            @{ 'Name' = 'Uncover adversaries with new Microsoft Defender threat intelligence products'; 'URL' = 'https://www.microsoft.com/en-us/security/blog/2022/08/02/microsoft-announces-new-solutions-for-threat-intelligence-and-attack-surface-management/' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz31015
{
	try
	{
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id))/providers/Microsoft.Easm/workspaces?api-version=2023-04-01-preview").content | ConvertFrom-Json)
		
		if ([string]::IsNullOrEmpty($Settings.value))
		{
			$endobject = Build-CISAz31015 -ReturnedValue ("No EASM Workspace available") -Status "FAIL" -RiskScore "3" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz31015 -ReturnedValue ($Settings.value) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz31015 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz31015