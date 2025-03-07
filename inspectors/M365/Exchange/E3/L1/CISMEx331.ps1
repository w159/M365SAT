# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx331
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx331"
        ID               = "3.3.1"
        Title            = "(L1) Ensure SharePoint Online Information Protection policies are set up and used"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "By categorizing and applying policy-based protection, SharePoint Online Data Classification Policies can significantly reduce the risk of data loss or unauthorized data exposure. Proper policies also facilitate a more effective incident response in the event of a breach."
        Impact           = "The creation of data classification policies is unlikely to have a significant impact on an organization. However, maintaining long-term adherence to policies may require ongoing training and compliance efforts across the organization. Therefore, organizations should include training and compliance planning as part of the data classification policy creation process."
        Remediation 	 = 'New-LabelPolicy -Name "Example Name" -Labels "Example","Domain"'
        References       = @(
            @{ 'Name' = 'Top sensitivity labels applied to content'; 'URL' = "https://learn.microsoft.com/en-us/purview/data-classification-overview?view=o365-worldwide#top-sensitivity-labels-applied-to-content" },
            @{ 'Name' = 'Enable sensitivity labels for files in SharePoint and OneDrive'; 'URL' = "https://learn.microsoft.com/en-us/purview/sensitivity-labels-sharepoint-onedrive-files" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx331
{
	try
	{
		try
		{
			$ExistenceLabelPolicy = Get-LabelPolicy
			$ExistenceLabelPolicy | Format-Table -AutoSize | Out-File "$path\LabelPolicySettings.txt"
		}
		catch
		{
			$ExistenceLabelPolicy = "No Label Policy Active"
		}
		
		if ($ExistenceLabelPolicy -eq "No Label Policy Active" -or [string]::IsNullOrEmpty($ExistenceLabelPolicy))
		{
			$endobject = Build-CISMEx331 -ReturnedValue $ExistenceLabelPolicy -Status "FAIL" -RiskScore "8" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx331 -ReturnedValue $ExistenceLabelPolicy -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx331 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx331