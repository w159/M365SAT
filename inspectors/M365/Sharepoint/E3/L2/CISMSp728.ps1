# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp728
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp728"
        ID               = "7.2.8"
        Title            = "(L2) Ensure external sharing is restricted by security group"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "Unchecked"
        ExpectedValue    = "Checked"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Restricting external sharing to specific security groups enforces role-based access control, enhancing security for external sharing by leveraging Microsoft Entra-defined groups."
        Impact           = "OneDrive will also be governed by this and there is no granular control at the SharePoint site level."
        Remediation	 	 = 'https://contoso-admin.sharepoint.com/_layouts/15/online/AdminHome.aspx#/sharing'
        References       = @(
            @{ 'Name' = 'Allow only members in specific security groups to share SharePoint and OneDrive files and folders externally'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/manage-security-groups' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp728
{
	try
	{
			$endobject = Build-CISMSp728 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
			return $endobject
	}
	catch
	{
		$endobject = Build-CISMSp728 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp728