# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz86
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz86"
        ID               = "8.6"
        Title            = "(L1) Ensure that 'Enable Data Access Authentication Mode' is 'Checked'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, Data Access Authentication Mode is Disabled."
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling data access authentication mode adds a layer of protection using an Entra ID role to further restrict users from creating and using Secure Access Signature (SAS) tokens for exporting a detached managed disk or virtual machine state. Users will need the Data operator for managed disk role within Entra ID in order to download a VHD or VM Guest state using a secure URL."
        Impact           = "In order to apply this setting, the virtual machine to which the disk or disks are attached will need to be powered down and have their disk detached. Users without the Data operator for managed disk role within Entra ID will not be able to export VHD or VM Guest state using the secure download URL."
        Remediation      = 'Use the script to mitigate the issue: Get-AzDisk | Update-AzDisk -ResourceGroup $_.Resource -DiskName $disk.Name -Disk $disk'
        References       = @(
            @{ 'Name' = 'Secure downloads and uploads with Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/windows/download-vhd?tabs=azure-portal#secure-downloads-and-uploads-with-microsoft-entra-id' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz86
{
    try
    {
        # Checking for disks where Data Access Authentication Mode is not using Azure Active Directory
        $Violation = @()
        $Disks = Get-AzDisk 

        foreach ($Disk in $Disks)
        {
            if ([string]::IsNullOrEmpty($Disk.DataAccessAuthMode) -or -not $Disk.DataAccessAuthMode.Contains("AzureActiveDirectory"))
            {
                $Violation += $Disk.Name
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz86 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz86 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz86 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz86
