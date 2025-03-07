# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz85
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz85"
        ID               = "8.5"
        Title            = "(L1) Ensure that 'Disk Network Access' is NOT set to 'Enable public access from all networks'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, Disk Network access is set to Enable public access from all networks."
        ExpectedValue    = "Disabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The setting 'Enable public access from all networks' is, in many cases, an overly permissive setting on Virtual Machine Disks that presents atypical attack, data infiltration, and data exfiltration vectors. If a disk to network connection is required, the preferred setting is to 'Disable public access and enable private access.'"
        Impact           = "The setting 'Disable public access and enable private access' will require configuring a private link (URL in references below). The setting 'Disable public and private access' is most secure and preferred where disk network access is not needed."
        Remediation      = 'Use the below script to mitigate the issue: Update-AzDisk -ResourceGroup <resource group name> -DiskName $disk.Name -Disk $disk'
        References       = @(
            @{ 'Name' = 'Restrict import/export access for managed disks using Azure Private Link'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/disks-enable-private-links-for-import-export-portal' },
            @{ 'Name' = 'Azure CLI - Restrict import/export access for managed disks with Private Links'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/linux/disks-export-import-private-links-cli' },
            @{ 'Name' = 'Restrict managed disks from being imported or exported'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/disks-restrict-import-export-overview' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz85
{
    try
    {
        # Checking if any disk has public access enabled or incorrect network access policy
        $Violation = @()
        $Disks = Get-AzDisk 

        foreach ($Disk in $Disks)
        {
            if ($Disk.PublicNetworkAccess -eq "Enabled" -or $Disk.NetworkAccessPolicy -ne 'AllowPrivate' -or $Disk.NetworkAccessPolicy -ne 'DenyAll')
            {
                $Violation += $Disk.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz85 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz85 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz85 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz85
