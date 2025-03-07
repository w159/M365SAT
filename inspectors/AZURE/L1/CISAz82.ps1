# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz82
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{ 
        UUID             = "CISAz82"
        ID               = "8.2"
        Title            = "(L1) Ensure Virtual Machines are utilizing Managed Disks"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Managed disks are an option upon the creation of VMs"
        ExpectedValue    = "VMs with a Managed Disk."
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Managed disks are by default encrypted on the underlying hardware, so no additional encryption is required for basic protection. Additional encryption options are available if needed. Managed disks are designed to be more resilient than storage accounts. For ARM-deployed Virtual Machines, Azure Advisor will eventually recommend moving VHDs to managed disks for both security and cost management benefits."
        Impact           = "There are additional costs for managed disks based off of disk space allocated. When converting to managed disks, VMs will be powered off and back on."
        Remediation      = 'Use the following PowerShell command to convert an unmanaged disk to a managed disk: Stop-AzVM -ResourceGroupName $rgName -Name $vmName -Force; ConvertTo-AzVMManagedDisk -ResourceGroupName $rgName -VMName $vmName; Start-AzVM -ResourceGroupName $rgName -Name $vmName'
        References       = @( 
            @{ 'Name' = 'Migrate a Windows virtual machine from unmanaged disks to managed disks'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/windows/convert-unmanaged-to-managed-disks' },
            @{ 'Name' = 'DP-4: Enable data at rest encryption by default'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default' },
            @{ 'Name' = 'Frequently asked questions about Azure IaaS VM disks and managed and unmanaged premium disks'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/faq-for-disks?tabs=azure-portal' },
            @{ 'Name' = 'Managed Disks pricing'; 'URL' = 'https://azure.microsoft.com/en-us/pricing/details/managed-disks/' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz82
{
    try
    {
        # Checking Virtual Machines that are not utilizing Managed Disks
        $Violation = @()
        $AzVMs = Get-AzVM | Select-Object Name, StorageProfile

        foreach ($AzVM in $AzVMs)
        {
            if ($null -eq $AzVM.StorageProfile.OsDisk.ManagedDisk.Id)
            {
                $Violation += $AzVM.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz82 -ReturnedValue $Violation -Status "FAIL" -RiskScore "3" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz82 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz82 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz82
