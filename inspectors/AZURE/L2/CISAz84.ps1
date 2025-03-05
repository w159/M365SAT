# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz84
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{ 
        UUID             = "CISAz84"
        ID               = "8.4"
        Title            = "(L2) Ensure that 'Unattached disks' are encrypted with 'Customer Managed Key' (CMK)"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, Unmanaged disks are encrypted using SSE with PMK."
        ExpectedValue    = "CMK Managed Disks"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Encrypting the IaaS VM's OS disk (boot volume) and Data disks (non-boot volume) ensures that the entire content is fully unrecoverable without a key, thus protecting the volume from unwanted reads. PMK (Platform Managed Keys) are enabled by default in Azure-managed disks and allow encryption at rest. CMK is recommended because it gives the customer the option to control which specific keys are used for the encryption and decryption of the disk. The customer can then change keys and increase security by disabling them instead of relying on the PMK key that remains unchanging. There is also the option to increase security further by using automatically rotating keys so that access to disk is ensured to be limited. Organizations should evaluate what their security requirements are, however, for the data stored on the disk. For high-risk data using CMK is a must, as it provides extra steps of security. If the data is low risk, PMK is enabled by default and provides sufficient data security."
        Impact           = "You must have your key vault set up to utilize this. Encryption is available only on Standard tier VMs. This might cost you more. Utilizing and maintaining Customer-managed keys will require additional work to create, protect, and rotate keys."
        Remediation      = "Use the below script to allow encryption on Azure VM Disks: Set-AzVMDiskEncryptionExtension -ResourceGroupName <VMRGname> -VMName <vmName> -DiskEncryptionKeyVaultUrl <diskEncryptionKeyVaultUrl> -DiskEncryptionKeyVaultId <KeyVaultResourceId>"
        References       = @( 
            @{ 'Name' = 'Overview of managed disk encryption options'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview' },
            @{ 'Name' = 'Use asset inventory to manage your resources security posture'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/asset-inventory?toc=%2Fazure%2Fsecurity%2Ftoc.json' },
            @{ 'Name' = 'DP-5: Use customer-managed key option in data at rest encryption when required'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz84
{
    try
    {
        # Checking unattached disks that are not encrypted with Customer Managed Keys (CMK)
        $Violation = @()
        $Disks = Get-AzDisk | Where-Object { $_.DiskState -eq 'Unattached' }

        foreach ($Disk in $Disks)
        {
            if ($Disk.Encryption.Type -eq "EncryptionAtRestWithPlatformKey")
            {
                $Violation += $Disk.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz84 -ReturnedValue $Violation -Status "FAIL" -RiskScore "3" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz84 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz84 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz84
