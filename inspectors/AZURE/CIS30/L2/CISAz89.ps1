# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz89
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz89"
        ID               = "8.9"
        Title            = "(L2) Ensure that VHDs are Encrypted"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "NO Encryption"
        ExpectedValue    = "Encryption"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "While it is recommended to use Managed Disks which are encrypted by default, 'legacy' VHDs may exist for a variety of reasons and may need to remain in VHD format. VHDs are not encrypted by default, so this recommendation intends to address the security of these disks. In these niche cases, VHDs should be encrypted using the procedures in this recommendation to encrypt and protect the data content."
        Impact           = "Depending on how the encryption is implemented will change the size of the impact. If provider-managed keys(PMK) are utilized, the impact is relatively low, but processes need to be put in place to regularly rotate the keys. If Customer-managed keys(CMK) are utilized, a key management process needs to be implemented to store and manage key rotation, thus the impact is medium to high depending on user maturity with key management."
        Remediation      = 'Use the PowerShell script to remediate the issue: New-AzKeyvault -name <name> -ResourceGroupName <resourceGroup> -Location <location> -EnabledForDiskEncryption; $KeyVault = Get-AzKeyVault -VaultName <name> -ResourceGroupName <resourceGroup>; Set-AzVMDiskEncryptionExtension -ResourceGroupName <resourceGroup> -VMName <name> -DiskEncryptionKeyVaultUrl $KeyVault.VaultUri -DiskEncryptionKeyVaultId $KeyVault.ResourceId'
        References       = @(
            @{ 'Name' = 'Quickstart: Create and encrypt a Windows VM with the Azure CLI'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-cli-quickstart' },
            @{ 'Name' = 'Quickstart: Create and encrypt a Windows virtual machine in Azure with PowerShell'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-powershell-quickstart' },
            @{ 'Name' = 'DP-4: Enable data at rest encryption by default'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default' },
            @{ 'Name' = 'Create a managed disk from a VHD file in a storage account in same or different subscription with PowerShell'; 'URL' = 'https://learn.microsoft.com/en-us/previous-versions/azure/virtual-machines/scripts/virtual-machines-powershell-sample-create-managed-disk-from-vhd' }
        )
    }

    return $inspectorobject
}

function Audit-CISAz89
{
    try
    {
        # Checking for VMs with unencrypted disks
        $Violation = @()
        $AzVMs = Get-AzVM | Select-Object ResourceGroupName,Name -ExpandProperty StorageProfile

        if ($null -ne $AzVMs.OsDisk.Vhd)
        {
            # Check for encryption status for VHD
            foreach ($AzVM in $AzVMs)
            {
                $Encryption = Get-AzVmDiskEncryptionStatus -ResourceGroupName $AzVM.ResourceGroupName -VMName $AzVM.Name
                if ($Encryption.DataVolumesEncrypted -eq "NotEncrypted" -or $Encryption.OsVolumeEncrypted -eq "NotEncrypted")
                {
                    $Violation += $AzVM.Name
                }
            }
        }
        else
        {
            # Check for regular encryption
            foreach ($AzVM in $AzVMs)
            {
                $Encryption = Get-AzVmDiskEncryptionStatus -ResourceGroupName $AzVM.ResourceGroupName -VMName $AzVM.Name
                if ($Encryption.DataVolumesEncrypted -eq "NotEncrypted" -or $Encryption.OsVolumeEncrypted -eq "NotEncrypted")
                {
                    $Violation += $AzVM.Name
                }
            }
        }

        if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz89 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz89 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz89 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}

return Audit-CISAz89
