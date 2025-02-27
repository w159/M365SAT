# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Call the OutPath Variable here
$path = @($OutPath)

# Build Function
function Build-CISAz42
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz42"
        ID               = "4.2"
        Title            = "(L2) Ensure that ‘Enable Infrastructure Encryption’ for Each Storage Account in Azure Storage is Set to ‘enabled’"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Azure Storage automatically encrypts all data in a storage account at the network level using 256-bit AES encryption, which is one of the strongest, FIPS 140-2-compliant block ciphers available. Customers who require higher levels of assurance that their data is secure can also enable 256-bit AES encryption at the Azure Storage infrastructure level for double encryption."
        Impact           = "The read and write speeds to the storage will be impacted if both default encryption and Infrastructure Encryption are checked, as a secondary form of encryption requires more resource overhead for the cryptography of information. This performance impact should be considered in an analysis for justifying use of the feature in your environment. Customer-managed keys are recommended for the most secure implementation, leading to overhead of key management. The key will also need to be backed up in a secure location, as loss of the key will mean loss of the information in the storage."
        Remediation      = 'Use the following PowerShell command to remediate the issue: Set-AzStorageAccount -ResourceGroupName <name> -AccountName <AccountName> -Location <Location> -SkuName "Standard_RAGRS" -Kind StorageV2 -RequireInfrastructureEncryption'
        References       = @(
            @{ 'Name' = 'Check the encryption status of a blob'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-encryption-status?tabs=portal' },
            @{ 'Name' = 'Azure Storage encryption for data at rest'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-service-encryption' },
            @{ 'Name' = 'Enable infrastructure encryption for double encryption of data'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/infrastructure-encryption-enable?tabs=portal' },
            @{ 'Name' = 'DP-4: Enable data at rest encryption by default'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default' }
        )
    }
    return $inspectorobject
}

# Audit Function
function Audit-CISAz42
{
    try
    {
        $Violation = @()
        $StorageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName, ResourceGroupName, EnableInfrastructureEncryption

        foreach ($StorageAccount in $StorageAccounts) {
            if ($StorageAccount.EnableInfrastructureEncryption -ne $true) {
                $Violation += $StorageAccount.StorageAccountName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz42 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz42 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz42 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz42