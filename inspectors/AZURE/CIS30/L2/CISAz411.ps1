# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

# Build Function
function Build-CISAz411
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz411"
        ID               = "4.11"
        Title            = "(L2) Ensure Storage for Critical Data are Encrypted with Customer Managed Keys (CMK)"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Encryption: Microsoft Managed Keys"
        ExpectedValue    = "Encryption: Customer Managed Keys"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. If you want to control and manage this encryption key yourself, you can specify a customer-managed key. That key is used to protect and control access to the key that encrypts your data."
        Impact           = "If the key expires by setting the 'activation date' and 'expiration date', the user must rotate the key manually. Using Customer Managed Keys may also incur additional man-hour requirements to create, store, manage, and protect the keys as needed."
        Remediation      = 'Use the PowerShell command to remediate the issue: Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -KeySource "Microsoft.KeyVault"'
        References       = @(
            @{ 'Name' = 'Azure Storage encryption for data at rest'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-service-encryption' },
            @{ 'Name' = 'Protect data at rest'; 'URL' = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/data-encryption-best-practices#protect-data-at-rest' },
            @{ 'Name' = 'Azure Storage encryption for data at rest'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-service-encryption#azure-storage-encryption-versus-disk-encryption' },
            @{ 'Name' = 'DP-5: Use customer-managed key option in data at rest encryption when required'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required' }
        )
    }
    return $inspectorobject
}

# Audit Function
function Audit-CISAz411
{
    try
    {
        $Violation = @()
        $StorageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue

        foreach ($StorageAccount in $StorageAccounts) {
            $Encryption = $StorageAccount | Select-Object -ExpandProperty Encryption
            if ($Encryption.KeySource -eq "Microsoft.Storage") {
                $Violation += $StorageAccount.StorageAccountName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz411 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz411 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz411 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz411