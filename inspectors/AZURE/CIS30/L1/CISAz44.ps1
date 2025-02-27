# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Call the OutPath Variable here
$path = @($OutPath)

# Build Function
function Build-CISAz44
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz44"
        ID               = "4.4"
        Title            = "(L1) Ensure that Storage Account Access Keys are Periodically Regenerated"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Null"
        ExpectedValue    = "KeyExpirationPeriodInDay: 90"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Periodically regenerating storage account access keys reduces the risk of unauthorized access to sensitive data."
        Impact           = "Regenerating access keys can affect services in Azure as well as the organization's applications that are dependent on the storage account. All clients who use the access key to access the storage account must be updated to use the new key."
        Remediation      = 'Use the following PowerShell command to regenerate keys: Get-AzStorageAccount | Set-AzStorageAccount -Name $_.StorageAccountName -KeyExpirationPeriodInDay 90'
        References       = @(
            @{ 'Name' = 'Manage storage account access keys'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage' },
            @{ 'Name' = 'Microsoft Azure Security Best Practices'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/' },
            @{ 'Name' = 'NIST 800-57 Key Management'; 'URL' = 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf' },
            @{ 'Name' = 'Best practices for storage accounts'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview' }
        )
    }
    return $inspectorobject
}

# Audit Function
function Audit-CISAz44
{
    try
    {
        $Violation = @()
        $Settings = Get-AzStorageAccount -ErrorAction SilentlyContinue

        foreach ($Value in $Settings) {
            if ($Value.KeyPolicy.KeyExpirationPeriodInDays -lt 90 -or $null -eq $Value.KeyPolicy.KeyExpirationPeriodInDays) {
                $Violation += $Value.StorageAccountName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz44 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        } else {
            $FinalObject = Build-CISAz44 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz44 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz44
