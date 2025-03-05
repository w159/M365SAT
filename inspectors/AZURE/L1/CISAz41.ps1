# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Call the OutPath Variable here
$path = @($OutPath)

# Build Function
function Build-CISAz41
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz41"
        ID               = "4.1"
        Title            = "(L1) Ensure that 'Secure transfer required' is set to 'Enabled'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The secure transfer option enhances the security of a storage account by only allowing requests to the storage account via a secure connection. For example, when calling REST APIs to access storage accounts, the connection must use HTTPS. Any requests using HTTP will be rejected when 'secure transfer required' is enabled."
        Impact           = "Not enabling 'secure transfer required' can expose sensitive data to potential security risks during transit."
        Remediation      = 'Use the following PowerShell command to remediate the issue: Set-AzStorageAccount -ResourceGroupName <name> -EnableHttpsTrafficOnly $true'
        References       = @(
            @{ 'Name' = 'Security recommendations for Blob storage'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations#encryption-in-transit' },
            @{ 'Name' = 'DP-3: Encrypt sensitive data in transit'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-3-encrypt-sensitive-data-in-transit' }
        )
    }
    return $inspectorobject
}

# Audit Function
function Audit-CISAz41
{
    try
    {
        $Violation = @()
        $Settings = Get-AzStorageAccount | Select-Object StorageAccountName, ResourceGroupName, EnableHttpsTrafficOnly

        foreach ($Value in $Settings) {
            if ($Value.EnableHttpsTrafficOnly -eq $false) {
                $Violation += $Value.StorageAccountName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz41 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz41 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz41 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz41
