# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz614
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz614"
        ID               = "6.1.4"
        Title            = "(L1) Ensure that logging for Azure Key Vault is 'Enabled'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "KeySource: Microsoft.Storage"
        ExpectedValue    = "KeySource: Microsoft.Keyvault"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Monitoring how and when key vaults are accessed, and by whom, enables an audit trail of interactions with confidential information, keys, and certificates managed by Azure Key Vault. Enabling logging for Key Vault saves information in a user-provided destination of either an Azure storage account or Log Analytics workspace. The same destination can be used for collecting logs for multiple Key Vaults."
        Impact           = "Failure to enable logging for Azure Key Vault can lead to a lack of visibility into unauthorized access or malicious activities."
        Remediation      = "Use the PowerShell Script to remediate the issue: New-AzDiagnosticSetting."
        References       = @(
            @{ 'Name' = 'Enable Key Vault logging'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/howto-logging?tabs=azure-cli' },
            @{ 'Name' = 'DP-8: Ensure security of key and certificate repository'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-8-ensure-security-of-key-and-certificate-repository' },
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz614
{
    try
    {
        # Subscription-Based Checking
        $Violation = @()
        $KeyVaults = Get-AzKeyVault

        foreach ($KeyVault in $KeyVaults) {
            try {
                $DiagSetting = Get-AzDiagnosticSetting -ResourceId $KeyVault.Id
                if ([string]::IsNullOrEmpty($DiagSetting) -or $DiagSetting.Log.Enabled -eq $false -or `
                    $DiagSetting.Log.CategoryGroup -notcontains "audit" -or $DiagSetting.Log.CategoryGroup -notcontains "allLogs") {
                    $Violation += $KeyVault.VaultName
                }
            }
            catch {
                continue
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz614 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz614 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz614 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz614
