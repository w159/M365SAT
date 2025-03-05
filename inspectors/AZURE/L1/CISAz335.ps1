# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz335
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz335"
        ID               = "3.3.5"
        Title            = "(L1) Ensure the Key Vault is Recoverable"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "enableSoftDelete: null enablePurgeProtection: null"
        ExpectedValue    = "enableSoftDelete: true enablePurgeProtection: true"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "There could be scenarios where users accidentally run delete/purge commands on Key Vault or an attacker/malicious user deliberately does so in order to cause disruption. Deleting or purging a Key Vault leads to immediate data loss, as keys encrypting data and secrets/certificates allowing access/services will become non-accessible. There is a Key Vault property that plays a role in permanent unavailability of a Key Vault: enablePurgeProtection: Setting this parameter to 'true' for a Key Vault ensures that even if Key Vault is deleted, Key Vault itself or its objects remain recoverable for the next 90 days. Key Vault/objects can either be recovered or purged (permanent deletion) during those 90 days. If no action is taken, the key vault and its objects will subsequently be purged. Enabling the enablePurgeProtection parameter on Key Vaults ensures that Key Vaults and their objects cannot be deleted/purged permanently."
        Impact           = "Once purge-protection and soft-delete are enabled for a Key Vault, the action is irreversible"
        Remediation      = 'Use the PowerShell Script to enable Purge Protection and Soft Delete on the Key Vault: Update-AzKeyVault -VaultName <vaultName> -ResourceGroupName <resourceGroupName> -EnablePurgeProtection'
        References       = @(
            @{ 'Name' = 'Azure Key Vault recovery management with soft delete and purge protection'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/key-vault-recovery?tabs=azure-cli' },
            @{ 'Name' = 'Azure Key Vault soft-delete overview'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview' },
            @{ 'Name' = 'GS-8: Define and implement backup and recovery strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-8-define-and-implement-backup-and-recovery-strategy' },
            @{ 'Name' = 'DP-8: Ensure security of key and certificate repository'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-8-ensure-security-of-key-and-certificate-repository' }
        )
    }
    return $inspectorobject
}

# Audit Script
function Audit-CISAz335
{
    try
    {
        $Violation = @()
        $AzKeyVaults = Get-AzKeyVault
        foreach ($AzKeyVault in $AzKeyVaults){
            $KeyVaultDetails = Get-AzKeyVault -VaultName $AzKeyVault.VaultName
            if ($KeyVaultDetails.EnablePurgeProtection -ne $True -or $KeyVaultDetails.EnableSoftDelete -ne $True){
                $Violation += $AzKeyVault.VaultName
            }
        }

        if ($Violation.count -gt 0)
        {
            $finalobject = Build-CISAz335 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
            return $finalobject
        }
        else
        {
            $finalobject = Build-CISAz335 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $finalobject
        }

        return $null
    }
    catch
    {
        $finalobject = Build-CISAz335 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $finalobject
    }
}
return Audit-CISAz335
