# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz333
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz333"
        ID               = "3.3.3"
        Title            = "(L1) Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Expiration"
        ExpectedValue    = "An Expiration Date + Time"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure environment. The exp (expiration date) attribute identifies the expiration date on or after which the secret MUST NOT be used. By default, secrets never expire. It is recommended to rotate secrets in the key vault and set an explicit expiration date for all secrets."
        Impact           = "Secrets cannot be used beyond their assigned expiry date respectively. Secrets need to be rotated periodically wherever they are used."
        Remediation      = 'Use the PowerShell Script to remediate the issue: Set-AzKeyVaultSecretAttribute -VaultName <Vault Name> -Name <Secret Name> -Expires <DateTime>'
        References       = @(
            @{ 'Name' = 'Azure Key Vault basic concepts'; 'URL' = 'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis' },
            @{ 'Name' = 'Azure Key Vault keys, secrets and certificates overview'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#key-vault-keys' },
            @{ 'Name' = 'DP-6: Use a secure key management process'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-6-use-a-secure-key-management-process' }
        )
    }
    return $inspectorobject
}

# AuditScript
function Audit-CISAz333
{
    try
    {
        $Violation = @()
        $AzKeyVaults = Get-AzKeyVault
        foreach ($AzKeyVault in $AzKeyVaults)
        {
            $KeyVaultDetails = Get-AzKeyVault -VaultName $AzKeyVault.VaultName
            if ($KeyVaultDetails.EnableRbacAuthorization -eq $True)
            {
                $KeyVaultSecret = Get-AzKeyVaultSecret -VaultName $AzKeyVault.VaultName -ErrorAction SilentlyContinue
                if ([string]::IsNullOrEmpty($KeyVaultSecret.Expires) -or $KeyVaultSecret.Enabled -eq $true)
                {
                    $Violation += $AzKeyVault.VaultName
                }
            }
        }

        # validation
        if ($Violation.count -gt 0)
        {
            $endobject = Build-CISAz333 -ReturnedValue ($Violation.Count) -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
            return $endobject
        }
        else
        {
            $endobject = Build-CISAz333 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            Return $endobject
        }
        return $null
    }
    catch
    {
        $endobject = Build-CISAz333 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $endobject
    }
}

return Audit-CISAz333
