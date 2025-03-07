# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz331
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz331"
        ID               = "3.3.1"
        Title            = "(L1) Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Expiration"
        ExpectedValue    = "An Expiration Date + Time"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Azure Key Vault enables users to store and use cryptographic keys within the Microsoft Azure environment. The exp (expiration date) attribute identifies the expiration date on or after which the key MUST NOT be used for encryption of new data, wrapping of new keys, and signing. By default, keys never expire. It is thus recommended that keys be rotated in the key vault and set an explicit expiration date for all keys to help enforce the key rotation. This ensures that the keys cannot be used beyond their assigned lifetimes."
        Impact           = "Keys cannot be used beyond their assigned expiration dates respectively. Keys need to be rotated periodically wherever they are used."
        Remediation      = 'You can change the expiration date using the PowerShell script: Set-AzKeyVaultKeyAttribute -VaultName <VaultName> -Name <KeyName> -Expires <DateTime>.'
        References       = @(
            @{ 'Name' = 'Azure Key Vault basic concepts'; 'URL' = 'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis' },
            @{ 'Name' = 'Azure Key Vault keys, secrets and certificates overview'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#key-vault-keys' },
            @{ 'Name' = 'DP-6: Use a secure key management process'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-6-use-a-secure-key-management-process' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz331
{
    try
    {
        $Violation = @()
        $AzKeyVaults = Get-AzKeyVault
        foreach ($AzKeyVault in $AzKeyVaults)
        {
            $KeyVaultDetails = Get-AzKeyVault -VaultName $AzKeyVault.VaultName
            if ($KeyVaultDetails.EnableRbacAuthorization -eq $true)
            {
                $KeyVaultKey = Get-AzKeyVaultKey -VaultName $AzKeyVault.VaultName -ErrorAction SilentlyContinue
                if ([string]::IsNullOrEmpty($KeyVaultKey.Expires) -or $KeyVaultKey.Enabled -eq $true)
                {
                    $Violation += $AzKeyVault.VaultName
                }
            }
        }

        # validation
        if ($Violation.count -igt 0)
        {
            $endobject = Build-CISAz331 -ReturnedValue ($Violation.Count) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $endobject
        }
        else
        {
            $endobject = Build-CISAz331 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            Return $endobject
        }
        return $null
    }
    catch
    {
        $endobject = Build-CISAz331 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $endobject
    }
}

return Audit-CISAz331