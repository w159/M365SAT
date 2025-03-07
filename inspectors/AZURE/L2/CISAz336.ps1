# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz336
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz336"
        ID               = "3.3.6"
        Title            = "(L2) Enable Role Based Access Control for Azure Key Vault"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The new RBAC permissions model for Key Vaults enables a much finer grained access control for key vault secrets, keys, certificates, etc., than the vault access policy. This in turn will permit the use of privileged identity management over these roles, thus securing the key vaults with JIT Access management."
        Impact           = "Implementation needs to be properly designed from the ground up, as this is a fundamental change to the way key vaults are accessed/managed. Changing permissions to key vaults will result in loss of service as permissions are re-applied. For the least amount of downtime, map your current groups and users to their corresponding permission needs."
        Remediation      = 'Use the PowerShell Script to remediate the issue: Update-AzKeyVault -ResourceGroupName <RESOURCE GROUP NAME> -VaultName <KEY VAULT NAME> -EnableRbacAuthorization $True'
        References       = @(
            @{ 'Name' = 'Vault access policy to Azure RBAC migration steps'; 'URL' = 'https://learn.microsoft.com/en-gb/azure/key-vault/general/rbac-migration#vault-access-policy-to-azure-rbac-migration-steps' },
            @{ 'Name' = 'Assign Azure roles using the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-gb/azure/role-based-access-control/role-assignments-portal?tabs=current' },
            @{ 'Name' = 'What is Azure role-based access control (Azure RBAC)?'; 'URL' = 'https://learn.microsoft.com/en-gb/azure/role-based-access-control/overview' },
            @{ 'Name' = 'DP-8: Ensure security of key and certificate repository'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-8-ensure-security-of-key-and-certificate-repository' }
        )
    }
    return $inspectorobject
}

# AuditScript
function Audit-CISAz336
{
    try
    {
        $Violation = @()
        $AzKeyVaults = Get-AzKeyVault
        foreach ($AzKeyVault in $AzKeyVaults){
            $KeyVaultDetails = Get-AzKeyVault -VaultName $AzKeyVault.VaultName
            if ($KeyVaultDetails.EnableRbacAuthorization -ne $true){
                $Violation += $AzKeyVault.VaultName
            }
        }

        #validation
        if ($Violation.count -gt 0)
        {
            $finalobject = Build-CISAz336 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
            return $finalobject
        }
        else
        {
            $finalobject = Build-CISAz336 -ReturnedValue "All Key Vaults are RBAC enabled" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $finalobject
        }
        return $null
    }
    catch
    {
        $endobject = Build-CISAz336 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $endobject
    }
}

return Audit-CISAz336
