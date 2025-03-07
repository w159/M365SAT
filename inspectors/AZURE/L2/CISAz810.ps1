# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz810
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz810"
        ID               = "8.10"
        Title            = "(L2) Ensure only MFA enabled identities can access privileged Virtual Machine"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Unknown"
        ExpectedValue    = "Unknown"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Integrating multi-factor authentication (MFA) as part of the organizational policy can greatly reduce the risk of an identity gaining control of valid credentials that may be used for additional tactics such as initial access, lateral movement, and collecting information. MFA can also be used to restrict access to cloud resources and APIs. An Adversary may log into accessible cloud services within a compromised environment using Valid Accounts that are synchronized to move laterally and perform actions with the virtual machine's managed identity. The adversary may then perform management actions or access cloud-hosted resources as the logged-on managed identity."
        Impact           = "This recommendation requires the Entra ID P2 license to implement. Ensure that identities that are provisioned to a virtual machine utilizes an RBAC/ABAC group and is allocated a role using Azure PIM, and the Role settings require MFA or use another third-party PAM solution for accessing Virtual Machines."
        Remediation      = 'Use the PowerShell script to remediate the issue: New-AzKeyvault -name <name> -ResourceGroupName <resourceGroup> -Location <location> -EnabledForDiskEncryption; $KeyVault = Get-AzKeyVault -VaultName <name> -ResourceGroupName <resourceGroup>; Set-AzVMDiskEncryptionExtension -ResourceGroupName <resourceGroup> -VMName <name> -DiskEncryptionKeyVaultUrl $KeyVault.VaultUri -DiskEncryptionKeyVaultId $KeyVault.ResourceId'
        References       = @(
            @{ 'Name' = 'Sign in to a Windows virtual machine in Azure by using Microsoft Entra ID including passwordless'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/devices/howto-vm-sign-in-azure-ad-windows' }
        )
    }

    return $inspectorobject
}

function Audit-CISAz810
{
    try
    {
        #This check is not automated yet!
        $EndObject = Build-CISAz810 -ReturnedValue "Cannot verify!" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        return $EndObject

    }
    catch
    {
        $EndObject = Build-CISAz810 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}

return Audit-CISAz810
