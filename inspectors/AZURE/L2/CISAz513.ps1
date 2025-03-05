# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz513
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz513"
        ID               = "5.1.3"
        Title            = "(L2) Ensure SQL server's Transparent Data Encryption (TDE) protector is encrypted with Customer-managed key"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Enabled"
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure’s cloud-based external key management system, is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server."
        Impact           = "Once TDE protector is encrypted with a Customer-managed key, it transfers entire responsibility of respective key management on to you, and hence you should be more careful about doing any operations on the particular key in order to keep data from corresponding SQL server and Databases hosted accessible. When deploying Customer Managed Keys, it is prudent to ensure that you also deploy an automated toolset for managing these keys (this should include discovery and key rotation), and Keys should be stored in an HSM or hardware backed keystore, such as Azure Key Vault. As far as toolsets go, check with your cryptographic key provider, as they may well provide one as an add-on to their service."
        Remediation      = 'You can change the settings by executing the following PowerShell command: Set-AzSqlServerTransparentDataEncryptionProtector -Type AzureKeyVault -KeyId <KeyIdentifier> -ServerName <ServerName> -ResourceGroupName <ResourceGroupName>'
        References       = @(
            @{ 'Name' = 'Azure SQL transparent data encryption with customer-managed key'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-byok-overview?view=azuresql' },
            @{ 'Name' = 'Databases (Preview)'; 'URL' = 'https://azure.microsoft.com/en-us/blog/category/databases/' },
            @{ 'Name' = 'Deploying a Key Vault-based TDE protector for Azure SQL'; 'URL' = 'https://winterdom.com/2017/09/07/azure-sql-tde-protector-keyvault' },
            @{ 'Name' = 'DP-5: Use customer-managed key option in data at rest encryption when required'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required' },
            @{ 'Name' = 'Azure Key Vault basic concepts'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz513
{
    try
    {
        $Violation = @()
        $SQLServers = Get-AzSqlServer

        foreach ($SQLServer in $SQLServers) {
            $Server = Get-AzSqlServerTransparentDataEncryptionProtector -ServerName $SQLServer.ServerName -ResourceGroupName $SQLServer.ResourceGroupName
            if ($Server.Type -ne "AzureKeyVault" -or $Server.ServerKeyVaultKeyName -ne "KeyVaultName_KeyName_KeyIdentifierVersion" -or $Server.KeyId -ne "KeyIdentifier") {
                $Violation += $SQLServer.ServerName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz513 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz513 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz513 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz513
