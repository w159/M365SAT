# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz911
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz911"
        ID               = "9.11"
        Title            = "(L2) Ensure Azure Key Vaults are Used to Store Secrets"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, no Azure Key Vaults are created."
        ExpectedValue    = "An active used KeyVault"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The credentials given to an application have permissions to create, delete, or modify data stored within the systems they access. If these credentials are stored within the application itself, anyone with access to the application or a copy of the code has access to them. Storing within Azure Key Vault as secrets increases security by controlling access. This also allows for updates of the credentials without redeploying the entire application."
        Impact           = "Integrating references to secrets within the key vault are required to be specifically integrated within the application code. This will require additional configuration to be made during the writing of an application, or refactoring of an already written one. There are also additional costs that are charged per 10000 requests to the Key Vaults."
        Remediation      = 'Use the PowerShell Script and change the expiration date to the desired value New-AzKeyvault -name <name> -ResourceGroupName <myResourceGroup> -Location <myLocation>'
        References       = @(
            @{ 'Name' = 'Use Key Vault references as app settings in Azure App Service and Azure Functions'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references?tabs=azure-cli' },
            @{ 'Name' = 'IM-3: Manage application identities securely and automatically'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-3-manage-application-identities-securely-and-automatically' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz911
{
	try
	{
		
		$Violation = @()
		$AzKeyVaults = Get-AzKeyVault
		foreach ($AzKeyVault in $AzKeyVaults){
			$KeyVaultDetails = Get-AzKeyVault -VaultName $AzKeyVault.VaultName
			$KeyVaultSecret = Get-AzKeyVaultSecret -VaultName $AzKeyVault.VaultName -ErrorAction SilentlyContinue
				if ([string]::IsNullOrEmpty($KeyVaultSecret) -or $KeyVaultSecret.Enabled -ne $true){
					$Violation += "No KeyVault Secrets in KeyVault stored."
				}
		}
		
		
		if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz911 -ReturnedValue $Violation -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
            return $FinalObject
        }

        $FinalObject = Build-CISAz911 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
        return $FinalObject
    }
    catch
    {
        $EndObject = Build-CISAz911 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz911