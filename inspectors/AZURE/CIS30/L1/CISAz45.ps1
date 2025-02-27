# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Call the OutPath Variable here
$path = @($OutPath)

# Build Function
function Build-CISAz45
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz45"
        ID               = "4.5"
        Title            = "(L1) Ensure that Shared Access Signature Tokens Expire Within an Hour"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "480 or null"
        ExpectedValue    = "60"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "A shared access signature (SAS) is a URI that grants restricted access rights to Azure Storage resources. A shared access signature can be provided to clients who should not be trusted with the storage account key but for whom it may be necessary to delegate access to certain storage account resources. Providing a shared access signature URI to these clients allows them access to a resource for a specified period of time. This time should be set as low as possible and preferably no longer than an hour."
        Impact           = "Long expiry times on SAS tokens may expose resources to security risks."
        Remediation      = "Navigate to this URL to change the SAS-token expiry: https://portal.azure.com/#browse/Microsoft.Storage%2FStorageAccounts"
        References       = @(
            @{ 'Name' = 'Delegate access by using a shared access signature'; 'URL' = 'https://learn.microsoft.com/en-us/rest/api/storageservices/delegate-access-with-shared-access-signature' },
            @{ 'Name' = 'Grant limited access to Azure Storage resources using shared access signatures (SAS)'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview' }
        )
    }
    return $inspectorobject
}

# Audit Function
function Audit-CISAz45
{
    try
    {
        $Violation = @()
        $StorageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName, ResourceGroupName

        foreach ($StorageAccount in $StorageAccounts){
            try {
                $StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)[0].Value
                $AzStorageContext = New-AzStorageContext -StorageAccountName $StorageAccount.StorageAccountName -StorageAccountKey $StorageAccountKey -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                $AzKeyVaults = Get-AzKeyVault

                foreach ($Keyvault in $AzKeyVaults){
                    $secrets = Get-AzKeyVaultSecret -VaultName $Keyvault.VaultName -ErrorAction SilentlyContinue

                    foreach ($secret in $secrets){
                        # Retrieve the secret value as a SecureString
                        $secretValue = $secret.SecretValue | ConvertFrom-SecureString -AsPlainText

                        # Extract the expiry time from the secret value
                        $expiryTimeString = ($secretValue -split '&') | Where-Object { $_ -like 'se=*' }

                        # Extract the actual expiry time value from the string
                        $expiryTimeValue = ($expiryTimeString -split '=')[1]

                        # Decode the URL-encoded datetime string
                        $decodedExpiryTimeValue = [System.Web.HttpUtility]::UrlDecode($expiryTimeValue)

                        # Parse the decoded expiry time value as a datetime
                        $expiryTime = [datetime]::Parse($decodedExpiryTimeValue)

                        if ($expiryTime -gt (Get-Date).AddHours(1)) {
                            # Do nothing if expiry is greater than an hour
                        } else {
                            $Violation += "Secret '$secretName' is still valid and set to expire at $expiryTime"
                        }
                    }
                }
            }
            catch {
                continue
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz45 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz45 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz45 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz45
