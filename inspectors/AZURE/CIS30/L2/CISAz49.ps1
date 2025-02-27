# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz49
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz49"
        ID               = "4.9"
        Title            = "(L2) Ensure Private Endpoints are used to access Storage Accounts"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, Private Endpoints are not created for Storage Accounts."
        ExpectedValue    = "A private endpoint used for access"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Securing traffic between services through encryption protects the data from easy interception and reading."
        Impact           = "A Private Endpoint costs approximately 7.30 US Dollars per month. If an Azure Virtual Network is not implemented correctly, this may result in the loss of critical network traffic."
        Remediation      = "Use private endpoints for storage access. You can configure this by executing the following PowerShell command: Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -Bypass AzureServices"
        References       = @(
            @{ 'Name' = 'Use private endpoints for Azure Storage'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints' },
            @{ 'Name' = 'What is Azure Virtual Network?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview' },
            @{ 'Name' = 'Quickstart: Create a private endpoint by using the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-portal?tabs=dynamic-ip' },
            @{ 'Name' = 'Quickstart: Create a private endpoint by using the Azure CLI'; 'URL' = 'https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-cli?tabs=dynamic-ip' },
            @{ 'Name' = 'Quickstart: Create a private endpoint by using Azure PowerShell'; 'URL' = 'https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip' },
            @{ 'Name' = 'Tutorial: Connect to a storage account using an Azure Private Endpoint'; 'URL' = 'https://learn.microsoft.com/en-us/azure/private-link/tutorial-private-endpoint-storage-portal?tabs=dynamic-ip' },
            @{ 'Name' = 'NS-2: Secure cloud native services with network controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls' }
        )
    }
    return $inspectorobject
}


function Audit-CISAz49
{
    try
    {
        $violation = @()
        $StorageAccounts = Get-AzStorageAccount | Get-AzPrivateEndpoint

        if ([string]::IsNullOrEmpty($StorageAccounts)){
            return $null
        }

        # The script should check if Private Endpoints are used
        foreach ($Account in $StorageAccounts){
            if ($Account.PrivateLinkServiceConnections.Count -eq 0){
                $violation += $Account.StorageAccountName
            }
        }

        if ($violation.Count -gt 0){
            $finalobject = Build-CISAz49 -ReturnedValue $violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $finalobject
        }
        else {
            $finalobject = Build-CISAz49 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $finalobject
        }
    }
    catch
    {
        $EndObject = Build-CISAz49 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz49
