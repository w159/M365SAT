# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz543
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz543"
        ID               = "5.4.3"
        Title            = "(L1) Use Entra ID Client Authentication and Azure RBAC where possible"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default Cosmos DB does not have private endpoints enabled and its traffic is public to the network."
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "For sensitive data, private endpoints allow granular control of which services can communicate with Cosmos DB and ensure that this network traffic is private. You set this up on a case by case basis for each service you wish to be connected."
        Impact           = "Failure to secure Cosmos DB with Entra ID Client Authentication and Azure RBAC increases the potential attack surface and risks unauthorized access."
        Remediation      = 'Use the PowerShell Script to remediate the issue: Update-AzMySqlServer -ResourceGroupName <server>.ResourceGroupName -Name <Server>.Name -ssl-enforcement Enabled'
        References       = @(
            @{ 'Name' = 'Use control plane role-based access control with Azure Cosmos DB for NoSQL'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cosmos-db/nosql/security/how-to-grant-control-plane-role-based-access?tabs=built-in-definition%2Ccsharp&pivots=azure-interface-cli' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz543
{
    try
    {
        $Violation = @()
        $SubscriptionId = Get-AzContext
        $ResourceGroupNames = Get-AzResource | Select-Object ResourceGroupName -Unique
        foreach ($ResourceGroup in $ResourceGroupNames) {
            $Databases = Get-AzResource -ResourceType 'Microsoft.DocumentDB/databaseAccounts' -ResourceGroupName $ResourceGroup.ResourceGroupName
            foreach ($Database in $Databases) {
                $Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id)/resourceGroups/$($ResourceGroup.ResourceGroupName)/providers/Microsoft.DocumentDB/databaseAccounts/$($Database.Name)?api-version=2024-08-15").content | ConvertFrom-Json)
                if ($Settings.properties.disableLocalAuth -eq $false) {
                    $Violation += $Database.Name
                }
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz543 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz543 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz543 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz543
