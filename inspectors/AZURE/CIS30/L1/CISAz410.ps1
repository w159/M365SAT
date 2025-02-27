# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz410
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
	)

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz410"
        ID               = "4.10"
        Title            = "(L1) Ensure Soft Delete is Enabled for Azure Containers and Blob Storage"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Disabled"
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Containers and Blob Storage data can be incorrectly deleted. An attacker or malicious user may do this deliberately in order to cause disruption. Enabling soft delete ensures that deleted blobs/data objects are recoverable within a retention period, ranging from 7 to 365 days."
        Impact           = "Additional storage costs may be incurred as snapshots are retained."
        Remediation      = 'Use the following PowerShell command to enable soft delete: Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -EnableSoftDelete'
        References       = @(
            @{ 'Name' = 'Soft delete for blobs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview' },
            @{ 'Name' = 'Soft delete for containers'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-overview' },
            @{ 'Name' = 'Enable and manage soft delete for containers'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-enable?tabs=azure-portal' }
        )
    }
    return $inspectorobject
}


function Audit-CISAz410
{
    try
    {
        $violation = @()
        $contexts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName,ResourceGroupName
        foreach ($context in $contexts){
            $BlobServiceProperty = Get-AzStorageBlobServiceProperty -ResourceGroupName $context.ResourceGroupName -StorageAccountName $context.StorageAccountName
            foreach ($ServiceProperty in $BlobServiceProperty){
                $CDRP = $false
                $CDRPD = $false
                if ($ServiceProperty.ContainerDeleteRetentionPolicy.Enabled -eq $false){
                    $CDRP = $true
                }elseif ($ServiceProperty.ContainerDeleteRetentionPolicy.Days -ilt 7 -or $ServiceProperty.ContainerDeleteRetentionPolicy.Days -igt 365){
                    $CDRPD = $true
                }
                $DelRP =  $false
                $DelRPD = $false
                if ($ServiceProperty.DeleteRetentionPolicy.Enabled -eq $false){
                    $DelRP =  $true
                }elseif ($ServiceProperty.DeleteRetentionPolicy.Days -ilt 7 -or $ServiceProperty.DeleteRetentionPolicy.Days -igt 365){
                    $DelRPD = $true
                }
                if ($CDRP -eq $True -or $CDRPD -eq $True -or $DelRP -eq $True -or $DelRPD -eq $True){
                    $violation += $ServiceProperty.StorageAccountName
                }
            }
        }

        if ($violation.Count -gt 0){
            $finalObject = Build-CISAz410 -ReturnedValue $violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $finalObject
        } else {
            $finalObject = Build-CISAz410 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $finalObject
        }
        return $null
    }
    catch
    {
        $EndObject = Build-CISAz410 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz410
