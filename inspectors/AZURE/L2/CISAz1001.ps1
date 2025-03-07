# Date: 26-09-2024
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz1001
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz1001"
        ID               = "10.1"
        Title            = "(L1) Ensure that Resource Locks are set for Mission-Critical Azure Resources"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Enabled"
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "As an administrator, it may be necessary to lock a subscription, resource group, or resource to prevent other users in the organization from accidentally deleting or modifying critical resources. The lock level can be set to CanNotDelete or ReadOnly to achieve this purpose."
        Impact           = "There can be unintended outcomes of locking a resource. Applying a lock to a parent service will cause it to be inherited by all resources within. Conversely, applying a lock to a resource may not apply to connected storage, leaving it unlocked. Please see the documentation for further information."
        Remediation      = "Use the PowerShell script to remediate the issue: Get-AzResourceLock -ResourceName <Resource Name> -ResourceType <ResourceType> -ResourceGroupName <Resource Group Name> -Locktype <CanNotDelete/Read-only>"
        References       = @(
            @{ 'Name' = 'Lock your resources to protect your infrastructure'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources?tabs=json' },
            @{ 'Name' = 'Azure enterprise scaffold is now the Microsoft Cloud Adoption Framework for Azure'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/resources/azure-scaffold#azure-resource-locks' },
            @{ 'Name' = 'Understand resource locking in Azure Blueprints'; 'URL' = 'https://learn.microsoft.com/en-us/azure/governance/blueprints/concepts/resource-locking' },
            @{ 'Name' = 'AM-4: Limit access to asset management'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-asset-management#am-4-limit-access-to-asset-management' }
        )
    }

    return $inspectorobject
}

function Audit-CISAz1001
{
	try
	{
		$Violation = @()
		#Resource Group
		$AzResources = Get-AzResource | Select-Object ResourceGroupName -Unique
		foreach ($Resource in $AzResources){
			$ResourceLock = Get-AzResourceLock -ResourceGroupName $Resource.ResourceGroupName -AtScope | Select-Object -Unique
			if ([String]::IsNullOrEmpty($ResourceLock)){
				$Violation += $Resource.ResourceGroupName
			}
		}
		#Resouces Based
		$AzResources = Get-AzResource | Select-Object ResourceGroupName,ResourceId,ResourceName,ResourceType -Unique
		foreach ($Resource in $AzResources){
			$ResourceLock = Get-AzResourceLock -ResourceName $Resource.ResourceName -ResourceGroupName $Resource.ResourceGroupName -ResourceType $Resource.ResourceType  | Select-Object -Unique
			if ([String]::IsNullOrEmpty($ResourceLock)){
				$Violation += $Resource.ResourceGroupName
			}
		}

		if ($Violation.Count -gt 0)
        {
            $FinalObject = Build-CISAz1001 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }

        $FinalObject = Build-CISAz1001 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
        return $FinalObject
    }
    catch
    {
        $EndObject = Build-CISAz1001 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz1001