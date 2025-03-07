# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz81
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{ 
        UUID             = "CISAz81"
        ID               = "8.1"
        Title            = "(L2) Ensure an Azure Bastion Host Exists"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, the Azure Bastion service is not configured."
        ExpectedValue    = "An Azure Bastion service is configured."
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The Azure Bastion service allows organizations a more secure means of accessing Azure Virtual Machines over the Internet without assigning public IP addresses to those Virtual Machines. The Azure Bastion service provides Remote Desktop Protocol (RDP) and Secure Shell (SSH) access to Virtual Machines using TLS within a web browser, thus preventing organizations from opening up 3389/TCP and 22/TCP to the Internet on Azure Virtual Machines. Additional benefits of the Bastion service include Multi-Factor Authentication, Conditional Access Policies, and any other hardening measures configured within Azure Active Directory using a central point of access."
        Impact           = "The Azure Bastion service incurs additional costs and requires a specific virtual network configuration. The Standard tier offers additional configuration options compared to the Basic tier and may incur additional costs for those added features."
        Remediation      = 'Use the following PowerShell command to deploy an Azure Bastion service: New-AzBastion -ResourceGroupName <resource group name> -Name <bastion name> -PublicIpAddress $publicip -VirtualNetwork $virtualNet -Sku "Standard" -ScaleUnit <integer>'
        References       = @(
            @{ 'Name' = 'What is Azure Bastion?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/bastion/bastion-overview#sku' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz81
{
    try
    {
        # Check for Azure Bastion Hosts
        $Violation = @()
        $AzResources = Get-AzResource | Select-Object ResourceGroupName -Unique

        foreach ($AzResource in $AzResources)
        {
            $AzureBastions = Get-AzBastion -ResourceGroupName $AzResource.ResourceGroupName
            if ([String]::IsNullOrEmpty($AzureBastions))
            {
                $Violation += $AzResource.ResourceGroupName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz81 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz81 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz81 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz81
