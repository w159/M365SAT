# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz74
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{ 
        UUID             = "CISAz74"
        ID               = "7.4"
        Title            = "(L1) Ensure that HTTP(S) access from the Internet is evaluated and restricted"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Disabled"
        ExpectedValue    = "Disabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The potential security problem with using HTTP(S) over the Internet is that attackers can use various brute force techniques to gain access to Azure resources. Once the attackers gain access, they can use the resource as a launch point for compromising other resources within the Azure tenant."
        Impact           = "Failure to restrict HTTP(S) access from the Internet increases the risk of unauthorized access and potential security breaches."
        Remediation      = "No PowerShell Script Available"
        References       = @( 
            @{ 'Name' = 'NS-1: Establish network segmentation boundaries'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-1-establish-network-segmentation-boundaries' },
            @{ 'Name' = 'ExpressRoute documentation'; 'URL' = 'https://learn.microsoft.com/en-us/azure/expressroute/' },
            @{ 'Name' = 'Tutorial: Create a site-to-site VPN connection in the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/vpn-gateway/tutorial-site-to-site-portal' },
            @{ 'Name' = 'Configure server settings for P2S VPN Gateway certificate authentication'; 'URL' = 'https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal' }
        )
    }

    return $inspectorobject
}

function Audit-CISAz74
{
    try
    {
        # Network Security Group (NSG) Rule Checking
        $Violation = @()
        $azNsgs = Get-AzNetworkSecurityGroup

        foreach ($azNsg in $azNsgs)
        {
            $SecurityRuleConfig = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $azNsg | Where-Object { 
                $_.Access -eq "Allow" -and
                ($_.DestinationPortRange -eq "443" -or $_.DestinationPortRange -eq "80" -or $_.DestinationPortRange -eq '*') -and 
                $_.Direction -eq "Inbound" -and 
                ($_.Protocol -eq "TCP" -or $_.Protocol -eq '*') -and
                ($_.SourceAddressPrefix -eq '*' -or 
                $_.SourceAddressPrefix -eq "0.0.0.0" -or 
                $_.SourceAddressPrefix -match "/0" -or 
                $_.SourceAddressPrefix -eq "internet" -or 
                $_.SourceAddressPrefix -eq "any")
            }

            if ($SecurityRuleConfig)
            {
                $Violation += $azNsg.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz74 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz74 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz74 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz74
