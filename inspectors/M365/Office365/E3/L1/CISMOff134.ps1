#Requires -module Az.Accounts
# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff134
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    #Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMOff134"
        ID               = "1.3.4"
        Title            = "(L1) Ensure 'User owned apps and services' is restricted"
        ProductFamily    = "Microsoft Office 365"
        DefaultValue     = "iwpurchaseallowed: True / iwpurchasefeatureenabled: True"
        ExpectedValue    = "iwpurchaseallowed: False / iwpurchasefeatureenabled: False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Attackers commonly use vulnerable and custom-built add-ins to access data in user applications. While allowing users to install add-ins by themselves does allow them to easily acquire useful add-ins that integrate with Microsoft applications, it can represent a risk if not used and monitored carefully. Disable future user's ability to install add-ins in Microsoft Word, Excel, or PowerPoint helps reduce your threat-surface and mitigate this risk."
        Impact           = "Implementation of this change will impact both end users and administrators. End users will not be able to install add-ins that they may want to install."
        Remediation      = 'Uncheck all 3 boxes: https://admin.microsoft.com/Adminportal/Home#/Settings/Services/:/Settings/L1/Store'
        References       = @(@{ 'Name' = 'Manage add-in downloads by turning on/off the Office store across all apps (Except Outlook)'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/admin/manage/manage-addins-in-the-admin-center?view=o365-worldwide#manage-add-in-downloads-by-turning-onoff-the-office-store-across-all-apps-except-outlook' })
    }
    return $inspectorobject
}

function Audit-CISMOff134
{
	try
	{
		$AffectedSettings = @()
		# Actual Script
		$AccessStoreSetting = Invoke-MultiMicrosoftAPI -Url "https://admin.microsoft.com/admin/api/storesettings/iwpurchaseallowed" -Resource "https://admin.microsoft.com" -Method 'GET'
		$StartTrialsSetting = Invoke-MultiMicrosoftAPI -Url "https://admin.microsoft.com/admin/api/storesettings/iwpurchasefeatureenabled" -Resource "https://admin.microsoft.com" -Method 'GET'
		
		# Validation
		if ($AccessStoreSetting -eq $true)
		{
			$AffectedSettings += "iwpurchaseallowed: $($AccessStoreSetting)"
		}
		else 
		{
			$CorrectSettings += "iwpurchaseallowed: $($AccessStoreSetting)"
		}
		if ($StartTrialsSetting -eq $true)
		{
			$AffectedSettings += "iwpurchasefeatureenabled: $($StartTrialsSetting)"
		}
		else
		{
			$CorrectSettings += "iwpurchasefeatureenabled: $($StartTrialsSetting)"
		}
		if ($AffectedSettings.Count -igt 0)
		{
			$endobject = Build-CISMOff134 -ReturnedValue $AffectedSettings -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMOff134 -ReturnedValue $CorrectSettings -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISMOff134 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
function Invoke-MultiMicrosoftAPI
{
	param (
		#The whole URL to call
		[Parameter()]
		[String]$Url,
		#The Name of the Resource
		[Parameter()]
		[String]$Resource,
		[Parameter()]
		#Body if a POST or PUT
		[Object]$Body,
		[Parameter()]
		#Specify the HTTP Method you wish to use. Defaults to GET
		[ValidateSet("GET", "POST", "OPTIONS", "DELETE", "PUT")]
		[String]$Method = "GET"
	)
	
	try
	{
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	catch
	{
		Connect-AzAccount -ErrorAction Stop
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	
	#Specify Resource
	$apiToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $Resource)
	
	# Creating the important header
	$header = [ordered]@{
		'Authorization' = 'Bearer ' + $apiToken.AccessToken.ToString()
		'Content-Type'  = 'application/json'
		'X-Requested-With' = 'XMLHttpRequest'
		'x-ms-client-request-id' = [guid]::NewGuid()
		'x-ms-correlation-id' = [guid]::NewGuid()
	}
	# URL Where PUT Request is being done. You can extract this from F12 
	
	$method = 'GET'
	
	#In Case your Method is PUT or POST to edit something. Change things here
	
	if ($method -eq 'PUT')
	{
		# Remediation Scripts HERE
		$contentpart1 = '{"restrictNonAdminUsers":false}'
		
		#Convert the content (DUMMY)
		$Body = $contentpart1
		
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'POST')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'GET')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -ErrorAction Stop
	}
	return $Response
}
return Audit-CISMOff134