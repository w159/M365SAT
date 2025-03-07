# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh


# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5152
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5152"
        ID               = "5.1.5.2"
        Title            = "(L1) Ensure the admin consent workflow is enabled"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "EnableAdminConsentRequests: False \n notificationsEnabled: True \n remindersEnabled: True \n approvers: null \n approversv2: null \n requestExpiresInDays: 30"
        ExpectedValue    = "EnableAdminConsentRequests: True \n notificationsEnabled: True \n remindersEnabled: True \n approvers: at least 1 \n approversv2: at least 1 \n requestExpiresInDays: 30"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The admin consent workflow allows admins to securely grant access to applications requiring admin approval. Without this workflow, users may be unable to access necessary applications, and critical access decisions might bypass security oversight."
        Impact           = "To approve requests, a reviewer must be a global administrator, cloud application administrator, or application administrator. The reviewer must already have one of these admin roles assigned; simply designating them as a reviewer doesn't elevate their privileges."
        Remediation	 	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings'
        References       = @(
            @{ 'Name' = 'Configure the admin consent workflow'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5152
{
	try
	{
		# Actual Script
		$Violation = @()
		$ConsentPolicySettings = Get-MgBetaDirectorySetting | Where-Object {$_.TemplateId -eq 'dffd5d46-495d-40a9-8e21-954ff55e198a'}
		$Setting = $ConsentPolicySettings.Values | Where-Object {$_.Name -eq 'EnableAdminConsentRequests'}
		if ($Setting.Value -ne $true){
			$Violation += "EnableAdminConsentRequests: False"
		}
		else{
			$AdvancedSettings = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/RequestApprovals/V2/PolicyTemplates?type=AdminConsentFlow' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
			if ($AdvancedSettings.notificationsEnabled -ne $True){
				$Violation += "AdminConsentPolicy: NotificationsEnabled: $($AdvancedSettings.notificationsEnabled)"
			}
		}
		
		# Validation
		if ($Violation.Count -igt 0)
		{
			$Violation | Format-Table -AutoSize | Out-File "$path\CISMAz5152-AdminConsentPolicy.txt"
			$endobject = Build-CISMAz5152 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5152 -ReturnedValue "EnableAdminConsentRequests: True / AdminConsentPolicy: NotificationsEnabled: $($AdvancedSettings.notificationsEnabled)" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5152 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
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

return Audit-CISMAz5152
