
function PowershellClientCredentialsLogin {
    param (
        [Parameter(Mandatory = $true)][String]$clientId,
        [Parameter(Mandatory = $true)][String]$tenantId,
        [Parameter(Mandatory = $true)][String]$clientSecret,
        [Parameter(Mandatory = $false)][String]$scope 
    )
    ### Static vars ###
    $tokenUrl = ('https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $tenantId)

    ### Build the body for the clientSecret flow ###
    $body = @{
        client_id     = $clientId
        tenant        = $tenantId
        client_secret = $clientSecret
        grant_type    = "client_credentials"
        scope         = $scope
    }

    ### Call token endpoint to retrieve access token ###
    $response = Invoke-WebRequest -Method Post -Uri $tokenUrl -Body $body
    if ($response.StatusCode -eq "200") {
        $content = ($response.Content | ConvertFrom-Json)
        return @{
            access_token = $content.access_token
        }
    }
    else {
        Write-Warning "Access Code retrieval failed: $($response.StatusCode)"
    }
}

$settingsPath = "..\.vscode\settings.json"

if (Test-Path $settingsPath) {
    $settings = Get-Content $settingsPath | ConvertFrom-Json
    $tenantId = $settings."credential-flow.settings".tenandId
    $clientId = $settings."credential-flow.settings".apiClientId
    $clientSecret = $settings."credential-flow.settings".apiClientSecret
    $scope = $settings."credential-flow.settings".scope
} else {
    Write-Error "Settings file not found at path: $settingsPath"
    exit
}
### Retrieve access token using client secret ###
$tokens = PowershellClientCredentialsLogin -tenantId $tenantId -clientId $clientId -clientSecret $clientSecret -scope $scope

$accessToken = $tokens.access_token
Write-Output "Access Token: $accessToken"