### Load settings from VSCode settings.json ###
$settingsPath = "..\.vscode\settings.json"

if (Test-Path $settingsPath) {
    $settings = Get-Content $settingsPath | ConvertFrom-Json
    $password = ConvertTo-SecureString -String $settings."credential-flow.settings".password -Force -AsPlainText
    $subjectName = $settings."credential-flow.settings".SubjectName
} else {
    Write-Error "Settings file not found at path: $settingsPath"
    exit
}

### Create self-signed certificate and store in user certificate store ###
$certificateParams = @{
    Subject           = $subjectName
    CertStoreLocation = "Cert:\CurrentUser\My"
}
$certificate = New-SelfSignedCertificate  @certificateParams

### Export the public key to be uploaded into your app registration ###
Export-Certificate -Cert $certificate -FilePath "public.cer" -Force

### Export the private key to use to generate a JWT ###
Export-PfxCertificate -Cert $certificate -FilePath "private.pfx" -Password $password -Force