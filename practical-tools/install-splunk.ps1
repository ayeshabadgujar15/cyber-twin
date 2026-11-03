$ErrorActionPreference = 'Stop'
$resultPath = 'D:\cyber-twin\practical-tools\installers\splunk-result.txt'
try {
    $installerPath = 'D:\cyber-twin\practical-tools\installers\splunk-complete-x64.msi'
    $signature = Get-AuthenticodeSignature -LiteralPath $installerPath
    if ($signature.Status -ne 'Valid') { throw 'Installer signature is not valid.' }
    if ($signature.SignerCertificate.Subject -notmatch 'Splunk|Cisco') { throw 'Unexpected installer publisher.' }
    $passwordBytes = New-Object byte[] 16
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $random.GetBytes($passwordBytes)
    $random.Dispose()
    $splunkPassword = 'Aa9!' + ([BitConverter]::ToString($passwordBytes).Replace('-', ''))
    $loginPath = 'D:\Splunk-login.txt'
    "Splunk Enterprise`r`nURL: http://localhost:8000`r`nUsername: admin`r`nPassword: $splunkPassword" | Set-Content -LiteralPath $loginPath
    $installerArgs = '/i "' + $installerPath + '" AGREETOLICENSE=Yes INSTALLDIR="D:\Splunk" SPLUNKUSERNAME=admin SPLUNKPASSWORD=' + $splunkPassword + ' LAUNCHSPLUNK=1 INSTALL_SHORTCUT=1 /quiet /norestart'
    $installProcess = Start-Process -FilePath 'msiexec.exe' -ArgumentList $installerArgs -WindowStyle Hidden -Wait -PassThru
    "Installer exit code: $($installProcess.ExitCode)" | Set-Content -LiteralPath $resultPath
} catch {
    "Installation error: $($_.Exception.Message)" | Set-Content -LiteralPath $resultPath
    exit 1
}
