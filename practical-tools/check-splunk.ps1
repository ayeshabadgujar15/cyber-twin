$report = 'D:\cyber-twin\practical-tools\installers\splunk-check.txt'
& {
    Get-Service Splunkd -ErrorAction SilentlyContinue | Format-List Status
    Get-Process msiexec,splunk,splunkd -ErrorAction SilentlyContinue | Select-Object ProcessName,Id,CPU | Format-Table
    Get-ChildItem 'D:\Splunk' -ErrorAction Continue | Select-Object Name,LastWriteTime | Format-Table
    Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='MsiInstaller';StartTime=(Get-Date).AddMinutes(-30)} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | Format-List
    Get-Content 'D:\Splunk\var\log\splunk\splunkd.log' -Tail 12 -ErrorAction SilentlyContinue
} *> $report
