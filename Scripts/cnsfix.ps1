# Stop services if running, then delete them
$services = @(
    "cybercnsagent",
    "cybercnsagentv2",
    "cybercnsagentmonitor"
)
​
foreach ($service in $services) {
    Write-Host "Stopping service: $service"
    Stop-Service -Name $service -ErrorAction SilentlyContinue
​
    Write-Host "Deleting service: $service"
    sc.exe delete $service
}
​
#Deletes CyberCNSAgent folder and its contents
Remove-Item -Path "C:\Program Files (x86)\CyberCNSAgent" -Recurse -Force