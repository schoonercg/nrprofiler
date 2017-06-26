echo "Hostname:" > c:\NRprofile.txt
hostname >> c:\NRprofile.txt
echo "IP information:" >> c:\NRprofile.txt
cmd /c ipconfig /all >> c:\NRprofile.txt
echo "Windows Version:" >> c:\NRprofile.txt
(Get-WmiObject -class Win32_OperatingSystem).Caption >> c:\NRprofile.txt
echo "Features Installed" >> c:\NRprofile.txt
Import-module servermanager ; Get-WindowsFeature | where-object {$_.Installed -eq $True} | format-list DisplayName >> c:\NRprofile.txt
echo "Installed Updates" >> c:\NRprofile.txt
Get-HotFix >> c:\NRprofile.txt
echo "Installed applications" >> c:\NRprofile.txt
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize >> c:\NRprofile.txt
echo "IIS Apps:" >> c:\NRprofile.txt
cmd /c  %systemroot%\system32\inetsrv\APPCMD list app >> c:\NRprofile.txt
echo "IIS Sites:" >> c:\NRprofile.txt
cmd /c  %systemroot%\system32\inetsrv\APPCMD list site >> c:\NRprofile.txt
echo "IIS AppPools:" >> c:\NRprofile.txt
cmd /c  %systemroot%\system32\inetsrv\APPCMD list apppool >> c:\NRprofile.txt
echo "Users and Administrators" >> c:\NRprofile.txt
net user >> c:\NRprofile.txt
net localgroup >> c:\NRprofile.txt
net localgroup Administrators >> c:\NRprofile.txt
echo "Running Services" >> c:\NRprofile.txt
net start >> c:\NRprofile.txt
echo "Firewall Rules" >> c:\NRprofile.txt
netsh advfirewall firewall show rule name=all >> c:\NRprofile.txt
echo "END" >> c:\NRprofile.txt