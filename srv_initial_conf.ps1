#
# srv_initial_conf.ps1
#
#Enable File/Print Sharing on Servers
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes

#Enable WinRM
winrm quickconfig -q
netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" new enable=Yes

#Enable WMI Firewall Exception on Servers
netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=Yes
