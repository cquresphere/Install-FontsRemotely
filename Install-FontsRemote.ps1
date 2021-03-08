#Check if ImportExcel module is installed
$IsImportExcel = Get-InstalledModule -Name ImportExcel

if($IsImportExcel -eq $null){
    Install-Module -Name ImportExcel -Force
}

$ComputerTo = Import-Excel -Path <path to list with hostnames/IPs to install fonts>  | %{$_.HostName}


# Enter you path to psexec
$PsExecPath = '<path to psexec>\psexec.exe'
#Computers to install fonts to
$ComputerArray= $ComputerTo 
#A Share containing only the fonts you want to install
$FontDir= <Path to Fonts> 
#Wil be created on remote Pc if not exists, fonts will be copied here and deleted after install.
$PcStagingDir="c:\Temp\Fonts"
#Get Credentials 
$cred = Get-Credential
 
foreach($pc in $ComputerArray){
    $IsPCOnline = Test-Connection -ComputerName  $pc -Count  1 -ErrorAction SilentlyContinue
    $IsAccess = Test-Path -Path "\\$pc\c$\"
    if((-not $IsPCOnline) -or ($IsAccess -eq $false)){
        Write-Host "Could NOT connect to $pc Skipping Computer $pc" -ForegroundColor Red
        Continue
    }
    Write-Host "$pc is online" -ForegroundColor Magenta

    $IsFontInstalled = ((Get-ChildItem -Path "$FontDir\*").Name  | %{Test-Path -Path "\\$pc\c$\Windows\Fonts\$_"}) -contains $False
    if($IsFontInstalled -eq $False){
        Write-Host "$pc has fonts installed already" -ForegroundColor Green
        Continue
    }
    else{
        $IsWinRMRun = Test-WSMan -ComputerName $pc -ErrorAction SilentlyContinue
        if(-not $IsWinRMRun){
            try{
                Start-Process -Filepath $PsExecPath -Argumentlist "\\$pc -h -d winrm.cmd quickconfig -q" -Credential $cred
            }
            Catch [InvalidOperationException]{
                Write-Host "$($error[0].ToString())" -ForegroundColor Red
                break
            }
            Write-Host "Enabling WINRM Quickconfig on $pc" -ForegroundColor Green
            Write-Host "Waiting for 60 Seconds......." -ForegroundColor Yellow
            Start-Sleep -Seconds 60 -Verbose	
            Start-Process -Filepath $PsExecPath -Argumentlist "\\$pc -h -d powershell.exe enable-psremoting -force" -Credential $cred
            Write-Host "Enabling PSRemoting on $pc" -ForegroundColor Green
            Start-Process -Filepath $PsExecPath -Argumentlist "\\$pc -h -d powershell.exe set-executionpolicy RemoteSigned -force" -Credential $cred
            Write-Host "Enabling Execution Policy on $pc" -ForegroundColor Green
            Start-Process -Filepath $PsExecPath -Argumentlist "\\$pc -h -d powershell.exe Set-NetFirewallRule -Enabled True -Name WINRM-HTTP-In-TCP-NoScope -force" -Credential $cred
            Write-Host "Enabling Firewall Rule - WINRM-HTTP-In-TCP-NoScope on $pc" -ForegroundColor Green
            Start-Process -Filepath $PsExecPath -Argumentlist "\\$pc -h -d powershell.exe Set-NetFirewallRule -Enabled True -Name WINRM-HTTP-In-TCP -force" -Credential $cred
            Write-Host "Enabling Firewall Rule - WINRM-HTTP-In-TCP on $pc" -ForegroundColor Green
            
                  
        }
        $RemotePcStagingDir = "\\$pc\$($PcStagingDir.replace(':','$'))"
        $RemoteWinDir= 'C:\Windows' #Invoke-Command -ComputerName $pc -ScriptBlock {return $env:windir}
        if(-not(Test-Path $RemotePcStagingDir)){
            New-Item -Path $RemotePcStagingDir -ItemType "directory" -Force 
            }
        foreach($FontFile in (Get-ChildItem -file -path $FontDir)){
            if(-not(Test-Path "\\$pc\$($RemoteWinDir.replace(':','$'))\Fonts\$FontFile")){
                Copy-Item "$FontDir\$FontFile" -Destination $RemotePcStagingDir -Force
                Invoke-Command -ComputerName $pc -ScriptBlock {
               $filePath="$using:PcStagingDir\$using:FontFile"
               $fontRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
               $fontsFolderPath = "$($env:windir)\fonts"
            # Create hashtable containing valid font file extensions and text to append to Registry entry name.
            $hashFontFileTypes = @{}
            $hashFontFileTypes.Add(".fon", "")
            $hashFontFileTypes.Add(".fnt", "")
            $hashFontFileTypes.Add(".ttf", " (TrueType)")
            $hashFontFileTypes.Add(".ttc", " (TrueType)")
            $hashFontFileTypes.Add(".otf", " (OpenType)")
            try
            {
                [string]$filePath = (Get-Item $filePath).FullName
                [string]$fileDir  = split-path $filePath
                [string]$fileName = split-path $filePath -leaf
                [string]$fileExt = (Get-Item $filePath).extension
                [string]$fileBaseName = $fileName -replace($fileExt ,"")
        
                $shell = new-object -com shell.application
                $myFolder = $shell.Namespace($fileDir)
                $fileobj = $myFolder.Items().Item($fileName)
                $fontName = $myFolder.GetDetailsOf($fileobj,21)
                
                if ($fontName -eq "") { $fontName = $fileBaseName }
        
                copy-item $filePath -destination $fontsFolderPath
        
                $fontFinalPath = Join-Path $fontsFolderPath $fileName
                if (-not($hashFontFileTypes.ContainsKey($fileExt))){Write-Host "File Extension Unsupported";$retVal = 0}
                if ($retVal -eq 0) {
                    Write-Host "Font `'$($filePath)`'`' installation failed on $env:computername" -ForegroundColor Red
                    Write-Host ""
                    1
                }
                
                else
                {
                    Set-ItemProperty -path "$($fontRegistryPath)" -name "$($fontName)$($hashFontFileTypes.$fileExt)" -value "$($fileName)" -type STRING
                    Write-Host "Font `'$($filePath)`' $fontName $($hashFontFileTypes.$fileExt) installed successfully on $env:computername" -ForegroundColor Green
                }
        
            }
            catch
            {
                Write-Host "An error occured installing `'$($filePath)`' on $env:computername" -ForegroundColor Red
                Write-Host "$($error[0].ToString())" -ForegroundColor Red
                $error.clear()
            }
            }
             }
             Remove-Item "$RemotePcStagingDir\$FontFile" -ErrorAction SilentlyContinue
        }
        
            $a = '"'
			$RegPath = "$a\\$pc\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system$a"   
            Write-Host "Setting service WinRM StartType to Disabled on $pc ..."
            Set-Service -ComputerName $pc -Name "WinRM" -StartupType Disabled -ErrorAction SilentlyContinue
            $commandz="sc \\"+$pc +" Stop "+"WinRM"
            cmd.exe /c $commandz | Out-Null
            Start-Process -Filepath $PsExecPath -Argumentlist "\\$pc -h -d powershell.exe enable-psremoting -force" -Credential $cred
            Write-Host "Diabling PSRemoting on $pc" -ForegroundColor Yellow
            Start-Process -Filepath $PsExecPath -Argumentlist "\\$pc -h -d powershell.exe set-executionpolicy Restricted -force" -Credential $cred
            Write-Host "Disabling Execution Policy on $pc" -ForegroundColor Yellow
            Start-Process -Filepath $PsExecPath -Argumentlist "\\$pc -h -d powershell.exe Set-NetFirewallRule -Enabled False -Name WINRM-HTTP-In-TCP-NoScope -force" -Credential $cred
            Write-Host "Disabling Firewall Rule - WINRM-HTTP-In-TCP-NoScope on $pc" -ForegroundColor Yellow
            Start-Process -Filepath $PsExecPath -Argumentlist "\\$pc -h -d powershell.exe Set-NetFirewallRule -Enabled False -Name WINRM-HTTP-In-TCP -force" -Credential $cred
            Write-Host "Disabling Firewall Rule - WINRM-HTTP-In-TCP on $pc" -ForegroundColor Yellow
            Start-Process -Filepath $PsExecPath -Argumentlist "\\$pc -h -d powershell.exe Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse -Force" -Credential $cred
            Write-Host "Removing WSMan listeners" -ForegroundColor Yellow
            Start-Process -Filepath $PsExecPath -Argumentlist "\\$pc -h -d reg add $RegPath /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f"
            Write-Host "Disable access to Windows Administrative Shares on $pc" -ForegroundColor Yellow
            Start-Sleep -Seconds 12
            $IsWinRMRun = Test-WSMan -ComputerName $pc -ErrorAction SilentlyContinue
            if(-not $IsWinRMRun) {
                Write-Host "WinRM service is stopped on $pc" -ForegroundColor Yellow
            }
            Else{
                Write-Host "WinRM service is still running on $pc" -ForegroundColor Red
            }
        }    
}
     