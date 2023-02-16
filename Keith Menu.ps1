#LondonDealingRoomSupport
        # File Name      : Keith Menu.ps1
        # Author         : Keith Scofield

Function Show-Menu {

Param(
[Parameter(Position=0,Mandatory=$True,HelpMessage="Enter your menu text")]
[ValidateNotNullOrEmpty()]
[string]$Menu,
[Parameter(Position=1)]
[ValidateNotNullOrEmpty()]
[string]$Title="Menu",
[switch]$ClearScreen
)

if ($ClearScreen) {Clear-Host}

#build the menu prompt
$menuPrompt=$title
#add a return
$menuprompt+="`n"
#add an underline
$menuprompt+="-"*$title.Length
$menuprompt+="`n"
#add the menu
$menuPrompt+=$menu


Read-Host -Prompt $menuprompt

} #end function
#Enter the menu below...

$menu=@"
    
    Keith's Joint Menu:

    1. Enable Remote Desktop
    2. Logged on user
    3. Users AD groups
    4. Wallboard PC
    5. Force Log Off
    6. User Info
    7. USB WriteProtect (Registry)
    8. Copy file/folder
    9. Account Locked Out
    10.UBD Group
    11.CRM AD Group
        
    12 Find person logged on a computer
    13 Find PC where user is logged in
    14 View info about a specific user
    15 Users in a group (Excel)
    16 Group membership for a user (Excel)
    17 Is user in group?
    18 Copy ION Logs for User
    19 Logged in User List for computers in C:\Temp\PCs.csv
   
    20 PING Hostname
    30 EU Support Contacts

    99 Force Reboot

    Q Quit

Select a task by number or Q to exit
"@

#Looping and running menu until user quits

Do{
        #use a Switch construct to take action depending on what menu choice is selected.
        
    Switch (Show-Menu $menu "London Dealing Room Support" -clear) {
    
        "1" {$ComputerName = Read-Host -prompt "Enable Remote Desktop on" 

                Write-output "Enabling Remote Desktop on $Computername..."

                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName) 
                $regkey = $reg.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",$true)
                $regkey.SetValue('fDenyTSConnections','0','DWord')  
		
                Write-output "Remote Desktop is enabled on machine: $ComputerName" -ForegroundColor Green
	            start-process "C:\Windows\System32\mstsc.exe" -argumentlist "/v:$Computername /f"
                sleep -seconds 5
             }

        "2" {Import-Module activedirectory
                $PcName = Read-Host -prompt "Please enter the hostname of the machine"
                $colComputers = Get-ADComputer $PcName -Properties description | ForEach-Object {$_.Name} 
                foreach ($strComputer in $colComputers)
                { 
                $description = Get-ADComputer $strComputer -Properties description
                $Username = (Get-WmiObject -ComputerName $strComputer -class Win32_computersystem).username}
                if($username -like "*Rabo*") 
                {Write-Host $strComputer $username " | Description: " $description.description -ForegroundColor Green}
                Else
                {$description = Get-ADComputer $strComputer -Properties description
                Write-Host "Nobody logged in on $StrComputer | Description: " $description.description -ForegroundColor Red} 
             sleep -seconds 5
         
                }

        "3" {Import-Module activedirectory
                $user = Read-Host -Prompt "Please enter the users login"
                Get-ADUser $user -Properties * | Select memberof | select -Expand memberof > "C:\temp\MIDTUser.txt"
                Invoke-Item "C:\temp\MIDTUser.txt"  
                Write-Host "Your user information is now on your screen" -ForegroundColor Green
              }

        "4" { $ComputerName='LOTD122159'
                Write-Host "Enabling Remote Desktop on $Computername..."
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName) 
                $regkey = $reg.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",$true)
                $regkey.SetValue('fDenyTSConnections','0','DWord')   
                Write-Host "Enabling Remote Desktop on $Computername...Complete"
                start-process "C:\Windows\System32\mstsc.exe" -argumentlist "/v:$Computername /f"
                }
    
        "5"    {$Pcname = Read-host -prompt "Please enter the hostname"
            $Verification = Read-Host -Prompt "Please type the following security code: Rab0bank100"
            If ($verification -notmatch "Rab0bank100")
            {Write-host "Incorrect security code" -ForegroundColor Red}
            else
            {
            (Get-WmiObject -Class Win32_operatingsystem -ComputerName $Pcname).win32shutdown(4)
                    
            Write-Host "Everyone will be logged off" -ForegroundColor Green
            }
            
            sleep -Seconds 5
                        
            }   


        "6"    { Import-Module activedirectory
                        $user = Read-Host -Prompt "Please enter the users credentials"
                        Get-ADUser $user -Properties * | Select CN, SamAccountName, Title, DisplayName, EmployeeNumber, Department, EmailAddress, telephoneNumber, HomeDirectory, ProfilePath, AccountExpirationDate, LastLogonDate, LockedOut, PasswordExpired, PasswordLastSet > "C:\temp\MIDTUser.txt"
                        Invoke-Item "C:\temp\MIDTUser.txt"  
                        Write-Host "Your user information is now on your screen" -ForegroundColor Green
                }

        "7"  {$ComputerName = Read-Host -prompt "Enter hostname" 

            Write-Host "Enter hostname $Computername"

            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName) 
            $regkey = $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies",$true)
            $regkey.SetValue('WriteProtect','0','DWord')  
		
            Write-Host "Value in the registry has changed: $ComputerName" -ForegroundColor Green
            sleep -seconds 5
         }

        "8"  {$path = read-host -prompt "Enter Path of file/folder"
                $destination = read-host -prompt "Enter path destination"
                Write-Host "Enter Path of file/folder $path"
                Write-Host "Enter path destination $destination"
                Copy-Item -Path $path -Destination $destination
                Write-Host "file/folder has been copied" -ForegroundColor Green
                sleep -Seconds 3
               }

        "9" {Import-Module activedirectory
                        $user = Read-Host -Prompt "Please enter the users credentials"
                        Get-ADUser $user -Properties * | Select LockedOut
                        sleep -seconds 5
                        }

        "10" {#ri.app.CtxEUUBD.gs AD group

                    $username = Read-Host -Prompt "Enter Credentials"
                    Function Test-ADGroupMember {

                    Param ($User,$Group)

                    Trap {Return "Incorrect username"}

                    If (

                    Get-ADUser `
                    -Filter "memberOf -RecursiveMatch '$((Get-ADGroup $Group).DistinguishedName)'" `
                    -SearchBase $((Get-ADUser $User).DistinguishedName)
                    ) {$true}
                    Else {$false}
                                                }

                    Test-ADGroupMember -user $username -group "ri.app.CtxEUUBD.gs"
                    sleep -Seconds 2

            }

        "11" {#eu.app.CRMOutlookAddin.gs CRM AD group

                    $username = Read-Host -Prompt "Enter Credentials"
                    Function Test-ADGroupMember {

                    Param ($User,$Group)

                    Trap {Return "Incorrect username"}

                    If (

                    Get-ADUser `
                    -Filter "memberOf -RecursiveMatch '$((Get-ADGroup $Group).DistinguishedName)'" `
                    -SearchBase $((Get-ADUser $User).DistinguishedName)
                    ) {$true}
                    Else {$false}
                                                }

                    Test-ADGroupMember -user $username -group "eu.app.CRMOutlookAddin.gs"
                    sleep -Seconds 2

            }
          
     "12" {       
            Import-Module activedirectory
         
            $Username = $null
            $colComputers = $null
            $Description = $null
            $PcName = Read-Host -prompt "Please enter the hostname of the machine"
            Try
            {
                $colComputers = Get-ADComputer $PcName -Properties description | ForEach-Object {$_.Name} 
                foreach ($strComputer in $colComputers)
                { 
                    $description = Get-ADComputer $strComputer -Properties description
                    #Get explorer.exe processes
                    $proc = Get-WmiObject win32_process -computer $strComputer -Filter "Name = 'explorer.exe'"
                    #Go through collection of processes
                    ForEach ($p in $proc) 
                    {
                        $Username = ($p.GetOwner()).User
                        if($Username -ne $null)
                        {
                            break
                        }
                    }
                }

                if($username -ne $null) 
                    {
                    Write-Host $strComputer $username " | Description: " $description.description -ForegroundColor Green
                    }
                Else
                   {
                   Write-Host "Nobody logged in on $StrComputer | Description: " $description.description -ForegroundColor Red
                   } 
                sleep -seconds 5
            } # End Try
            Catch
            {
                Write-Host "$PCName not in AD" -ForegroundColor Red   
                sleep -seconds 3
            }
         }

    # Find PC where user is logged in
    "13" {
        import-module activedirectory
        import-module DesktopSupportFunctions

        $FindUser = read-host -Prompt "Enter user name"
        $PCPrefix = read-host -prompt "Enter computer prefix (e.g. LOTD) or blank for all London computers"

        if($PCPrefix -ne "")
        {
            If($PCPrefix -in "LOND", "LOTD", "CDCD", "UTTD", "UTCD")
            {
                $PCPrefix = "$PCPrefix*"
                write-host "$PCPrefix"
                sleep -seconds 3

                $Computers =  Get-ADComputer  -Filter {(enabled -eq "true") -and (name -like $PCPrefix)} | Select-Object -ExpandProperty Name
            }
            else
            {
                write-host "Prefix must be: LOND, LOTD, CDCD, UTTD or UTCD" -ForegroundColor red
                sleep -seconds 3
                $computers = $null
            }

        }            
        else # all London PCs
        {
            write-host "All london computers"
            $Computers =  Get-ADComputer  -Filter {(enabled -eq "true") -and ((name -like "LOTD*") -or (name -like "LOND*") -or (name -like "CDCD*"))} | Select-Object -ExpandProperty Name
        } # end if $PCprefix=null

        ForEach($Computer in $Computers)
        {
            #write-host $Computer
            $User = Get-LoggedOnUser -ComputerName $Computer
            #write-host $User
            if($User -ne $Null)
            {
                if($User -eq $FindUser)
                {
                    write-host "$User is logged in to $Computer"  -ForegroundColor Green
                    sleep -seconds 3
                    read-host -prompt "Press Enter to continue"
                    break
                } # end user found
            } # end $user=null
        } # end for each
    }

    # View info about a specific user
    "14" {
            Import-Module activedirectory
            $user = Read-Host -Prompt "Please enter the login name of the user"
            Get-ADUser $user -Properties * | Select CN, SamAccountName, Title, DisplayName, EmployeeNumber, Department, EmailAddress, telephoneNumber, HomeDirectory, ProfilePath, AccountExpirationDate, LastLogonDate, LockedOut, PasswordExpired, PasswordLastSet > "C:\temp\MIDTUser.txt"
            Invoke-Item "C:\temp\MIDTUser.txt"  
            Write-Host "Your user information is now on your screen" -ForegroundColor Green
            Sleep -Seconds 5
          }

    # Users in a group (Excel)
    "15" {
            import-module activedirectory
            import-module DesktopSupportFunctions  
            if(get-fileopen C:\Temp\GroupMembers.csv)
            {
                write-host "File: C:\Temp\GroupMembers.csv is slready open - close and rerun" -ForegroundColor Red
                sleep -seconds 3
            }
            else
            {
                $Group = read-host -Prompt "Enter group name"
                If(Get-ADGroup -filter {SamAccountName -eq $Group})
                {
                    $Results=@()

                    $Members = Get-ADGroupMember -Identity $Group -Recursive | Get-ADUser -Properties name, SamAccountName `
                        | Select name, SamAccountName | sort name
      
                    ForEach ($Member in $Members)
                    {
                        $Record = "" | Select Group, DisplayName, Username 
                        $Record.Group = $Group
                        $Record.DisplayName = $Member.name
                        $Record.Username = $Member.SamAccountName
                        $Results += $Record
                    }

                    $Results | Export-Csv -path C:\Temp\GroupMembers.csv -NoTypeInformation
                    Invoke-Item -Path C:\Temp\GroupMembers.csv
                    $ErrorActionPreference = "Stop"
                }
               ELSE
                {
                    Write-Host "Group: $Group not found in AD" -ForegroundColor Red
                    sleep -seconds 3
                }
        }
    }
    
    # Group membership for a user (Excel)
    "16" {
            import-module activedirectory
            import-module DesktopSupportFunctions  
            if(get-fileopen C:\Temp\UserGroups.csv)
            {
                write-host "File: C:\Temp\UserGroups.csv is slready open - close and rerun" -ForegroundColor Red
                sleep -seconds 3
            }
            else
            {
               $User = read-host -Prompt "Enter user name"
                If(Get-ADUser -filter {SamAccountName -eq $User})
                {
                    $Results=@()

                    $Aduser = Get-ADUser  -identity $User -Properties MemberOf 

                    $Groups=ForEach ($Group in $AdUser.MemberOf)
                            {
                                try
                                {
                                    (Get-AdGroup $Group).SamAccountName
                                
                                }
                                Catch
                                {
                                    "Error: $Group"
                                }
                            }
                    $Groups = $Groups | Sort
 
                    ForEach ($Group in $Groups)
                    {
                        $Record = "" | Select User, GroupName
                        $Record.User = $User
                        $Record.GroupName = $Group
                    
                        $Results += $Record

                    }
                    $Results | Export-Csv -path C:\Temp\UserGroups.csv -NoTypeInformation
                    Invoke-Item -Path C:\Temp\UserGroups.csv
                    $ErrorActionPreference = "Stop"
           
                }
                ELSE
                {
                    Write-Host "User: $User not found in AD" -ForegroundColor Red
                    sleep -seconds 3
                } 
            }
        }


    # Is user in group?
    "17" {
            import-module activedirectory
            import-module DesktopSupportFunctions
            $User = read-host -Prompt "Enter user name"
            $Group = read-host -prompt "Enter group name"

            if(Get-UserInGroup -User $User -Group $Group)
            {
                Write-Host -ForegroundColor Green "User: $User is in group: $Group"
                sleep -seconds 3
            }
            else
            {
                write-host -ForegroundColor Red "User: $User is not in group: $Group"
                sleep -seconds 3
            }

        }


    #  Copy ION Logs for User
    "18"  {
            $FindUser = read-host "Enter user ID"
            $ADUser = Get-ADUSer -LDAPFilter "(sAMAccountName=$FindUser)"
            $ErrorActionPreference= "SilentlyContinue"
            if($ADUser -ne $Null)
            {
                $TransferFolder = read-host "Enter Transfer$ folder to copy to"
                $DestinationPath="\\EURV150001\Transfer$\$TransferFolder"
                If(test-path $DestinationPath)
                {
                    if(Get-WriteAccess $DestinationPath)
                    {
                        if(Test-Path "$DestinationPath\$FindUser")
                        { 
                            # Delete previous User folder from Transfer$ if exists
                            remove-item "$DestinationPath\$FindUser" -recurse
                        }

                        # Create User folder on Transfer$ (below destination folder)
                        New-Item "$DestinationPath\$FindUser" -type directory 
 
                        $Computers =  Get-ADComputer  -Filter {(enabled -eq "true") -and (name -like "LOTD*")} | Select-Object -ExpandProperty Name
                        ForEach($Computer in $Computers)
                        {
                            #write-host $Computer
                            $User = $null
                            $User = Get-LoggedOnUser -ComputerName $Computer
                            #write-host $User
                            if($User -ne $Null)
                            {
                                if($User -eq $FindUser)
                                {
                                    write-host "$User is logged in to $Computer" -ForegroundColor Green
                                    sleep -seconds - 3

                                    $SourcePath = "\\$Computer\C$\Program Files\ION Trading\MMI\MMI_IGB_$user\LOGS\"
                                    if(test-path $SourcePath)
                                    {
                                        $LogFiles=Get-ChildItem $SourcePath -Filter *.log 
                        
                                        ForEach($LogFile in $LogFiles)
                                        {
                                            if((New-TimeSpan $LogFile.LastWriteTime).days -le 1)
                                            {
                                            $LogFile.CopyTo("$DestinationPath\$User\$LogFile", $True)
                                            }#write-host "$LogFile ...copied to $SourcePath"
                                        }#End loop through log files
                                        write-host "ION logs copied for user: $User to $DestinationPath\$User"  -ForegroundColor Green
                                        sleep -seconds 3
                                        read-host -prompt "Press Enter to continue"

                                   }
                                    else
                                    {
                                        if(test-path "\\$Computer\C$\Program Files\ION Trading\")
                                        {
                                            write-host "$SourcePath not found"
                                            sleep -Seconds 3
                                        }
                                        else
                                        {
                                            write-host "Error: ION not installed on $Computer"
                                            sleep -Seconds 3
                                        }
                                    }#End User logged into $Computer
                                    break
                                } # end User=FindUser
                            }#End if $user is null
                        }#End Foreach$Computer
                        if($User -eq $Null)
                        {
                            write-host "User: $FindUser not logged in (LOTD, LOND or CDCD)"
                            sleep -Seconds 3
                        }
                    }
                    else
                    {
                        write-host "You do not have write access to $DestinationPath"  
                        sleep -Seconds 3
                    }
                }
                else
                {
                    write host "Destination path: $DestinationPath not found"  
                    sleep -Seconds 3
                }#End DestinationPath OK
            }
            else
            {
                write-host "User: $FindUser not in AD"
                sleep -Seconds 3
            }#End ADUser Null
        }

    # Logged in User List for computers in C:\Temp\PCs.csv
    "19" {
        Import-Module activedirectory
        import-module DesktopSupportFunctions

        if (get-fileOpen C:\temp\Users.csv)
        {
            write-host "Output csv file C:\temp\Users.csv already open - close and rerun" -ForegroundColor Red
            sleep -seconds 3
        }
        Else
        {   
            if (test-path -Path "c:\temp\PCs.csv") 
            {
                $ComputerList=get-content c:\temp\PCs.csv           
                $OutputList= @()

                Write-host "Please wait while csv file is created..." -ForegroundColor Green

                foreach ($Computer in $ComputerList)
                { 
                    write-host $Computer
        
                    $OutputRecord = "" | Select Computername, Username, Description

                    $OutputRecord.ComputerName = $Computer

                    Try
                    {
                        # Get Computer object from AD
                        $ADComputer = Get-ADComputer $Computer -Properties Description
                        $OutputRecord.Description = $ADComputer.description

                        if (Test-Connection -computername $Computer -count 1 -quiet)  
                        {
                        # If PC is online - check username
                            $username = $null
                            $Processes = Get-WmiObject -class win32_process -computer $Computer -Filter "Name = 'explorer.exe'"
                            #Go through collection of processes
                            ForEach ($Process in $Processes) 
                            {
                              
                                $Username = ($Process.GetOwner()).User
                                if($Username -ne $null)
                                {
                                    break
                                }
                            }

                            If ($UserName -ne $Null)
                            {
                            # if User found - output
                                $OutputRecord.Username=$Username
                            }
                            Else
                            {
                            # If no user found - 
                                $OutputRecord.Username="Nobody logged in"
                            }
                        }
                        Else 
                        {
                        # If PC is not online
                            $OutputRecord.Username="Offline"
                        } # end Test Connection
                    } #End Try
                    Catch
                    {
                    # IF Computer not in AD
                        $OutputRecord.Description = "$Computer Not in AD"
                        $OutputRecord.Username = $Null
                    } #End Catch


                    # Add record to OutputList
                    $OutputList += $OutputRecord
                } # End For each

                $OutputList | SORT Computername | Export-Csv -Path "C:\temp\Users.csv" -NoTypeInformation 
                Invoke-Item "C:\temp\Users.csv"
            } 
            else
            {
                write-host "C:\Temp\PCs.csv not found - please create file for input" -ForegroundColor Red
                sleep -seconds 3
            } # end test path c:\temp\pcs.csv
        } # end if file in use
     }




        "20" {
                $hostname = Read-Host -Prompt "Enter hostname"
                            ping $hostname
                }
       

        "30" {
               Write-Host                "EU Support Contacts" -ForegroundColor Green
               Write-Host "================================================="
               Write-Host "Antwerp = Vincent Huybrechts & Peggy Autreve Van"
               Write-Host "Frankfurt = Kai Liu"
               Write-Host "Paris = Herve Petit"
               Write-Host "Istanbul = Emre Icdemir"
               Write-Host "Mardrid = Javier Florez & Mari Paz Llop"
               Write-Host "Warsaw = Robert Wotjtasiak"
               Write-Host "Mailan = Fabio Poidomani"            
               Sleep -seconds 10
               }

    "99" {# Force Reboot 
               $Hostname = Read-Host "Enter Hostname"
                        Restart-Computer -ComputerName $Hostname -Force
                        Write-Host "$hostname has been rebooted" -ForegroundColor Green
                        Sleep -Seconds 2
                
                        
         } 

        "Q" {Write-Host "Goodbye" -ForegroundColor Green
                Return
                }

                    Default {Write-Warning "Invalid Choice. Try again."
                    sleep -seconds 2
                    }

         } #switch
         } While ($True)