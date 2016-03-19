######ignore invalid SSL Certs##########
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

######setup details, access related.
$auth = "username=api_access&passhash=1669687025"
$PRTGHost = "192.168.0.89"



##############################################
############Get-prtgSensorInGroup#############
##############################################
# will return ALL sensors listed in PRTG, for a given Group (via its ID) (limited to 2500)
#default is the root (ID=0)
#its important to remember that a "Group" is also a device, and probe etc.
#eg
#Get-prtgSensorInGroup 8011

function Get-prtgSensorInGroup([string]$StartingID=0)
{
    $url = "http://$PRTGHost/api/table.xml?content=sensors&output=csvtable&columns=objid,probe,group,device,sensor,status,message,lastvalue,priority,favorite,tags&id=$StartingID&count=2500&$auth"
    $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore

    convertFrom-csv $request -WarningAction SilentlyContinue
} # end function




##############################################
############Get-prtgDevicesInGroup####################
##############################################
# will return ALL Devices listed in PRTG, for a given Group (via its ID) (limited to 2500)
#default is the root (ID=0)
#if you want to find 1 device(ID=8011), then use: Get-prtgDevicesInGroup | where {$_.ID -eq 8011}
#anther example, seaching for an IP
#Get-prtgDevicesInGroup | where {$_.host -eq "10.81.8.36"}

#you may also want to return many devices, eg
#Get-prtgDevicesInGroup | where {$_.host -like "10.81.8.*"}

function Get-prtgDevicesInGroup ([string]$StartingID=0)
{
    #if ($script:devicesCached -eq $false){
        $url = "http://$PRTGHost/api/table.xml?content=devices&output=csvtable&columns=objid,probe,groupid,device,host,downsens,partialdownsens,downacksens,upsens,warnsens,pausedsens,unusualsens,undefinedsens,comments&id=$StartingID&count=2500&$auth"
        $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
        $getprtgDeviceRet = convertFrom-csv ($request.content) -WarningAction SilentlyContinue
        $getprtgDeviceRet 
    #    write-host "got devices from website..."
    #    $script:devicesCached = $true
    #}else{
    #    write-host "got groups from cache..."
    #    $getprtgDeviceRet 
    #}
} # end function


##############################################
############Get-prtgGroupsInGroup####################
##############################################
# will return ALL Groups listed in PRTG, for a given Group (via its ID) (limited to 2500)
#default is the root (ID=0)

#will will list all the group recurively under the listed group (ie, not JUST the children)

#eg, return al lthe groups in the local probe
# get-prtgGroupsInGroup 1

function get-prtgGroupsInGroup ([string]$StartingID=0)
{
   
    $url = "http://$PRTGHost/api/table.xml?content=groups&output=csvtable&columns=objid,probe,group,name,downsens,partialdownsens,downacksens,upsens,warnsens,pausedsens,unusualsens,undefinedsens&count=2500&id=$StartingID&$auth"
    $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
    $getprtgGroupret = convertFrom-csv ($request) -WarningAction SilentlyContinue
    #write-host "got groups from website..."
    $getprtgGroupret
   
} # end function



##############################################
############Set-prtgDeviceProperty############
##############################################
# Sets a property of a device

function Set-prtgDeviceProperty ([string]$DeviceID,[string]$PropertyName,[string]$Value)
{
    $url = "http://$PRTGHost/api/setobjectproperty.htm?id=$DeviceID&name=$PropertyName&value=$Value&$auth"
    $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore


} # end function



##############################################
############Get-prtgSensorChannels############
##############################################

function Get-prtgSensorChannels ([string]$SensorID)
{
    #this does not retuen the channelID - rather important for somethings.
    $url = "http://$PRTGHost/api/table.xml?content=channels&output=csvtable&columns=name,lastvalue_&id=$SensorID&$auth"
    $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
    convertFrom-csv ($request) -WarningAction SilentlyContinue

    
} # end function

function Get-prtgSensorChannelIDs ([string]$SensorID)
{
    #this does retuen the channelID - but not the last value
    $url = "http://$PRTGHost/controls/channeledit.htm?_hjax=true&id=$SensorID&$auth"
    
    $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
    $ret = $request.AllElements.FindByName("channel") | select -ExpandProperty outerText
    $temp = ""|select ChannelID,ChannelName,LastValue
    $rets = $ret -split "\)"
    foreach ($ret3 in $rets)
    {
        $temp.ChannelName = $ret3 -split "ID"[0]
        $temp.ChannelID = $ret3 -split "ID"[1]
        $temp
    }
    
    

    
} # end function



##############################################
##############Get-prtgSensorData##############
##############################################

function Get-prtgSensorData ([string]$SensorID,[datetime]$StartDate,[datetime]$EndDate)
{
    $StartDate2 = get-date $StartDate -format "yyyy-MM-dd-hh-mm-ss"
    $EndDate2 = get-date $EndDate -format "yyyy-MM-dd-hh-mm-ss"
    #/api/historicdata.csv?id=objectid&avg=0&sdate=2016-01-20-00-00-00&edate=2016-01-21-00-00-00
    $url = "http://$PRTGHost/api/historicdata.csv?id=$SensorID&avg=3600&sdate=$StartDate2&edate=$EndDate2&$auth"
    #$url
    $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
    convertFrom-csv ($request) -WarningAction SilentlyContinue

} # end function


##############################################
#######Get-prtgSensorChannelPrediction########
##############################################

function Get-prtgSensorChannelPrediction ($SensorID,$ChannelName,$AgeOfFirstSampleInDays,$Limit,[bool]$Debug)
{
    $NewDate = [DateTime]::Now.Subtract([TimeSpan]::FromDays($AgeOfFirstSampleInDays)) 
    $NewDate = get-date $NewDate -format "yyyy-MM-dd hh:mm:ss"
    if($debug){"Checking Historical Data from $NewDate"}

    $ChannelNameRaw = $ChannelName + "(RAW)"
    $OldData = [long](Get-prtgSensorData -SensorID $SensorID -StartDate $NewDate -EndDate $NewDate | where {$_.$ChannelNameRaw -like "*.*" } | select $ChannelNameRaw -first 1)."$ChannelNameRaw" 
    if($debug){"Historical Data equals $OldData"}
    $CurrentDate = get-date -format "yyyy-MM-dd hh:mm:ss"
    if($debug){"Current Date equals $CurrentDate"}
    
#I really have to change the line below to to use /10 but rather replace "0.","." - then test.
    $NewData = [long](Get-prtgSensorChannels -SensorID $SensorID | where {$_.channel -eq "$ChannelName"} | select "Last Value(RAW)")."last value(RAW)" /10
    if($debug){"Current Data equals $NewData"}
    if($debug){"Limit equals equals $Limit"}

    
    $r = 1
    if($Limit -gt $NewData)
    { #eg, 100 percent
        if($NewData -gt $OldData)
        {   # its raising, eg disk space use is growing
            #=(limit-newdata)/((newdata-olddata)/timeunits)
            $ret = ($Limit-$NewData)/(($NewData-$OldData)/$AgeOfFirstSampleInDays)
        }
        else
        {# eg, we are freeing space up! this is good
            if($debug){"We will not hit the limit"}
            $ret = 999
        }
    }
    else
    { # its small, like zero
        if($NewData -gt $OldData)
        { # eg, we are freeing space up! this is good
            if($debug){"We will not hit the limit"}
            $ret = 999
        }
        else
        {# its falling, eg free disk space is gown down
            #=new/((old-new)/timeunits)
            $ret = $NewData / (($OldData-$NewData)/$AgeOfFirstSampleInDays)
        }
    }

    if($debug){"Days Till Limit is reached equals $ret"}
    [int]$ret = $ret
    "" + $ret + ":OK"
} # end function




##############################################
############Get-prtgDeviceProperty############
##############################################
# Gets a property of a device

function Get-prtgDeviceProperty ([string]$DeviceID,[string]$PropertyName)
{
    $url = "http://$PRTGHost/api/getobjectproperty.htm?id=$DeviceID&name=$PropertyName&$auth"
    [xml]$request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
    $request.ChildNodes.result

} # end function


##############################################
############Add-prtgSensorToDevice############
##############################################
# add's a sensor to a device (good for updating templates- adding a new sensor to 100's of devices)



#eg add one sensor to a group of devices
#add-prtgSensorToDevice -SensorScriptBlock {Get-prtgSensorInGroup | where {$_.id -eq 8328}} -DevicesScriptBlock {Get-prtgDevicesInGroup 7633}

#eg, add sensor 5520 to device 6409
#add-prtgSensorToDevice -SensorScriptBlock {Get-prtgSensorInGroup | where {$_.id -eq 5520}} -DevicesScriptBlock {Get-prtgDevicesInGroup | where {$_.id -eq 6409}}

#eg add a pages_left sensor to all devices with a tag of "printer"
#TODO

function Add-prtgSensorToDevice
{
    [CmdletBinding()]
    
    param(
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$false)]
            [scriptblock]$DevicesScriptBlock,

            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$false)]
            [scriptblock]$SensorScriptBlock
          )

    process
    {
        
        if ($SensorScriptBlock -ne $null -and $DevicesScriptBlock -ne $null)
        {
            ##loop thru all the devices.
            $Devices = &([scriptblock]::Create($DevicesScriptBlock))
    
            foreach($Device in  $Devices)
            {
                $DeviceID = $device.id
                "DeviceID=$DeviceID"

                ##Loop thru all the sensors.
                $Sensors = &([scriptblock]::Create($SensorScriptBlock))
    
                foreach($Sensor in  $Sensors)
                {
                    $SensorID = $Sensor.id
                    "SensorID=$SensorID"
                    $NewName=$Sensor.Sensor
                    $url = "http://$PRTGHost/api/duplicateobject.htm?id=$SensorID&Targetid=$DeviceID&name=$NewName&$auth"
                    $url
                    $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
                } # end foreach -  Sensor
            } # end foreach - Device

        } # end if

    } # end process

} # end function



##############################################
############Add-prtgDevice############
##############################################
# adds a new device in PRTG

#example
#Add-prtgDevice -NewIP "5.5.5.5" -TemplateID 5682 -DestGroupID 6408 -NewDeviceName "Hi_I_Am_New"

#example, import from CSV. where the fields are newip, TemplateID, DestGroupID, NewDeviceName
#Import-Csv -Delimiter "`t" -path c:\prtgimport.csv | Add-prtgDevice

function Add-prtgDevice 
{
 
    [CmdletBinding()]
    
    param(
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]
            [string]$NewIP,

            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]
            [string]$TemplateID,

            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]
            [string]$DestGroupID,

            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]
            [string]$NewDeviceName
    
    
    )

    Process 
    {
        #$NeWIP = "2.2.2.2"
        #$TemplateID = "5539"
        #$DestGroupID = "5538"
        #$NewDeviceName = "Server1"

        "" + "adding sensor$NewIP"
        #Duplicate the sensor (Server replies with a redirect to new objects webpage, e.g. /sensor.htm?id=10214, parse id 10214 from the URL):
        $url = "http://$PRTGHost/api/duplicateobject.htm?id=$TemplateID&name=$NewDeviceName&targetid=$DestGroupID&$auth"
    
        $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
        $newID = $request.Headers.Location.Split("=")[1]

        #add in the correct IP (host) the new sensor:
        $url = "http://$PRTGHost/api/setobjectproperty.htm?id=$newID&name=host&value=$newIP&$auth" 
        $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore

        #Resume monitoring for the new sensor:
        $url = "http://$PRTGHost/api/pause.htm?id=$newID&action=1&$auth"
        $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
    } #end process
} # end function


##############################################
#######Get-PRTGActiveAdvancedSchedule#########
##############################################
#looks in the comments for a given sensor, and grabs what is between the "{AdvancedSchedule}" and "{/AdvancedSchedule}" tags.
# eg:
#{AdvancedSchedule}
#Channel,Start,Stop,UpperWarn,UpperError,LowerWarn,LowerError
#0,07:00,12:30,1,2,3,4
#0,12:31,6:59,5,6,7,8
#{/AdvancedSchedule}
#

Function Get-PRTGActiveAdvancedSchedule{
    param
    (
        $DeviceID
    )

    ##get the comments
    [string]$ret = Get-prtgDeviceProperty -DeviceID $DeviceID -PropertyName comments

    #strip the headers
    $q1 = $ret.IndexOf("{AdvancedSchedule}")
    $q2 = $ret.IndexOf("{/AdvancedSchedule}")
    $ret = $ret.Substring($q1+18,($q2-$q1)-18)
    
    #$ret = $ret.Replace("{AdvancedSchedule}","")
    #$ret = $ret.Replace("{/AdvancedSchedule}","")

    #get rid of the blank lines
    $ret2 = $ret -creplace '(?m)^\s*\r?\n',''
    
    $ret3 = convertFrom-csv ($ret2)

    #return just the active entries
    $ret3 | where {$_.start -lt (get-date).TimeOfDay -and $_.stop -gt (get-date).TimeOfDay}
    

}


##############################################
###########Set-PRTGChannelSettings############
##############################################

#warning: this is not part of the standard API - and might be removed at any time.
#warning: this is really useful!
#this lets you update channel properties. To get a list of properties you can change you will
# need to examine the post data (using browser tools) when making changes to a channel via the PRTG web interface.

function Set-PRTGChannelSettings{
    param(
    $DeviceID, 
    $ChannelID,
    $Property,
    $Value
    )

    $url = "http://$PRTGHost/editsettings?$Property" + "_" + $ChannelID + "=" + "$value&id=$DeviceID&$auth"
    #$url
    $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
}

##############################################
###########Get-PRTGChannelSettings############
##############################################

#warning: this is not part of the standard API - and might be removed at any time.
#warning: this is really useful!
#this lets you update channel properties. To get a list of properties you can change you will
# need to examine the post data (using browser tools) when making changes to a channel via the PRTG web interface.

function Get-PRTGChannelSettings{
    param(
    $DeviceID, 
    $ChannelID
    )

    $url = "http://$PRTGHost/controls/channeledit.htm?_hjax=true&id=$DeviceID&channel=$ChannelID&$auth"
    
    $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
    $ret = $request.AllElements | select name,value | where {$_.name -like "*_*"}
    foreach ($line in $ret)
    {
        $line.name = $line.name -replace "_$ChannelID",""
    }
    $ret
}



function Set-PRTGAdvancedSchedules{
    $DeviceswithAdvancedSchedules = Get-prtgSensorInGroup | where {$_.Tags -like "*AdvancedSchedule*"}
    Foreach ($Device in $DeviceswithAdvancedSchedules){
	    $Schedules = Get-PRTGActiveAdvancedSchedule -DeviceID $Device.ID
	    Foreach ($Schedule in $Schedules){
		    If ($Schedule.UpperError -ne ""){
			    Set-PRTGChannelSettings -DeviceID $Device.ID -ChannelID $Schedule.channel -Property limitmaxerror -Value $Schedule.UpperError
		    }
            If ($Schedule.LowerError -ne ""){
			    Set-PRTGChannelSettings -DeviceID $Device.ID -ChannelID $Schedule.channel -Property limitminerror -Value $Schedule.LowerError
		    }
            If ($Schedule.UpperWarn -ne ""){
			    Set-PRTGChannelSettings -DeviceID $Device.ID -ChannelID $Schedule.channel -Property limitmaxwarning -Value $Schedule.UpperWarn
		    }
            If ($Schedule.LowerWarn -ne ""){
			    Set-PRTGChannelSettings -DeviceID $Device.ID -ChannelID $Schedule.channel -Property limitminwarning -Value $Schedule.LowerWarn
		    }
	    }
    }

}


#example:
#Set-PRTGObjectPause -ObjectID 2003 -Minutes 5 -Message "Please Wait - Server Rebooting"
function Set-PRTGObjectPause{
    param
    (
    $ObjectID,
    $Message,
    $Minutes
    )
    ##ObjectID can be a sensor, device or Group
    $url = "http://$PRTGHost/api/pauseobjectfor.htm?id=$ObjectID&duration=$minutes&pausemsg=$Message&$auth"
    $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore

}

function Set-PRTGPauseThisServer{
    param
    (
    $Message,
    $Minutes
    )
    $myIPs = Get-NetIPAddress -AddressFamily IPv4 | where { $_.InterfaceAlias -notmatch 'Loopback'} |Select IPAddress
    
    $t = "" | select ipaddress 
    $t.ipaddress = hostname
    $myips += $t

    $t = "" | select ipaddress 
    $t.ipaddress = "$env:computername.$env:userdnsdomain"
    $myips += $t


    #$myips
    foreach ($ip in $MYIPs){
        $q = Get-prtgDevicesInGroup | where {$_.host -eq $IP.ipaddress} 

        foreach ($x in $q){
            Set-PRTGObjectPause -ObjectID $x.ID -Minutes $Minutes -Message "$Message"
        }
    }
}


function Set-PRTGResumeThisServer{
    $myIPs = Get-NetIPAddress -AddressFamily IPv4 | where { $_.InterfaceAlias -notmatch 'Loopback'} |Select IPAddress
    
    $t = "" | select ipaddress 
    $t.ipaddress = hostname
    $myips += $t

    $t = "" | select ipaddress 
    $t.ipaddress = "$env:computername.$env:userdnsdomain"
    $myips += $t


    #$myips
    foreach ($ip in $MYIPs){
        $q = Get-prtgDevicesInGroup | where {$_.host -eq $IP.ipaddress} 

        foreach ($x in $q){
            $url = "http://$PRTGHost/api/pause.htm?id=" + $x.ID + "&action=1&$auth"
            $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore
        }
    }
}

function Get-PRTGChannelDetailExportForDevices
{
    param
    (
    $ObjectID
    )

    $Devices = Get-prtgDevicesInGroup -StartingID $ObjectID
        foreach ($Device in $Devices)
        {
            $Sensors = Get-prtgSensorInGroup -StartingID $Devices.id
            Foreach ($Sensor in $Sensors)
            {
                $Channels = Get-prtgSensorChannels -SensorID $Sensor.id
                Foreach ($Channel in $Channels)
                {
                    $ret = Get-PRTGChannelSettings -DeviceID $Device.id -ChannelID $Channel.id
                    $ret
                }                
            }
        }
        


}