/*
	Yara Rule Set
	Author: Lewis McKee
	Date: 2018-10-05
	Identifier: APT28
*/

/* Rule Set ----------------------------------------------------------------- */
rule APT28_X-Agent {
	meta:
        description = "X-AGENT (Also known as CHOPSTICK) is a second-stage modular remote access trojan (RAT)."
        Author= "APT28"
        reference = "https://www.ncsc.gov.uk/alerts/indicators-compromise-malware-used-apt28"
        super_rule =1
        hash0 = "46e2957e699fae6de1a212dd98ba4e2bb969497d"
        hash1 = "c53930772beb2779d932655d6c3de5548810af3d"
        hash2 = "fa695e88c87843ca0ba9fc04b176899ff90e9ac5"
        hash3 = "046a8adc2ef0f68107e96babc59f41b6f0a57803"
        score = 60
    strings:
		$s0 = "chost.exe" fullword ascii
		$s1 = "msoutlook.dll" fullword ascii
        $s2 = "Samp_(16).file" fullword ascii
        $s3 = "outlook.dll" fullword ascii
        $s4 = "139.5.177.205" fullword ascii
        $s5 = "80.255.6.15" fullword ascii
        $s6 = "89.34.111.107" fullword ascii
        $s7 = "86.106.131.229" fullword ascii 
        $s8 = "139.5.177.206" fullword ascii
        $s9 = "185.181.102.203" fullword ascii
        $s10 = "185.181.102.204" fullword ascii
        $s11 = "169.239.129.31" fullword ascii
        $s12 = "213.252.247.112" fullword ascii 
        $s13 = "185.86.148.15" fullword ascii
        $s14 = "89.45.67.110" fullword ascii
        $s15 = "185.86.150.205" fullword ascii
        $s16 = "193.37.255.10" fullword ascii
        $s17 = "195.12.50.171" fullword ascii
        $s18 = "51.38.128.110" fullword ascii
        $s19 = "185.144.83.124" fullword ascii
        $s20 = "185.216.35.10" fullword ascii
        $s21 = "185.94.192.122" fullword ascii
        $s22 = "185.216.35.7" fullword ascii
        $s23 = "103.253.41.124" fullword ascii
        $s24 = "185.189.112.195" fullword ascii
        $s25 = "185.230.124.246" fullword ascii
        $s26 = "87.120.254.106" fullword ascii
        $s27 = "77.81.98.122" fullword ascii
        $s28 = "89.34.111.132" fullword ascii
        $s29 = "46.21.147.55" fullword ascii
        $s30 = "103.208.86.57" fullword ascii
        $s31 = "185.128.24.104" fullword ascii
        $s32 = "145.239.67.8" fullword ascii
        $s33 = "185.210.219.250" fullword ascii
        $s34 = "86.105.9.174" fullword ascii
        $s35 = "89.34.111.107" fullword ascii
        $s36 = "malaytravelgroup.com" fullword ascii
        $s37 = "worldimagebucket.com" fullword ascii
        $s38 = "fundseats.com" fullword ascii
        $s39 = "globaltechengineers.org" fullword ascii
        $s40 = "beststreammusic.com" fullword ascii
        $s41 = "thepiratecinemaclub.org" fullword ascii
        $s42 = "coindmarket.com" fullword ascii
        $s43 = "creekcounty.net" fullword ascii
        $s44 = "virtsvc.com" fullword ascii
        $s45 = "moderntips.org" fullword ascii
        $s46 = "daysheduler.org" fullword ascii
        $s47 = "escochart.com" fullword ascii
        $s48 = "loungecinemaclub.com" fullword ascii
        $s49 = "genericnetworkaddress.com" fullword ascii
        $s50 = "bulgariatripholidays.com" fullword ascii
        $s51 = "georgia-travel.org" fullword ascii
        $s52 = "bbcweather.org" fullword ascii
        $s53 = "politicweekend.com" fullword ascii
        $s54 = "truefashionnews.com" fullword ascii
        $s55 = "protonhardstorage.com" fullword ascii
        $s56 = "moldtravelgroup.com" fullword ascii
        $s57 = "iboxmit.com" fullword ascii
        $s58 = "brownvelocity.org" fullword ascii
        $s59 = "pointtk.com" fullword ascii
        $s60 = "narrowpass.net" fullword ascii
        $s61 = "powernoderesources.com" fullword ascii
        $s62 = "topcinemaclub.com" fullword ascii
        $s63 = "fundseats.com" fullword ascii

	condition:
		uint16(0) == 0x5a4d and 1 of them 

}



/* Compu-trace
*/
rule APT28_Compu-trace {
	meta:
        description = "exploitation of this software enables persistence on the victim's operating system, as well as the ability to modify the system memory and retrieve additional modules through the installed modified CompuTrace/Lojack agent."
        Author= "APT28"
        reference = "https://www.ncsc.gov.uk/alerts/indicators-compromise-malware-used-apt28"
        super_rule =1
        hash0 = "d70db6a6d660aae58ccfc688a2890391fd873bfb"
        score = 60
    strings:
        $s0 = "dcbfd12321fa7c4fa9a72486ced578fdc00dcee79e6d95aa481791f044a55dll" fullword ascii
        $s1 = "185.86.151.2" fullword ascii
        $s2 = "46.21.147.76" fullword ascii
        $s3 = "46.21.147.71" fullword ascii
        $s4 = "162.208.10.66" fullword ascii
        $s5 = "185.86.151.104" fullword ascii
        $s6 = "185.86.149.116" fullword ascii
        $s7 = "86.106.131.54" fullword ascii
        $s8 = "185.181.102.201" fullword ascii
        $s9 = "179.43.158.20" fullword ascii
        $s10 = "85.204.124.77" fullword ascii
        $s11 = "185.86.148.184" fullword ascii
        $s12 = "185.183.107.40" fullword ascii
        $s13 = "185.94.191.65" fullword ascii
        $s14 = "94.177.12.150" fullword ascii
        $s15 = "54.37.104.106" fullword ascii
        $s16 = "93.113.131.103" fullword ascii
        $s17 = "169.239.129.121" fullword ascii
        $s18 = "169.239.128.133" fullword ascii
	condition:
		uint16(0) == 0x5a4d and 1 of them 

}



/* X-Tunnel
*/
rule APT28_X-Tunnel {
	meta:
        description = "X-TUNNEL (XTUNNEL) is a network tunnelling tool that is used for network traversal and pivoting. It provides a secure tunnel to an external command and control server,through which the actors can operate using a variety of standard networking tools and protocols to connect to internal services."
        Author= ""
        reference = "https://www.ncsc.gov.uk/alerts/indicators-compromise-malware-used-apt28"
        super_rule =1
        hash0 = "8dbe37dfb0d498f96fb7f1e09e9e5c8f"
        hash1 = "5086989639aed17227b8d6b041ef3163"
        score = 60
    strings:
        $s0 = "gpu.dll" fullword ascii
        $s1 = "23.163.0.59" fullword ascii
        $s2 = "picturecrawling.com" fullword ascii
        $s3 = "86.105.1.123" fullword ascii
        $s4 = "185.86.149.218" fullword ascii
        $s5 = "185.145.128.80" fullword ascii
        $s6 = "89.37.226.106" fullword ascii
        $s7 = "94.177.12.238" fullword ascii
        $s0 = "lncstnt.exe" fullword ascii
    condition:
		uint16(0) == 0x5a4d and 1 of them 
}

/* Zebrocy
*/
rule APT28_Zebrocy {
	meta:
        description = "ZEBROCY is a tool used by APT28, which has been observed since late 2015. The communications module used by ZEBROCY transmits using HTTP. The implant has key logging and file exfiltration functionality and utilises a file collection capability that identifies files with particular extensions."
        Author= ""
        reference = "https://www.ncsc.gov.uk/alerts/indicators-compromise-malware-used-apt28"
        super_rule =1
        hash0 = "913ac13ff245baeff843a99dc2cbc1ff5f8c025c"
        hash1 = "b758c7775d9bcdc0473fc2e738b32f05b464b175"
        hash2 = "3e7dfe9a8d5955a825cb51cb6eec0cd07c569b41"
        score = 60

    strings:
        $s1 = "176.223.111.243" fullword ascii
        $s2 = "188.241.68.118" fullword ascii
        $s3 = "89.45.67.153" fullword ascii
        $s4 = "185.25.50.93" fullword ascii
        $s5 = "45.124.132.127" fullword ascii
        $s6 = "codexgigas_913ac13ff245baeff843a99dc2cbc1ff5f8c025c" fullword ascii
        $s7 = "codexgigas_b758c7775d9bcdc0473fc2e738b32f05b464b175" fullword ascii
        $s8 = "UpnP Error Handler" fullword ascii
    condition:
		uint16(0) == 0x5a4d and 1 of them 
}