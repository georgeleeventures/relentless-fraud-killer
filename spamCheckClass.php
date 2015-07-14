<?php
/*
# File:    spamCheckClass.php
# Author:  George Lee
# Date:    Upload 7/14/2015 (but created more than 1 yr ago)
# E-mail:  george@georgel.ee
# Web: georgel.ee
# © Copyright 2015 George Lee / georgel.ee. All Rights Reserved.
# Description:
# This class helps check for user spam activity across several DNS blacklist
# providers such as sorbs, spamhaus, and others. This class uses built in 
# functions and reverse dns lookup to determine the possibility of spam behavior of a user.
# Great for vetting users on any platform.
# To use: embed class in your app and call spamCheck class and blacklistCheck() to perform lookup.
*/

class spamCheck {

	
	# dnsbllookup() gets the $payload IP address to check DNSBL. Use below function for validation.
	# Input:  $payload, the ip address.
	# Output: boolean, true if listed, false if not listed
	public function dnsbllookup($payload)
	{
		$dnsbl_lookup = array(
		"dnsbl-1.uceprotect.net",
		"dnsbl-2.uceprotect.net",
		"dnsbl-3.uceprotect.net",
		"dnsbl.dronebl.org",
		"dnsbl.sorbs.net",
		"pbl.spamhaus.org",
		"dnsbl.tornevall.org",
		"zen.spamhaus.org"); 
		// Add your preferred list of DNSBL's above (but please take note of added latency)
		if($payload)
		{
			$listed = '';
			$reverse_ip = implode(".",array_reverse(explode(".",$payload)));
			foreach($dnsbl_lookup as $host)
			{
				if(checkdnsrr($reverse_ip.".".$host.".","A"))
				{
					$listed.= $reverse_ip.'.'.$host.' <span style="color:red">Listed</span><br>';
				}
			}
		}
		// Choice of boolean (but you can always choose to see the listed addresses.
		if($listed)
		{
			return true;
			// Uncomment next 2 lines below to see the DNS blacklists that were listed.
			//echo 'The IP is listed on one or more DNS blacklists: <br>';
			//echo $listed;
		}
		else
		{
			// No A record was found - IP is clean.
			return false;
		}
	}
	
	# blacklistCheck() gets the $payload IP address to send to dnsbllookup function
	# and puts through validation.
	# Input:  $payload, the ip address.
	# Output: boolean, or invalid IP address message.
	public function blacklistCheck($payload)
	{
		if(filter_var($payload,FILTER_VALIDATE_IP))
		{
			return $this->dnsbllookup($payload);
		}
		else
		{
			return "Invalid IP address.";
		}
	}

}
?>