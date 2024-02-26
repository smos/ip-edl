<?php

// print_r($_SERVER);
// Exit when not on shell
if(isset($_SERVER['REMOTE_ADDR'])) {
	echo "This should be run from the CLI\n";
	exit(0);
}
$regs = array("ripencc", "apnic", "arin", "afrinic", "lacnic");
$indir = "in";
$outdir = "out";

echo "Time: ". date("Y-m-d H:i:s") ."\n";

$dbs = array();
$dbs['ripe']['serial'] = "https://ftp.ripe.net/ripe/dbase/RIPE.CURRENTSERIAL";
$dbs['ripe']['db'] = "https://ftp.ripe.net/ripe/dbase/ripe.db.gz";
$dbs['apnic']['serial'] = "https://ftp.apnic.net/apnic/whois/APNIC.CURRENTSERIAL";
$dbs['apnic']['db'] = "https://ftp.apnic.net/apnic/whois/apnic.db.route.gz";
$dbs['apnic6']['serial'] = "https://ftp.apnic.net/apnic/whois/APNIC.CURRENTSERIAL";
$dbs['apnic6']['db'] = "https://ftp.apnic.net/apnic/whois/apnic.db.route6.gz";
$dbs['lacnic']['serial'] = "https://ftp.lacnic.net/lacnic/irr/LACNIC.CURRENTSERIAL";
$dbs['lacnic']['db'] = "https://ftp.lacnic.net/lacnic/irr/lacnic.db.gz";
$dbs['arin']['serial'] = "https://ftp.arin.net/pub/rr/ARIN.CURRENTSERIAL";
$dbs['arin']['db'] = "https://ftp.arin.net/pub/rr/arin.db.gz";
$dbs['afrinic']['serial'] = "https://ftp.afrinic.net/dbase/AFRINIC.CURRENTSERIAL";
$dbs['afrinic']['db'] = "https://ftp.afrinic.net/dbase/afrinic.db.gz";

$cdbs['ripe']['hash'] = "https://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest.md5";
$cdbs['ripe']['db'] = "https://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest";
$cdbs['apnic']['hash'] = "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest.md5";
$cdbs['apnic']['db'] = "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest";
$cdbs['lacnic']['hash'] = "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest.md5";
$cdbs['lacnic']['db'] = "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest";
$cdbs['arin']['hash'] = "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest.md5";
$cdbs['arin']['db'] = "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest";
$cdbs['afrinic']['hash'] = "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest.md5";
$cdbs['afrinic']['db'] = "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest";

// Download current DB
foreach($dbs as $rir => $db) {
	echo "Check serial for RIR {$rir}\n";
	$onlineserial = "";
	$localserial = "";

	$onlineserial  = file_get_contents($db['serial']);
	$dbfile = basename($db['db']);
	if(is_readable("{$indir}/{$dbfile}.serial"))
		$localserial  = file_get_contents("{$indir}/{$dbfile}.serial");

	if((floatval($onlineserial) > floatval($localserial)) || (empty($localserial))) {
		echo "Download file {$db['db']}\n";
		if (file_put_contents("{$indir}/{$dbfile}", file_get_contents($db['db']))) {
			echo "File {$dbfile} downloaded successfully\n";
			file_put_contents("{$indir}/{$dbfile}.serial", $onlineserial);
		} else {
			echo "Failed to download {$dbfile}\n";
		}
	}
}

// Download current DB
foreach($cdbs as $rir => $db) {
	echo "Check hash for RIR {$rir}\n";
	$onlineserial = "";
	$localserial = "";

	$onlineserial  = file_get_contents($db['hash']);
	$dbfile = basename($db['db']);
	if(is_readable("{$indir}/{$dbfile}.hash"))
		$localserial  = file_get_contents("{$indir}/{$dbfile}.hash");

	if((floatval($onlineserial) != floatval($localserial)) || (empty($localserial))) {
		echo "Download file {$db['db']}\n";
		if (file_put_contents("{$indir}/{$dbfile}", file_get_contents($db['db']))) {
			echo "File {$dbfile} downloaded successfully\n";
			file_put_contents("{$indir}/{$dbfile}.hash", $onlineserial);
		} else {
			echo "Failed to download {$dbfile}\n";
		}
	}
}

$rirs = array();
foreach($regs as $reg){
	if(is_readable("{$indir}/delegated-{$reg}-extended-latest"))
		$rirs[$reg]['file'] = "{$indir}/delegated-{$reg}-extended-latest";
}

$iso3166 = file("all.csv");
array_shift($iso3166);

// keep dividing number of hosts by until we have 1
function calc_snbits($nr) {
	$sn = 0;
	while($nr > 1) {
		$nr = $nr /2;
		$sn++;
	}
	return $sn;
}


/**
 * Validates the format of a CIDR notation string
 *
 * @param string $cidr
 * @return bool
 */
function validateCidr($cidr)
{
    $parts = explode('/', $cidr);
    if(count($parts) != 2) {
        return false;
    }

    $ip = $parts[0];
    $netmask = $parts[1];

    if (!preg_match("/^\d+$/", $netmask)){
        return false;
    }

    $netmask = intval($parts[1]);

    if($netmask < 0) {
        return false;
    }

    if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return $netmask <= 32;
    }

    if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return $netmask <= 128;
    }

    return false;
}


$cip = array();
$guid = array();
$asn = array();
$asroutes = array();

echo "Parse RIR allocations\n";
foreach($rirs as $rir => $info) {
	if (is_readable($info['file'])) {
		echo "Parsing file {$info['file']}\n";
		$arr = array();
		$arr = file($info['file']);
		foreach($arr as $entry) {
			$el = preg_split("/\|/", $entry);
			if(!isset($el[2]))
				continue;
			if(!isset($el[7]))
				continue;

			$el[3] = trim($el[3]);
			$el[7] = trim($el[7]);
			switch($el[2]) {
				case "asn":
					// 7 is guid
					// 3 is asn
					// 2 is country
					$asn[$el[3]] = $el[7];
					$asguid[$el[7]] = $el[3];
					// echo "Found AS {$el[3]} RIR {$rir} guid {$el[7]}\n";
					// print_r($el);
					break;
				case "ipv6":
				case "ipv4":
					// Only output the useful info
					if(preg_match("/(assigned|allocated)/", $el[6])) {
						// calculate subnet mask
						$bits = 32 - calc_snbits($el[4]);
						if($el[2] == "ipv6")
							$bits = $el[4];


						$cidr = "{$el[3]}/{$bits}";
						if(!validateCidr($cidr)) {
							echo "Address '{$el[3]}/{$bits}' is not valid in {$info['file']}, skipping\n";
							continue;
						} else {
							$cip[$el[1]][] = $cidr;
							// echo "{$el[3]}/{$bits} \n";
							// also save by guid for ASN lookup
							$guid[$el[7]][] = $cidr;
						}

					}
					// print_r($asn);
					// print_r($ip6);
					// print_r($el);
					// exit;
					break;
				default:
					// noop
					break;
			}
		}
	}

		echo "Parse RIR {$rir} GUID ASN routes\n";
		foreach($asn as $as => $id) {
			if(isset($guid[$id])) {
				// $arr = $guid[$id];
				// echo "Found AS {$as} on {$rir} with {$id}\n";
				if(!isset($asroutes[$as]))
					$asroutes[$as] = $guid[$id];
				else
					$asroutes[$as] = array_merge($asroutes[$as], $guid[$id]);
				// file_put_contents("{$outdir}/asn/AS{$as}.txt", implode("\n", $arr));
			}
		}
		// print_r($asroutes);
		// exit();
		$guid = array();
		$asn = array();
		$asguid = array();


}


$regions = array();
foreach($iso3166 as $country) {
	$el = str_getcsv($country);
	if($el[6] == "")
		continue;
	$region[$el[6]][] = $el[1];

}

// print_r($region);
// exit(0);

// print_r($res);
echo "Write Aggregate country lists from all RIRs\n";
foreach($cip as $country => $arr) {
	file_put_contents("{$outdir}/country/{$country}.txt", implode("\n", $arr));

}



echo "Parse RIR DB for ASN routes\n";
foreach($dbs as $rir => $db) {
	$i = 0;
	$k = 0;
	$db = "{$indir}/". basename($db['db']);
	if (is_readable($db)) {
		echo "Parsing $db \n";
		// $arr = file('compress.zlib://'.$db);
		$arr = array();
		$ret = null;
		$cmd = "zgrep -E \"(^route|^origin)\" $db";
		exec($cmd, $arr, $ret);
		// print_r($arr);

		foreach($arr as $line) {
			unset($matches);
			if(preg_match("/^(route|route6):[ ]+([0-9a-f\:\.\/]+)/", $line, $matches))
				$route = trim($matches[2]);

			if(preg_match("/^origin:[ ]+AS([0-9]+)/", $line, $matches))
				$asnum = round($matches[1]);

			if((isset($route)) && (isset($asnum))) {
				$asroutes[$asnum][] = trim($route);
				// echo "Add route {$route} for AS {$asnum}\n";
				unset($route);
				unset($asnum);
			}

			$i++;
			if($i > 49999) {
				$k++;;
				echo ($k*5) ."0k.";
				$i = 0;
			}
		}
		echo "\n";

	}
}

// exit(0);

echo "Write ". count($asroutes) ." ASN files\n";
$i = 0;
$k = 0;
foreach($asroutes as $as => $routes) {
	// echo "Write file for {$as} ". count($routes) . "entries\n";
	if(!empty($routes)) {
		file_put_contents("{$outdir}/asn/AS{$as}.txt", implode("\n", array_unique($routes)));
	}
	$i++;
	if($i > 9999) {
		$k++;;
		echo "{$k}0k.";
		$i = 0;
	}
}
echo "\n";

echo "Time: ". date("Y-m-d H:i:s") ."\n";
