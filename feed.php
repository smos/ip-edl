<?php

error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE);

$outdir = "out";
$filter = "";

$result = [];

if((!isset($_GET['asn'])) && (!isset($_GET['country'])) && (!isset($_GET['rir'])) ) {
	header("Content-Type: text/plain");
	echo file_get_contents("README");
	exit(0);

}

if( isset( $_GET['proto'] ) ) {
	switch( $_GET['proto'] ) {
		case 'ipv4':
			$filter_flag = FILTER_FLAG_IPV4;
			break;
		case 'ipv6':
			$filter_flag = FILTER_FLAG_IPV6;
			break;
		case 'both':
		default:
			$filter_flag = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6;
			break;
	}
} else {
	$filter_flag = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6;
}

function rlimit($cl) {
	return substr($cl, 0, 7);
}

function climit($cl) {
	return substr($cl, 0, 2);
}

function aslimit($as) {
	return substr($as, 0, 6);
}

// Process Country value
if(isset($_GET['proto'])) {
	switch($_GET['proto']) {
		case "ip4":
			$filter = ".";
			break;
		case "ip6":
			$filter = ":";
			break;
		default:
			$filter = "";
			break;

	}

}
// Process Country value
if(isset($_GET['rir'])) {
	$val = strtolower(strip_tags($_GET['rir']));
	$items = preg_split("/;/", $val);
	$items = array_map('trim', $items);
	$items = array_map('rlimit', $items);
	// print_r($items);

	foreach($items as $rir) {
		if(is_readable("{$outdir}/rir/{$rir}.txt")) {
			$lines = file("{$outdir}/rir/{$rir}.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			$filtered = array_filter($lines, fn($line) => str_contains($line, $filter));

			echo implode(PHP_EOL, $filtered);
			//echo file_get_contents("{$outdir}/rir/{$rir}.txt");
		}
	}
}

// Process Country value
if(isset($_GET['country'])) {
	$val = strtoupper(strip_tags($_GET['country']));
	$items = preg_split("/;/", $val);
	$items = array_map('trim', $items);
	$items = array_map('climit', $items);
	// print_r($items);

	foreach($items as $country) {
		if(is_readable("{$outdir}/country/{$country}.txt")) {
			$lines = file("{$outdir}/country/{$country}.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			$filtered = array_filter($lines, fn($line) => str_contains($line, $filter));

			echo implode(PHP_EOL, $filtered);
			// echo file_get_contents("{$outdir}/country/{$country}.txt");
		}
	}
}

// Process ASN value
if(isset($_GET['asn'])) {
	$val = strtoupper(strip_tags($_GET['asn']));
	$items = preg_split("/;/", $val);
	$items = array_filter($items, 'is_numeric');
	$items = array_map('aslimit', $items);
	//print_r($items);

	foreach($items as $as) {
		if(is_readable("{$outdir}/asn/AS{$as}.txt")) {
			$lines = file("{$outdir}/asn/AS{$as}.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			$filtered = array_filter($lines, fn($line) => str_contains($line, $filter));

			echo implode(PHP_EOL, $filtered);
			// echo file_get_contents("{$outdir}/asn/AS{$as}.txt");
		}
	}
}

if( isset( $_GET['format'] ) ) {
	switch( strtolower( $_GET['format'] ) ){
		case 'json':
			header('Content-type: application/json');
			echo( json_encode( $result ) );
			break;
		case 'php':
			echo( var_export( $result, true ) );
			break;
		case 'raw':
		default:
			echo( implode( "\n", $result ) );
			break;
	}
} else {
	echo( implode( "\n", $result ) );
}
