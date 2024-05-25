<?php

error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE);

$outdir = "out";

if((!isset($_GET['asn'])) && (!isset($_GET['country']))) {
	header("Content-Type: text/plain");
	echo file_get_contents("README");
	exit(0);

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
if(isset($_GET['rir'])) {
	$val = strtoupper(strip_tags($_GET['rir']));
	$items = preg_split("/;/", $val);
	$items = array_map('trim', $items);
	$items = array_map('rlimit', $items);
	// print_r($items);

	foreach($items as $rir) {
		if(is_readable("{$outdir}/rir/{$rir}.txt")) {
			echo file_get_contents("{$outdir}/rir/{$rir}.txt");
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
			echo file_get_contents("{$outdir}/country/{$country}.txt");
		}
	}

}

// Process Country value
if(isset($_GET['asn'])) {
	$val = strtoupper(strip_tags($_GET['asn']));
	$items = preg_split("/;/", $val);
	$items = array_filter($items, 'is_numeric');
	$items = array_map('aslimit', $items);
	//print_r($items);

	foreach($items as $as) {
		if(is_readable("{$outdir}/asn/AS{$as}.txt")) {
			echo file_get_contents("{$outdir}/asn/AS{$as}.txt");
		}
	}

}

