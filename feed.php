<?php

error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE);

$outdir = "out";

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

// Process RIR value
if(isset($_GET['rir'])) {
	$val = strtolower(strip_tags($_GET['rir']));
	$items = preg_split("/;/", $val);
	$items = array_map('trim', $items);
	$items = array_map('rlimit', $items);
	// print_r($items);

	foreach($items as $rir) {
		$file = "{$outdir}/rir/{$rir}.txt";
		if(is_readable( $file )) {
			$content = explode( "\n", file_get_contents( $file ) );
			foreach( $content as $cidr ) {
				[ $subnet, $mask ] = explode( "/", $cidr );
				if( filter_var( $subnet, FILTER_VALIDATE_IP, $filter_flag ) ) $result[] = $cidr;
			}
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
		$file = "{$outdir}/country/{$country}.txt";
		if(is_readable( $file )) {
			$content = explode( "\n", file_get_contents( $file ) );
			foreach( $content as $cidr ) {
				[ $subnet, $mask ] = explode( "/", $cidr );
				if( filter_var( $subnet, FILTER_VALIDATE_IP, $filter_flag ) ) $result[] = $cidr;
			}
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
		$file = "{$outdir}/asn/AS{$as}.txt";
		if(is_readable( $file )) {
			$content = explode( "\n", file_get_contents( $file ) );
			foreach( $content as $cidr ) {
				[ $subnet, $mask ] = explode( "/", $cidr );
				if( filter_var( $subnet, FILTER_VALIDATE_IP, $filter_flag ) ) $result[] = $cidr;
			}
		}
	}
}

if( isset( $_GET['format'] ) ) {
	switch( strtolower( $_GET['format'] ) ){
		case 'json':
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
