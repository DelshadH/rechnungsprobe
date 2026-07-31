<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';

$source = file_get_contents('/input/invoice.xml');
if ($source === false) {
    throw new RuntimeException('input unavailable');
}
$invoice = \NumNum\UBL\Reader::ubl()->parse($source);
$xml = (new \NumNum\UBL\Generator())->invoice($invoice);
if (file_put_contents('/output/roundtrip.xml', $xml) === false) {
    throw new RuntimeException('output unavailable');
}
