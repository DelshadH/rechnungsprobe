<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';

$source = file_get_contents('/input/invoice.xml');
if ($source === false) {
    throw new RuntimeException('input unavailable');
}
$invoice = (new \Einvoicing\Readers\UblReader())->import($source);
$xml = (new \Einvoicing\Writers\UblWriter())->export($invoice);
if (file_put_contents('/output/roundtrip.xml', $xml) === false) {
    throw new RuntimeException('output unavailable');
}
