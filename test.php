<?php

require_once 'vendor/autoload.php';

use ECCEOS\PrivateKey;
use ECCEOS\Signature;

// online tool used for testing: https://bachvtuan.github.io/eos-key-tools/

$valid_sig = "SIG_K1_K6UB6Z7z4GdwrYzJQpmwifcH6dsdvYmJaMaWLvJJ87DBLwoGRvMVUo7d6dcNr1QKmnxPSLPJo7c3X62RxtTT7vwZZGeTiM";
$valid_pub = "EOS7GwzMChHCjLTt4e46fvAbSDb9EHouzk2rJ48LDJuXX1TQq8DdW";
$priv_key_string = "5JiTii9eVn14R3vvVyTyJSdTbE74bj99M9Ed37LpQGgLC58H1Xj";

//$priv = new PrivateKey(gmp_init(25, 10));
$priv = new PrivateKey($priv_key_string);

echo $priv . PHP_EOL;

$pub = $priv->getPublicKey();

echo $pub  . PHP_EOL;

assert($pub->encode() == $valid_pub);


// Signing.
$message = "Test Message";
$invalid_message = "Some random data";


$sig = $priv->sign($message);
echo $sig->encode() . PHP_EOL;

assert($sig->encode() == $valid_sig);

$sig = new Signature($valid_sig);

assert($sig->encode() == $valid_sig);

// Verify

if ($pub->verify($sig, $message)) {
    echo "Signature is valid" . PHP_EOL;
} else {
    echo "Signature is NOT valid" . PHP_EOL;
}

assert($pub->verify($sig, $invalid_message) === false);


// Create a random signature.

$priv = new PrivateKey("5KfdCyUj1XjDuWAkBhs7zH2UsrDQtW8jjV3qKhts3pUp7EEtJZx");
$message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";


echo "Public Key: " . $priv->getPublicKey() . PHP_EOL;
echo "Message: " . $message . PHP_EOL;
echo "Signature: " . Signature::sign($priv, $message) . PHP_EOL;
