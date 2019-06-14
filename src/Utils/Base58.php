<?php

namespace ECCEOS\Utils;

/**
 * Code stolen from https://github.com/Bit-Wasp/bitcoin-php/blob/d3dc4b1b9e6ecaa157b54653b89cb289e7106907/src/Base58.php
 */

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;

class Base58
{
    /**
     * @var string
     */
    private static $base58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    /**
     * Encode a given hex string in base58
     *
     * @param BufferInterface $buffer
     * @return string
     */
    public static function encode(BufferInterface $buffer): string
    {
        $size = $buffer->getSize();
        if ($size === 0) {
            return '';
        }
        $orig = $buffer->getBinary();
        $decimal = $buffer->getGmp();
        $return = '';
        $zero = gmp_init(0);
        $_58 = gmp_init(58);
        while (gmp_cmp($decimal, $zero) > 0) {
            $div = gmp_div($decimal, $_58);
            $rem = gmp_sub($decimal, gmp_mul($div, $_58));
            $return .= self::$base58chars[(int) gmp_strval($rem, 10)];
            $decimal = $div;
        }
        $return = strrev($return);
        // Leading zeros
        for ($i = 0; $i < $size && $orig[$i] === "\x00"; $i++) {
            $return = '1' . $return;
        }
        return $return;
    }
    /**
     * Decode a base58 string
     * @param string $base58
     * @return BufferInterface
     * @throws Base58InvalidCharacterException
     */
    public static function decode(string $base58): BufferInterface
    {
        if ($base58 === '') {
            return new Buffer('', 0);
        }
        $original = $base58;
        $length = strlen($base58);
        $return = gmp_init(0);
        $_58 = gmp_init(58);
        for ($i = 0; $i < $length; $i++) {
            $loc = strpos(self::$base58chars, $base58[$i]);
            if ($loc === false) {
                throw new Base58InvalidCharacterException('Found character that is not allowed in base58: ' . $base58[$i]);
            }
            $return = gmp_add(gmp_mul($return, $_58), gmp_init($loc, 10));
        }
        $binary = gmp_cmp($return, gmp_init(0)) === 0 ? '' : Buffer::int(gmp_strval($return, 10))->getBinary();
        for ($i = 0; $i < $length && $original[$i] === '1'; $i++) {
            $binary = "\x00" . $binary;
        }
        return new Buffer($binary);
    }
}