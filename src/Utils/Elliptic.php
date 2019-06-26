<?php  declare(strict_types=1);

namespace ECCEOS\Utils;

use BitWasp\Buffertools\Buffer;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;

use Exception;

class Elliptic
{
    /**
     * Returns true if signature is canonical. false otherwise.
     *
     * @param SignatureInterface $sig
     * @return bool
     * @throws Exception
     */
    static public function isCanonical(SignatureInterface $sig)
    {
        // Code stolen from https://github.com/EOSIO/fc/blob/526d8b54196a9a8f4be5188220ac758cedd61b8e/src/crypto/elliptic_common.cpp#L161
        $r = Buffer::hex(gmp_strval($sig->getR(), 16))->getBinary();
        $s = Buffer::hex(gmp_strval($sig->getS(), 16))->getBinary();

        return !(ord($r[0]) & 0x80) && !(ord($r[0]) == 0 && !(ord($r[1]) & 0x80))
            && !(ord($s[0]) & 0x80) && !(ord($s[0]) == 0 && !(ord($s[1]) & 0x80));
    }
}