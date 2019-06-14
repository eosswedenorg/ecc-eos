<?php declare(strict_types=1);

namespace ECCEOS\Utils;

use GMP;
use ECCEOS\Factory;

use Mdanter\Ecc\Crypto\Signature\Signature as ECCSignature;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Primitives\PointInterface;

use InvalidArgumentException;
use Exception;


/**
 * Algorithm implemented from https://www.secg.org/sec1-v2.pdf (section 4.1.6)
 * And some code borrowed from https://github.com/cryptocoinjs/ecurve/blob/922d41039cc4b31e14cc6ba79b910b3cb8d86fdb/lib/curve.js
 */

class RecoverPublicKey
{
    /**
     * @param GeneratorPoint $generator
     * @param GMP $e
     * @param ECCSignature $sig
     * @param int $i
     * @return PointInterface
     * @throws Exception
     */
    public static function recover(GeneratorPoint $generator, GMP $e,
                                   ECCSignature $sig, int $i) : PointInterface
    {
        $math = Factory::getMathAdapter();
        $curve = $generator->getCurve();

        $n = $generator->getOrder();
        $G = $generator;
        $r = $sig->getR();
        $s = $sig->getS();

        $one = gmp_init(1, 10);

        if ($math->cmp($r, $one) < 0 || $math->cmp($r, $math->sub($n, $one)) > 0) {
            throw new InvalidArgumentException("Invalid r value");
        }

        if ($math->cmp($s, $one) < 0 || $math->cmp($s, $math->sub($n, $one)) > 0) {
            throw new InvalidArgumentException("Invalid s value");
        }

        // $i we can skip the loop (1. For j from 0 to h)
        $oddY = (bool) ($i & 1);

        // 1. For j from 0 to h (Using $i we can calculate j).
        // The most significant bit is used.
        $j = $i >> 1;

        // 1.1. Let x = r + jn.
        // Because $j is either 0 or 1
        // this can be simplified to
        //   j = 0 -> r + 0n = r
        //   j = 1 -> r + 1n = r + n
        $x = ($j) ? $math->add($r, $n) : $r;


        // 1.2 and 1.3 Find R by convert x to a point on the curve.
        $R = $curve->getPoint($x, $curve->recoverYfromX($oddY, $x), $n);
        if ($R->isInfinity()) {
            throw new \Exception("nR is not a valid curve point");
        }

        // Compute -e from e
        $eNeg = $math->mul($e, gmp_init(-1, 10));
        $eNeg = $math->mod($eNeg, $n);

        // 1.6.1 Compute Q = r^-1 (sR -  eG)
        //               Q = r^-1 (sR + -eG)
        $rInv = $math->inverseMod($r, $n);

        $sR = $R->mul($s);
        $eGInv = $G->mul($eNeg);

        $Q = $sR->add($eGInv)->mul($rInv);
        if (!$curve->contains($Q->getX(), $Q->getY())) {
            throw new \Exception("Failed to calculate Q");
        }
        return $Q;
    }

    public static function calculateParam(GeneratorPoint $generator,
                                          GMP $hash,
                                          ECCSignature $sig,
                                          PointInterface $Q) : int
    {
        for($i = 0; $i < 4; $i++) {

            try {
                $Qprim = self::recover($generator, $hash, $sig, $i);

                if ($Qprim->cmp($Q) == 0) {
                    return $i;
                }
            } catch(Exception $e) {

                if ($e->getCode() != 1337) {
                    throw $e;
                }
            }
        }

        throw new \Exception("Unable to find parameter");
    }
}