<?php

namespace ECCEOS;

use GMP;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PrivateKey as ECCPrivateKey;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKey as ECCPublicKey;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Math\MathAdapterFactory as MathFactory;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\Crypto\Signature\HasherInterface;
use Mdanter\Ecc\Curves\SecgCurve;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Primitives\Point;
use Mdanter\Ecc\Random\RandomGeneratorFactory as RNGFactory;
use Mdanter\Ecc\Random\RandomNumberGeneratorInterface;

class Factory
{
    static protected $_debug = null;

    /**
     * @return GmpMathInterface
     */
    static public function getMathAdapter() : GmpMathInterface
    {
        if (self::$_debug === null) {
            self::setDebug(false);
        }

        return MathFactory::getAdapter();
    }

    /**
     * @return GeneratorPoint
     */
    static public function getSecp256k1() : GeneratorPoint
    {
        $curve = new SecgCurve(self::getMathAdapter());
        return $curve->generator256k1();
    }

    /**
     * @param PrivateKeyInterface $key
     * @param GMP $hash
     * @return RandomNumberGeneratorInterface
     */
    static public function getRNG(PrivateKeyInterface $key, GMP $hash) : RandomNumberGeneratorInterface
    {
        return RNGFactory::getHmacRandomGenerator($key, $hash, 'sha256', self::$_debug);
    }

    /**
     * @return Signer
     */
    static public function getSigner() : Signer
    {
        return new Signer(self::getMathAdapter());
    }

    /**
     * @return HasherInterface
     */
    static public function getSignHasher() : HasherInterface
    {
        return new SignHasher('sha256', self::getMathAdapter());
    }

    /**
     * @param $data
     * @return GMP
     */
    static public function calculateSignatureHash($data) : GMP
    {
        return self::getSignHasher()->makeHash($data, self::getSecp256k1());
    }

    /**
     * Create Private key from secret number.
     *
     * @param GMP $secret
     * @return PrivateKeyInterface
     */
    static public function createPrivateKey(GMP $secret) : PrivateKeyInterface
    {
        return new ECCPrivateKey(self::getMathAdapter(), self::getSecp256k1(), $secret);
    }

    /**
     * Create public key from X,Y Coordinates.
     *
     * @param GMP $x
     * @param GMP $y
     * @return PublicKeyInterface
     */
    static public function createPublicKey(GMP $x, GMP $y) : PublicKeyInterface
    {
        $G = self::getSecp256k1();
        $M = self::getMathAdapter();

        $point = new Point($M, $G->getCurve(), $x, $y);
        return new ECCPublicKey($M, $G, $point);
    }

    /**
     * Set debug mode
     *
     * @param bool $value
     */
    static public function setDebug(bool $value)
    {
        self::$_debug = $value;
        $adapter = MathFactory::getAdapter(self::$_debug);
        MathFactory::forceAdapter($adapter);
    }
}