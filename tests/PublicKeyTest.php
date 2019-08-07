<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ECCEOS\Factory;
use ECCEOS\PublicKey;
use ECCEOS\Signature;
use ECCEOS\Checksum\InvalidChecksumException;

use Mdanter\Ecc\Primitives\Point;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Math\GmpMathInterface;

final class PublicKeyTest extends TestCase
{
    /**
     * @var GeneratorPoint
     */
    protected static $generator;

    /**
     * @var GmpMathInterface
     */
    protected static $math;

    public static function setUpBeforeClass() : void
    {
        self::$generator = Factory::getSecp256k1();
        self::$math = Factory::getMathAdapter();
    }

    /**
     * Wif key, X coordinate (hex), Y coordinate (hex)
     */
    public function data()
    {
        return [
            [ 'EOS7H92pdv5Z2mY6FfgRSjDyfUYCRJooAhLDy9VCmThzf6usoTQ8z', '3ad229a398c0beb1905898ebee25331dd5a783cc2c73980d5b05a29df2780388', '424ff8536c60e934e5c2ad0626d1ad0b9f191184a27f4675feaba4619285a3e3' ],
            [ 'EOS5A6wUqBqoMGUG2TusMggezh4rJvzNLJHd2rZRspikFogCBYyAp', '2373d6ec1427b3487fbce679faf2fa77c328e6c2e6395edcd2b9c55915c886b2', '90f90a02f215b712300e8e1ee873581aed79923fb4f9e6a1263c977bd2e802a'  ],
            [ 'EOS5RQvFcAmT4ukhFpzw1Xo7rNJz1V6ugKzBVvSE3ewrQLcmygyNS', '463736d197cdcf8c66df30fc4d67acf12c94b09918c8d8edf2f85cb6d0bed449', '6cc900abbc787ae1c1a73355ee4c135a5ee957845bc5a8d8562eb1c63408c732' ]
        ];
    }

    /**
     * @dataProvider data
     *
     * @param $wif_key
     */
    public function testConstruct($wif_key)
    {
        $key = new PublicKey($wif_key);
        $this->assertTrue($key instanceof PublicKey);
    }

    /**
     * @dataProvider data
     *
     * @param $wif_key
     * @param $x
     * @param $y
     */
    public function testPointConstruct($wif_key, $x, $y)
    {
        $x = gmp_init($x, 16);
        $y = gmp_init($y, 16);
        $p = new Point(self::$math,
            self::$generator->getCurve(),
            $x, $y,
            self::$generator->getOrder());

        $key = new PublicKey($p);
        $this->assertEquals($wif_key, $key->encode());
    }

    public function invalidData()
    {
        return [
            [ 'EOS7H92pdv5Z2mY6FfgRSjDyfUYCRJooAhLDy9VCmThzf6djvn4uY', InvalidChecksumException::class ],
            [ 'PRE5RQvFcAmT4ukhFpzw1Xo7rNJz1V6ugKzBVvSE3ewrQLcmygyNS', InvalidArgumentException::class ],
            [ 1337, InvalidArgumentException::class ]
        ];
    }

    /**
     * @dataProvider invalidData
     */
    public function testInvalidConstruct($data, $exception)
    {
        $this->expectException($exception);
        $key = new PublicKey($data);
    }

    /**
     * @dataProvider data
     *
     * @param $wif_key
     * @param $x
     * @param $y
     */
    public function testGetXY($wif_key, $x, $y)
    {
        $key = new PublicKey($wif_key);

        $this->assertEquals($x, gmp_strval($key->getX(), 16));
        $this->assertEquals($y, gmp_strval($key->getY(), 16));
    }

    /**
     * @dataProvider data
     *
     * @param $wif_key
     */
    public function testEncode($wif_key)
    {
        $key = new PublicKey($wif_key);
        $this->assertEquals($wif_key, $key->encode());
        $this->assertEquals($wif_key, $key->__toString());
    }

    public function testVerify()
    {
        $key = new PublicKey('EOS8WcnLBDAMN96cdDScQwaQc1qQrzKTt66o2wjkbNvqRCz27kKhe');
        $message = 'Hello World';
        $sig = new Signature('SIG_K1_KWWBFs6AsmZK5U1H2ugize4qnpKM4WuQS8EdDTPT6DpA3GBvWYJvbFrPDsxG8QTgfZ9nkj78r7FHjH78SZAkBRmVQiakQN');

        $this->assertTrue($key->verify($sig, $message));
        $this->assertFalse($key->verify($sig, $message . "_not_valid"));
    }
}