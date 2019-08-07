<?php
declare(strict_types=1);

use ECCEOS\Checksum\InvalidChecksumException;
use PHPUnit\Framework\TestCase;
use ECCEOS\PrivateKey;
use ECCEOS\PublicKey;
use ECCEOS\Signature;

final class PrivateKeyTest extends TestCase
{
    /**
     * PrivKey, PublicKey pairs
     *
     * IMPORTANT: Do not use these keys in production environments as they are publicly available.
     */
    public function validData()
    {
        return [
            [ '5KHNKXpx9iWPoSiWbpy4j8Gt4ugMp1xd6kmBe2iPXzScUtw1TMs', 'EOS7oSFV59mVkwteccV5B37oaaVN9xZpGaWiYKtZ8p6kGjai3HSbv' ],
            [ '5JRtLCcagMXehySzykpiwjRtVxEzQF1GugFbrJvQwu4UPNuY6A5', 'EOS63ynjeUrV1fY46UJHfJMHpqw7tfaZiJQZrsEC2TwoHDW59iTqZ' ],
            [ '5KShCz2aPp4gcqpZ5nXpp99ZzbL7iih9yNbwUjUHQXQZMajgZPN', 'EOS6rfA1HUVeqwgTVj62rhxZmWu7NgEX66CM2Kje4nrKfkasNY7FP' ],
        ];
    }

    public function testEmptyConstruct()
    {
        $expected = gmp_init(0, 10);
        $pk = new PrivateKey();

        $this->assertTrue(gmp_cmp($expected, $pk->getGMP()) === 0);
    }

    public function testInvalidConstruct()
    {
        $this->expectException(InvalidArgumentException::class);
        $pk = new PrivateKey([]);
    }

    public function testInvalidWifChecksum()
    {
        $this->expectException(InvalidChecksumException::class);
        $pk = new PrivateKey('5HpqieDRSNmHEbXqKn5KXjGadFoRSGkPTr1YNBrAwEYeiAx1azN');
    }

    public function testInvalidWifVersion()
    {
        $this->expectException(InvalidArgumentException::class);
        $pk = new PrivateKey('3EvYGcCbZS8eFynpsr3sgFyZDX9bR4SsBkDGMSphmtzWm4ek7uH');
    }

    public function testGMPConstruct()
    {
        $gmp = gmp_init(25, 10);
        $pk = new PrivateKey($gmp);

        $this->assertTrue(gmp_cmp($pk->getGMP(), $gmp) === 0);
    }

    /**
     * @dataProvider validData
     *
     * @param string $wif
     */
    public function testEncode(string $wif)
    {
        $pk = new PrivateKey($wif);
        $this->assertEquals($wif, $pk->encode());
        $this->assertEquals($wif, $pk->__toString());
    }

    /**
     * @dataProvider validData
     *
     * @param string $priv_wif
     * @param string $pub_wif
     */
    public function testGetPublicKey(string $priv_wif, string $pub_wif)
    {
        $priv = new PrivateKey($priv_wif);
        $pub = $priv->getPublicKey();
        $this->assertTrue($pub instanceof PublicKey);
        $this->assertEquals($pub_wif, $pub->encode());
    }

    /**
     * @dataProvider validData
     *
     * @param string $wif
     */
    public function testSign(string $wif)
    {
        $pk = new PrivateKey($wif);
        $sig = $pk->sign('message');
        $this->assertTrue($sig instanceof Signature);
        $this->assertTrue(strlen($sig->encode()) > 0);
    }
}
