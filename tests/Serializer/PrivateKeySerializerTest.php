<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ECCEOS\Serializer\PrivateKeySerializer;
use ECCEOS\Checksum\InvalidChecksumException;
use BitWasp\Buffertools\Buffer;


final class PrivateKeySerializerTest extends TestCase
{
    /**
     * @var PrivateKeySerializer
     */
    protected static $ser;

    public static function setUpBeforeClass() : void
    {
        self::$ser = new PrivateKeySerializer();
    }

    /**
     * WIF Key, decoded data (in hex) pairs
     *
     * IMPORTANT: Do not use these keys in production environments as they are publicly available.
     */
    public function validData()
    {
        return [
            [ '5KHNKXpx9iWPoSiWbpy4j8Gt4ugMp1xd6kmBe2iPXzScUtw1TMs', 'c1303c12226a4a0f34a1a2dc2d1f4fb1c454c23eb83aa5ebce06d6fdfa61fd7c' ],
            [ '5JRtLCcagMXehySzykpiwjRtVxEzQF1GugFbrJvQwu4UPNuY6A5', '50d50bca7afcf1c99db47a3adb4ab8d6010bdb81ef53286147e82035b83836e0' ],
            [ '5KShCz2aPp4gcqpZ5nXpp99ZzbL7iih9yNbwUjUHQXQZMajgZPN', 'd65d093d4d1b8d8a2d33f01e6640e514e75d1c222b9bcece4247e6288be8c15f' ],
        ];
    }

    /**
     * Dont use these either. as they are not valid :)
     */
    public function invalidChecksumData()
    {
        return [
            [ '5JKbaJKyE9v37bfeXz5FgHZ8qUnPiUcq7qnhPPVpPKaaU3kdrAX' ],
            [ '5HppDbgTbxi1ixZXoP6tCJZ3m8EkZNRHV8Qn9uxUf6U3ohExVUm' ],
            [ '5JBMmyD9YSb1W9SpWs4u4SbRNwVHHsiTPhH1feA4PWnvErPWbQH' ],
        ];
    }

    /**
     * These are also not valid.
     */
    public function invalidVersionData()
    {
        return [
            [ '3EvYGcCbZS8eFynpsr3sgFyZDX9bR4SsBkDGMSphmtzWm4ek7uH' ],
            [ '9abWoNpPmWtowHZSTYNcobj9LMNbeUcg3dMDwUEnMTdMTY6w7Ez' ],
            [ 'tybDcahpBV4G1XLKG9sqT4R1J2hAUKhcRjwnXGTfVMBod45beo' ]
        ];
    }

    /**
     * @dataProvider validData
     *
     * @param string $wif_key
     * @param string $expected
     */
    public function testValidEncode(string $expected, string $hexdata)
    {
        $encoded = self::$ser->encode(Buffer::hex($hexdata));
        $this->assertEquals($expected, $encoded);
    }


    /**
     * @dataProvider validData
     *
     * @param string $wif_key
     * @param string $expected
     */
    public function testValidDecode(string $wif_key, string $expected)
    {
        $decoded = self::$ser->decode($wif_key);
        $this->assertEquals($expected, $decoded->getHex());
    }

    /**
     * @dataProvider invalidVersionData
     *
     * @param string $data
     */
    public function testInvalidVersionDecode(string $data)
    {
        $this->expectException(InvalidArgumentException::class);
        self::$ser->decode($data);
    }

    /**
     * @dataProvider invalidChecksumData
     *
     * @param string $data
     */
    public function testInvalidChecksumDecode(string $data)
    {
        $this->expectException(InvalidChecksumException::class);
        self::$ser->decode($data);
    }
}
