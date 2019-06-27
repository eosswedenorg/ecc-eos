<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ECCEOS\Serializer\PublicKeySerializer;
use ECCEOS\Checksum\InvalidChecksumException;
use BitWasp\Buffertools\Buffer;


final class PublicKeySerializerTest extends TestCase
{
    /**
     * @var PublicKeySerializer
     */
    protected static $ser;

    public static function setUpBeforeClass() : void
    {
        self::$ser = new PublicKeySerializer();
    }

    /**
     * WIF Key, decoded data (in hex) pairs
     */
    public function validData()
    {
        return [
            [ 'EOS7ZycTQu9eYoN7pDCsR1RmxqzkhNyRXPeJCg6Cq2t7B9677Pto1', '03610d8092defb4943c2bab5f4d921e414f561fe6b8fec52660465f55c61ff75b4' ],
            [ 'EOS56jhhD87z3NhaeAV5bad8qDHGchJPxQZD1a9U6U2cHgtWhhzac', '021bcf27f93ea374d7619fbf9ad294c874f4ab27d39b4046de66437deb36f6afe9' ],
            [ 'EOS53K1MLsvpYPDQn26N3YptRR8cFWKmyBuiUC4XMCTbRtoZ2EWxf', '021407d1602191e7e3c14c449e91a97000a3d3658fd78d8dc1a81d5ae458914fa3' ],
            [ 'EOS68c81AxszwGLEWnetHXSUsHafe5VnRw7mN7hqaa78NQ2HxbmWp', '02a3bff075d2b570d7d9b8423adbf496f14879e2c354345c366a746aa543d72fc3' ]
        ];
    }

    public function invalidChecksumData()
    {
        return [
            [ 'EOS5opyVxUNwgXcCpmGSihNBjAwxLMeFiVQbuoXdfoQyLEcV545c7' ],
            [ 'EOS7G4m5bS5zChJhcF2CM7gPJnYcEdUF3erByhi2rZg8ZBK5Eb4WJ' ],
            [ 'EOS8KDhueY6xPmVY1ThZgwwS1fR7U24hPaAgq1Jz1AGmqb7JnEdQx' ],
        ];
    }

    public function invalidPrefixData()
    {
        return [
            [ 'ECC6Tf33zBksrKspknxHRfz8QKeUu3CuktE81ChGtYxQuV1BvwStt' ],
            [ 'ABC5j5GoXkybr8Nf7zEpWDNZ3V8JmbjBFh63mPc14nWHctwZR95uF' ]
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
     * @dataProvider invalidPrefixData
     *
     * @param string $data
     */
    public function testInvalidPrefixDecode(string $data)
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
