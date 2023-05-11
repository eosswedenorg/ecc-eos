<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ECCEOS\Serializer\K1PublicKeySerializer;
use ECCEOS\Checksum\InvalidChecksumException;
use BitWasp\Buffertools\Buffer;


final class K1PublicKeySerializerTest extends TestCase
{
    /**
     * @var K1PublicKeySerializer
     */
    protected static $ser;

    public static function setUpBeforeClass(): void
    {
        self::$ser = new K1PublicKeySerializer();
    }

    /**
     * WIF Key, decoded data (in hex) pairs
     */
    public function validData()
    {
        return [
            ['PUB_K1_6XqRHVR7Nz6zGke9R6ex1UpPDZDzgVWNdbq2jLDQEvE3GfAdSx', '02d87ea2ee94e07548283acb65dde1dffe2cd5db7dd711c3d11d25e04c74121087'],
            ['PUB_K1_4zMpSxYZQRPA5sLm6Acuctsprz4QNZvwztKUTG4U3xWdpH94W9', '020d54297e7754ed3509645e9f4b201d152ae27b2128f164a4d912989bcbc3ae6f'],
            ['PUB_K1_5vCbTgkUj7WgoZW7D4Ev4mafLS4MncUU3iQVvHDzXcSW3o1ztT', '028794cd73c7966334a1f4fe2c6c1a4a195fa3828a363dd7ea559383607afbfa02']
        ];
    }

    public function invalidChecksumData()
    {
        return [
            ['PUB_K1_86i1nY2cw9HqbgqYK5v84fuviPJmRNyqDz7KxnyvHk4cAuquxG'],
            ['PUB_K1_5zuz7zaLvuBz4xCnWH9tUHaHRzqshVfQ4SX5s9yDApgpAtA2e2'],
            ['PUB_K1_6X682W3DK2PM12K384VhwuyxPgUTnUG3shn4N5m1VtUAZEawkZ'],
        ];
    }

    public function invalidPrefixData()
    {
        return [
            ['XXX_K1_5MUTb8naF5xRz2yMc4LP192jU2ENdrmmAoirmUYezWBCokyRM3'],
            ['PUB_R1_6c5N8EFaMNAs4usDnRxHoKY22to33MPZjSPDeJc2TToYAru4N6']
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
