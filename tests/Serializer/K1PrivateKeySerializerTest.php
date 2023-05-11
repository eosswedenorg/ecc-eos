<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ECCEOS\Serializer\K1PrivateKeySerializer;
use ECCEOS\Checksum\InvalidChecksumException;
use BitWasp\Buffertools\Buffer;


final class K1PrivateKeySerializerTest extends TestCase
{
    /**
     * @var PrivateKeySerializer
     */
    protected static $ser;

    public static function setUpBeforeClass(): void
    {
        self::$ser = new K1PrivateKeySerializer();
    }

    /**
     * WIF Key, decoded data (in hex) pairs
     *
     * IMPORTANT: Do not use these keys in production environments as they are publicly available.
     */
    public function validData()
    {
        return [
            ['PVT_K1_2G6UBJrYimHwXekjqKXzvxXbZ62P7bXwehXaDHpAYTc8JZ8zRT', 'a5f832541395f7a7c434d41090d590d72697d173048f97b4530a9ce635e7fdc7'],
            ['PVT_K1_gcKtdpQwDJVUoyTikDzVLJitnv9BjgXK2QFgF3a9iRNNKKVK', '018cf6dc7a195421d991ce38910d4cd0132b90106012a66beb5678432465f580'],
            ['PVT_K1_YJYeG7tdZyx7eDpayCyxaVibZnKHs9wGs3JpHX528aKwH9vQS', '4713805dce7ac80af5a192219eae354e249d7d4a87fc0560bcecacb13a6bdd34'],
        ];
    }

    /**
     * Dont use these either. as they are not valid :)
     */
    public function invalidChecksumData()
    {
        return [
            ['PVT_K1_2CBprpfhVQXkHDF5p19YTisiwhJcy5cKnDBBpHF43ifHYJcgxC'],
            ['PVT_K1_23Ap8d8sXWbiyfez8dEpxLHntRxEveHvX7h5bUX3hMBfVY9Fee'],
            ['PVT_K1_1CGEHwcsbZqYpFCbDmauYABRGqWCqQzkfaP4EqmTDzD8YFqf4'],
        ];
    }

    /**
     * Dont use these either. as they are not valid :)
     */
    public function invalidData()
    {
        return [
            ['PVT_K1_26mk2xh3nJXzhBeA6zXem98NvnFmead7gJewS7rGCN94gWszyu'],
            ['PVT_K1_293DpcSp2UXj7aaRSEZiFfJn4Qibim8zSgkBR9BGAjisWyEMy'],
            ['PVT_K1_2eZnyCo2JyQezzT6jMLcuXWUjrNArnWujNXVaDTWBSh3nYQe9R'],
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
     * @dataProvider invalidChecksumData
     *
     * @param string $data
     */
    public function testInvalidChecksumDecode(string $data)
    {
        $this->expectException(InvalidChecksumException::class);
        self::$ser->decode($data);
    }

    /**
     * @dataProvider invalidData
     *
     * @param string $data
     */
    public function testInvalidDataDecode(string $data)
    {
        $this->expectException(InvalidChecksumException::class);
        self::$ser->decode($data);
    }
}
