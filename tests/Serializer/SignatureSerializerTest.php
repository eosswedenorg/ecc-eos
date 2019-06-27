<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ECCEOS\Serializer\SignatureSerializer;
use ECCEOS\Checksum\InvalidChecksumException;
use BitWasp\Buffertools\Buffer;


final class SignatureSerializerTest extends TestCase
{
    /**
     * @var SignatureSerializer;
     */
    protected static $ser;

    public static function setUpBeforeClass() : void
    {
        self::$ser = new SignatureSerializer();
    }

    /**
     * WIF Private Key, Message, Signature pairs.
     */
    public function validData()
    {
        return [
            [
                'SIG_K1_Jytt3yMsdqYju5ArBnz8dq6x3dNfhpkDo4nsks3pe1HxxWCyzw6kGPkxBtGHPjJUiYCkC5rEmTcecm6gxPbVUqSW8wW8EH',
                '1f2376d9a3f0e1dd1b5f5a22be1634d31fb7a333aff0d5ab3fc8ef3c5a015988f36890af91719f3880252ef698855ad27f7ecd0321353afafbe4813fa403893f48'
            ],
            [
                'SIG_K1_K6H9u19DEkd3zgjtQF8cSG7S2hTVwMBR9Ez6iVcMhHK44qgPk42aWSS9ajiagqusjGhUUpMHNS3GERtM3rSyLMj5TiXVRD',
                '1f5442d9a8c87f8de4db467ba56bd8334ec08e1efb5e8a86c433c5093c2a41f6a752cf902e7eb1053fe0fa594ff9d8f410192a473beb6b5d5ee847668444750bfd'
            ],
            [
                'SIG_K1_KgbSbwh68iHmL9PkEcJU2wyFTFxDHUqNc18os7u4ozgExcnVxCBpwjbiCzWcadRYAhAsTwMxMPRjBhSkn94MPuaTm39MMp',
                '205a8db2eb3d8d2f14f9ba2d26d1806b8b0591cc6f97f37f9ed547bf1b37bd737435cf7eb7854e8ee974fc1531db4d02ab11fb0403440226c7e4d348b2ae74d125'
            ]
        ];
    }

    public function invalidChecksumData()
    {
        return [
            [ 'SIG_K1_KALjfzR2fhZAbMHa8twohJgYkSyEYpQP9MtPH5sjHcsfut1Ydbyerd2tVGqP7kVD2kXTzGdqBHVmFZ6otcRnjHQt3ubkoK' ],
            [ 'SIG_K1_K4pdzpbsndMzuC4fmvM5hdR1ZcyyNVy7iBgjrR8seDt1P8hBTATPqyQcrjVngPuaeNb5dfBoLtJNNbLLQpuKY7enYa9D2D' ],
            [ 'SIG_K1_K6GqnSZBPNhv1g5EqmVpDGq3FzCDi6mhbcLG8Y5zX15fLD9HSuJT6FwJ2YkT2y4yyV56UjUaMFwTTFA9Dapx4xeiXC7yX3' ],
        ];
    }

    public function invalidPrefixData()
    {
        return [
            [ 'INV_K1_Kipv1uZH5y8DHGeWKLwp7ak3SnAmjkYxKJsFGLxhysmSgoEhBH69cGfGeHJj8R839bucDGGopsjEoDj5PU4LNmTzompWAj' ],
            [ 'SIG_K2_Kdhpx1QV5fjUpd7UCNdP3fBd5ZgYDTbiTnWmc3iyLWVFtS4NFy796qPw7KcUfrs94EiP6EYWiPqwnUeeFfpoqFg3nwewzf' ]
        ];
    }

    /**
     * @dataProvider validData
     *
     * @param string $expected
     * @param string $data
     */
    public function testValidEncode(string $expected, string $data)
    {
        $encoded = self::$ser->encode(Buffer::hex($data));
        $this->assertEquals($expected, $encoded);
    }


    /**
     * @dataProvider validData
     *
     * @param string $sig
     * @param string $expected
     */
    public function testValidDecode(string $sig, string $expected)
    {
        $decoded = self::$ser->decode($sig);
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
