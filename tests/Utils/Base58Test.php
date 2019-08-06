<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;

use BitWasp\Buffertools\Buffer;
use ECCEOS\Utils\Base58;
use ECCEOS\Utils\Base58InvalidCharacterException;

class Base58Test extends TestCase
{
    public function invalidChars()
    {
        return [ [ '0' ],  [ 'I' ],  [ 'O' ],  [ 'l' ], [ '+' ] ];
    }

    public function data()
    {
        return [
            [
                'Maecenas iaculis libero sit amet eros porttitor, at hendrerit felis consectetur.',
                'quZxAYzr7VQRmroqEYVxSdLXEk69rnzrG7DBWdWq9auojFr8K8doowWuG4Bz8HH2gZEpyoFoSSPNjYrjc6MYiDWbWSN1S3ofK2W7K7HuHk1qP'
            ],
            [ "\x00\x00Hello World", '11JxF12TrwUP45BMd' ],
            [ '', '' ]
        ];
    }

    /**
     * @dataProvider data
     *
     * @param string $input
     * @param string $expected
     */
    public function testEncode(string $input, string $expected)
    {
        $buffer = new Buffer($input);
        $this->assertEquals($expected, Base58::encode($buffer));
    }

    /**
     * @dataProvider data
     *
     * @param string $expected
     * @param string $input
     */
    public function testValidDecode(string $expected, string $input)
    {
        $expected = new Buffer($expected);
        $this->assertTrue($expected->equals(Base58::decode($input)));
    }

    /**
     * @dataProvider invalidChars
     *
     * @param string $invalid_ch
     * @throws Base58InvalidCharacterException
     */
    public function testInvalidCharacterDecode(string $invalid_ch)
    {
        $this->expectException(Base58InvalidCharacterException::class);

        Base58::decode('rG7DB' . $invalid_ch . 'WdWq9');
    }
}