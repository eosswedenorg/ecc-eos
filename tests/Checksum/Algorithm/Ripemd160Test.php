<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ECCEOS\Checksum\Algorithm\Ripemd160;
use BitWasp\Buffertools\Buffer;

class Ripemd160Test extends TestCase
{
    public function data()
    {
        return [
            [ 'Hello World', 'a830d7beb04eb7549ce990fb7dc962e499a27230'],
            [ 'molestie pharetra velit', '72091c467913dcb89ed04d970ffc56ecc5ca6f26' ],
            [ 'Morbi feugiat sodales dolor, at eleifend diam', '3c398154d648eb9f027b7b407c596beb500a9bec' ]
        ];
    }

    /**
     * @dataProvider data
     */
    public function testHash(string $data, string $expected)
    {
        $ripe = new Ripemd160();
        $hash = $ripe->calculate(new Buffer($data))->getHex();
        $this->assertEquals($expected, $hash);
    }
}