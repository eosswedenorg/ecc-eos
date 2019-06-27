<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ECCEOS\Checksum\Algorithm\Sha256Double;
use BitWasp\Buffertools\Buffer;

class Sha256DoubleTest extends TestCase
{
    public function data()
    {
        return [
            [ 'Hello World', '42a873ac3abd02122d27e80486c6fa1ef78694e8505fcec9cbcc8a7728ba8949'],
            [ 'molestie pharetra velit', '67013a0684d7835fc5ee2111a55b347f41283ed5787d77852bb3a5806a0e3fb7' ],
            [ 'Morbi feugiat sodales dolor, at eleifend diam', '10e36bafa1bca5c2155249a0f2f77acc2284c102eb831b8b415bc122cf3d632d' ]
        ];
    }

    /**
     * @dataProvider data
     */
    public function testHash(string $data, string $expected)
    {
        $sha256d = new Sha256Double();
        $hash = $sha256d->calculate(new Buffer($data))->getHex();
        $this->assertEquals($expected, $hash);
    }
}