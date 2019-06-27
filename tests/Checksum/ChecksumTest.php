<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;

use ECCEOS\Checksum\Checksum;
use ECCEOS\Checksum\Algorithm\Ripemd160; // We use Ripe for these tests.
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\Buffertools;


class ChecksumTest extends TestCase
{
    /**
     * @var Checksum
     */
    protected $check;

    protected function setUp() : void
    {
        $this->check = new Checksum(new Ripemd160());
    }

    public function testPack()
    {
        $buffer = Buffer::hex('ff1234');
        $checksum = Buffer::hex('ce');
        $packed = $this->check->pack($buffer, $checksum);

        $this->assertEquals('ff1234ce', $packed->getHex());

        $checksum = $this->check->calculate($buffer);
        $packed = $this->check->pack($buffer);
        $expected = $buffer->getHex() . $checksum->getHex();

        $this->assertEquals($expected, $packed->getHex());
    }

    public function data()
    {
        return [
            [ '4235591a117a0f2913a7abc4', '66c2125d' ],
            [ '08a6959271369d6382a32ad2', '1ed8409f' ]
        ];
    }

    /**
     * @dataProvider data
     *
     * @param string $data
     * @param string $checksum
     */
    public function testGetDataAndChecksum(string $data, string $checksum)
    {
        $packed = $this->check->pack(Buffer::hex($data), Buffer::hex($checksum));

        $packedData = $this->check->getData($packed);
        $packedChecksum = $this->check->getChecksum($packed);

        $this->assertEquals($data, $packedData->getHex());
        $this->assertEquals($checksum, $packedChecksum->getHex());
    }

    public function testCalculate()
    {
        // Taken from Ripemd160 test.
        $expected = '72091c46';
        $buffer = new Buffer('molestie pharetra velit');

        $calculated = $this->check->calculate($buffer);
        $this->assertEquals($expected, $calculated->getHex());
    }

    public function testValidate()
    {
        // Taken from Ripemd160 test.
        $checksum = Buffer::hex('3c398154');
        $data = new Buffer('Morbi feugiat sodales dolor, at eleifend diam');
        $buffer = Buffertools::concat($data, $checksum);

        $this->assertTrue($this->check->validate($buffer));

        $checksum = Buffer::hex('deadbeef');
        $buffer = Buffertools::concat($data, $checksum);
        $this->assertFalse($this->check->validate($buffer));
    }
}