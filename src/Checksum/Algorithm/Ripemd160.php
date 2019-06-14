<?php declare(strict_types=1);

namespace ECCEOS\Checksum\Algorithm;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;

use Exception;

/**
 * Checksum based on Ripemd160 hashing function.
 */
Class Ripemd160 implements AlgorithmInterface
{
    /**
     * @param BufferInterface $buffer
     * @return BufferInterface
     * @throws Exception
     */
    public function calculate(BufferInterface $buffer) : BufferInterface
    {
        $hash = hash('ripemd160', $buffer->getBinary(), true);
        return new Buffer($hash, 20);
    }
}