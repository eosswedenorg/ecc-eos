<?php declare(strict_types=1);

namespace ECCEOS\Checksum\Algorithm;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;

use Exception;

/**
 * Checksum based on sha256 hash function (but does it twice).
 */
Class Sha256Double implements AlgorithmInterface
{
    /**
     * @param BufferInterface $buffer
     * @return BufferInterface
     * @throws Exception
     */
    public function calculate(BufferInterface $buffer) : BufferInterface
    {
        $hash = hash('sha256', $buffer->getBinary(), true);
        $hash = hash('sha256', $hash, true);
        return new Buffer($hash, 32);
    }
}