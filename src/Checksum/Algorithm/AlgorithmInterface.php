<?php declare(strict_types=1);

namespace ECCEOS\Checksum\Algorithm;

use BitWasp\Buffertools\BufferInterface;
use Exception;

interface AlgorithmInterface
{
    /**
     * Calculate the checksum based on $buffer.
     *
     * @param BufferInterface $buffer
     * @return BufferInterface
     * @throws Exception
     */
    public function calculate(BufferInterface $buffer) : BufferInterface;
}
