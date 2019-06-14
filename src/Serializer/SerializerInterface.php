<?php declare(strict_types=1);

namespace ECCEOS\Serializer;

use BitWasp\Buffertools\BufferInterface;

interface SerializerInterface
{
    /**
     * Encode
     *
     * @param BufferInterface $data
     * @return string
     */
    public function encode(BufferInterface $data) : string;

    /**
     * Decode
     *
     * @param string $data
     * @return BufferInterface
     */
    public function decode(string $data) : BufferInterface;
}