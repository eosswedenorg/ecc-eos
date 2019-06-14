<?php

namespace ECCEOS\Checksum;

use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Buffertools;

use ECCEOS\Checksum\Algorithm\AlgorithmInterface;
use Exception;

/**
 * This class takes care of the checksum operations used on EOS Private/Public keys.
 *
 * Note: At the moment, all algorithms implemented are 4 bytes from the beginning
 *       of the checksum functions and packed at the end of data strings.
 *       This can maybe change in the future. If that happens, one needs
 *       to abstract that away in the algorithm classes.
 */

class Checksum
{
    const CHECKSUM_LENGTH = 4;

    /**
     * @var AlgorithmInterface
     */
    protected $_algorithm;

    /**
     * Constructor.
     *
     * @param AlgorithmInterface $algorithm
     */
    public function __construct(AlgorithmInterface $algorithm)
    {
        $this->_algorithm = $algorithm;
    }

    /**
     * Pack the checksum along with the data.
     *
     * @param BufferInterface       $data       The data.
     * @param BufferInterface|null  $checksum   The checksum to encode
     *                                          (if not applied, it will be
     *                                          calculated from $data).
     * @return BufferInterface
     * @throws Exception
     */
    public function pack(BufferInterface $data, BufferInterface $checksum = null)
    {
        if ($checksum === NULL) {
            $checksum = $this->calculate($data);
        }

        return Buffertools::concat($data, $checksum);
    }

    /**
     * Return the checksum part from previous packed buffer.
     *
     * @param BufferInterface $data
     * @return BufferInterface
     * @throws Exception
     */
    public function getChecksum(BufferInterface $data)
    {
        // return CHECKSUM_LENGTH bytes from the end.
        return $data->slice(-self::CHECKSUM_LENGTH);
    }

    /**
     * Return the data part from previous packed buffer.
     *
     * @param BufferInterface $data
     * @return BufferInterface
     * @throws Exception
     */
    public function getData(BufferInterface $data)
    {
        // Skip CHECKSUM_LENGTH bytes from the end.
        return $data->slice(0, -self::CHECKSUM_LENGTH);
    }

    /**
     * Calculate checksum.
     *
     * @param BufferInterface $data
     * @return BufferInterface
     * @throws Exception
     */
    public function calculate(BufferInterface $data) : BufferInterface
    {
        $checksum = $this->_algorithm->calculate($data);

        // Take first CHECKSUM_LENGTH bytes.
        return $checksum->slice(0, self::CHECKSUM_LENGTH);
    }

    /**
     * Validate a checksum
     *
     * @param BufferInterface $data
     * @param BufferInterface|null  $checksum   The checksum to check against
     *                                          (if not applied, it will be assumed
     *                                          that it is packed in $data).
     * @return bool
     * @throws Exception
     */
    public function validate(BufferInterface $data, BufferInterface $checksum = null)
    {
        // No checksum provided.
        // Assumed it is packed with the data.
        if ($checksum === NULL) {
            $checksum = $this->getChecksum($data);
            $data = $this->getData($data);
        }

        // Calculate the checksum from data.
        $calculated = $this->calculate($data);

        // Compare.
        return hash_equals($checksum->getBinary(), $calculated->getBinary());
    }
}