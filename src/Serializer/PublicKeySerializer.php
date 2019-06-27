<?php declare(strict_types=1);

namespace ECCEOS\Serializer;

use ECCEOS\Checksum\Algorithm\Ripemd160;
use ECCEOS\Checksum\Checksum;
use ECCEOS\Checksum\InvalidChecksumException;
use ECCEOS\Utils\Base58;

use BitWasp\Buffertools\BufferInterface;

use InvalidArgumentException;
use Exception;

class PublicKeySerializer implements SerializerInterface
{
    const PREFIX = "EOS";

    /**
     * @var Checksum
     */
    protected $_checksum;

    public function __construct()
    {
        $this->_checksum = new Checksum(new Ripemd160());
    }

    /**
     * @param BufferInterface $data
     * @return string
     * @throws Exception
     */
    public function encode(BufferInterface $data) : string
    {
        // Pack checksum
        $data = $this->_checksum->pack($data);

        // Add prefix and Base58 encoded data.
        return self::PREFIX . Base58::encode($data);
    }

    /**
     * @param string $data
     * @return BufferInterface
     * @throws Exception
     * @throws InvalidChecksumException
     */
    public function decode(string $data) : BufferInterface
    {
        // Validate prefix.
        $prefix = substr($data, 0 ,strlen(self::PREFIX));
        if ($prefix !== self::PREFIX) {
            $msg = sprintf("Serializer must be prefixed with '%s'", self::PREFIX);
            throw new InvalidArgumentException($msg);
        }

        // Remove prefix.
        $data = substr($data, strlen(self::PREFIX));
        $decoded = Base58::decode($data);

        // Last 4 bytes is the checksum.
        $checksum = $this->_checksum->getChecksum($decoded);

        // Get the data
        $decodedData = $this->_checksum->getData($decoded);

        // Validate checksum.
        if ($this->_checksum->validate($decodedData, $checksum) === false) {
            throw new InvalidChecksumException("Invalid checksum.");
        }

        return $decodedData;
    }
}