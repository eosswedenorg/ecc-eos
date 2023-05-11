<?php

declare(strict_types=1);

namespace ECCEOS\Serializer;

use ECCEOS\Checksum\Algorithm\Ripemd160;
use ECCEOS\Checksum\Checksum;
use ECCEOS\Checksum\InvalidChecksumException;
use ECCEOS\Utils\Base58;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Buffertools;

use InvalidArgumentException;
use Exception;

abstract class BaseSerializer implements SerializerInterface
{
    const SEPARATOR = "_";

    /**
     * @var Checksum
     */
    protected $_checksum;

    protected $_type;

    protected $_prefix;

    public function __construct()
    {
        $this->_checksum = new Checksum(new Ripemd160());
    }

    /**
     * @param BufferInterface $data
     * @return string
     * @throws Exception
     */
    public function encode(BufferInterface $data): string
    {
        $check_data = Buffertools::concat($data, new Buffer($this->_type));

        // calculate checksum
        $checksum = $this->_checksum->calculate($check_data);

        $data = Buffertools::concat($data, $checksum);

        // Add prefix and Base58 encoded data.
        return $this->_buildPrefix() . Base58::encode($data);
    }

    /**
     * @param string $data
     * @return BufferInterface
     * @throws Exception
     * @throws InvalidChecksumException
     */
    public function decode(string $data): BufferInterface
    {
        $valid_prefix = $this->_buildPrefix();

        // Validate prefix.
        $prefix = substr($data, 0, strlen($valid_prefix));
        if ($prefix !== $valid_prefix) {
            $msg = sprintf("Signature must be prefixed with '%s'", $valid_prefix);
            throw new InvalidArgumentException($msg);
        }

        // Remove prefix.
        $data = substr($data, strlen($valid_prefix));
        $decoded = Base58::decode($data);

        // Last 4 bytes is the checksum.
        $checksum = $this->_checksum->getChecksum($decoded);

        // Get the data
        $decodedData = $this->_checksum->getData($decoded);

        // Append type to the end and validate
        $check_data = Buffertools::concat($decodedData, new Buffer($this->_type));
        if ($this->_checksum->validate($check_data, $checksum) === false) {
            throw new InvalidChecksumException("Invalid checksum.");
        }

        return $decodedData;
    }

    protected function _buildPrefix()
    {
        return $this->_prefix . self::SEPARATOR
            . $this->_type . self::SEPARATOR;
    }
}
