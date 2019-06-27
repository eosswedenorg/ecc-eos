<?php declare(strict_types=1);

namespace ECCEOS\Serializer;

// Public key WIF uses sha256 double as checksum calculator.
use ECCEOS\Checksum\Algorithm\Sha256Double;
use ECCEOS\Checksum\Checksum;
use ECCEOS\Utils\Base58;
use ECCEOS\Checksum\InvalidChecksumException;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;

use BitWasp\Buffertools\Buffertools;
use InvalidArgumentException;
use Exception;

/**
 * Information about the EOS PrivateKey WIF can be found here:
 * https://developers.eos.io/keosd/docs/wallet-import-format-specification-wif
 */
class PrivateKeySerializer implements SerializerInterface
{
    /**
     * First byte contains a version constant.
     */
    const VERSION = 0x80;

    /**
     * @var Checksum
     */
    protected $_checksum;

    public function __construct()
    {
        $this->_checksum = new Checksum(new Sha256Double());
    }

    /**
     * @param BufferInterface $data
     * @return string
     * @throws Exception
     */
    public function encode(BufferInterface $data): string
    {
        // Add version byte to the beginning.
        $version = Buffer::int(self::VERSION);
        $data = Buffertools::concat($version, $data);

        // Pack checksum
        $data = $this->_checksum->pack($data);

        // Base58 encoded data.
        return Base58::encode($data);
    }

    /**
     * @param string $data
     * @return BufferInterface
     * @throws Exception
     * @throws InvalidArgumentException
     * @throws InvalidChecksumException
     */
    public function decode(string $data): BufferInterface
    {
        $decoded = Base58::decode($data);

        // Get Checksum.
        $checksum = $this->_checksum->getChecksum($decoded);

        // Extract the data from the checksum packed data.
        $data = $this->_checksum->getData($decoded);

        // Validate checksum.
        if ($this->_checksum->validate($data, $checksum) == false) {
            throw new InvalidChecksumException("Invalid checksum.");
        }

        // Validate version.
        $version = (int) $data->slice(0, 1)->getInt();
        if ($version !== self::VERSION) {
            throw new InvalidArgumentException("Version does not match");
        }

        // Remove version.
        return $data->slice(1);
    }
}