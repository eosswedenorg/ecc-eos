<?php declare(strict_types=1);

namespace ECCEOS;

use GMP;
use ECCEOS\Serializer\PrivateKeySerializer;

use BitWasp\Buffertools\Buffer;
use Mdanter\Ecc\Crypto\Key\PrivateKey as ECCPrivateKey;

use ECCEOS\Checksum\InvalidChecksumException;
use InvalidArgumentException;
use Exception;

class PrivateKey
{
    /**
     * @var ECCPrivateKey
     */
    protected $_ecc;

    /**
     * @var PrivateKeySerializer
     */
    protected $_serializer;

    public function __construct($data = null)
    {
        $this->_serializer = new PrivateKeySerializer();

        if ($data == null) {
            $data = gmp_init(0, 10);
        }

        if (is_string($data)) {
            $data = $this->_serializer->decode($data)->getGmp();
        }

        if (!($data instanceof GMP)) {
            throw new InvalidArgumentException("Data must be a GMP number or WIF String.");
        }

        $this->_ecc = new ECCPrivateKey(Factory::getMathAdapter(), Factory::getSecp256k1(), $data);
    }

    /**
     * @return PublicKey
     * @throws InvalidChecksumException
     */
    public function getPublicKey() : PublicKey
    {
        $eccpub = $this->_ecc->getPublicKey();

        return new PublicKey($eccpub->getPoint());
    }

    /**
     * Create a signature using this private key.
     *
     * Shorthand for calling `new Signature($data, $key)`
     *
     * @param string $data
     * @return Signature
     * @throws Exception
     */
    public function sign(string $data) : Signature
    {
        return new Signature($data, $this);
    }

    /**
     * Get the private key's numeric representation.
     *
     * @return GMP
     */
    public function getGMP() : GMP
    {
        return $this->_ecc->getSecret();
    }

    public function encode() : string
    {
        $data = gmp_strval($this->_ecc->getSecret(), 16);
        $data = Buffer::hex($data);

        return $this->_serializer->encode($data);
    }

    public function __toString() : string
    {
        return $this->encode();
    }
}