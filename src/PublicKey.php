<?php declare(strict_types=1);

namespace ECCEOS;

use GMP;
use BitWasp\Buffertools\Buffer;
use ECCEOS\Serializer\PublicKeySerializer;
use Mdanter\Ecc\Crypto\Key\PublicKey as ECCPublicKey;

use InvalidArgumentException;
use Mdanter\Ecc\Primitives\PointInterface;
use Mdanter\Ecc\Serializer\Point\CompressedPointSerializer;
use Exception;

class PublicKey
{
    /**
     * @var ECCPublicKey
     */
    protected $_ecc;

    /**
     * @var PublicKeySerializer
     */
    protected $_serialzer;

    /**
     * Constructor.
     *
     * @param string $data
     * @throws InvalidChecksumException
     */
    public function __construct($data)
    {
        $generator = Factory::getSecp256k1();
        $math = Factory::getMathAdapter();

        $this->_serializer = new PublicKeySerializer();

        if (is_string($data)) {
            $data = $this->_serializer->decode($data);
            $pointSerializer = new CompressedPointSerializer($math);
            $point = $pointSerializer->unserialize($generator->getCurve(), $data->getBinary());
        } else if ($data instanceof PointInterface) {
            $point = $data;
        } else {
            throw new InvalidArgumentException("Argument must be a string.");
        }

        $this->_ecc = new ECCPublicKey($math, $generator, $point);
    }

    /**
     * Get the X coordinate.
     *
     * @return GMP
     */
    public function getX() : GMP
    {
        return $this->_ecc->getPoint()->getX();
    }

    /**
     * Get the Y coordinate
     *
     * @return GMP
     */
    public function getY() : GMP
    {
        return $this->_ecc->getPoint()->getY();
    }

    /**
     * Verify $data with this key and signature.
     *
     * Shorthand for calling `$signature->verify($key, $data)`
     *
     * @param Signature $signature
     * @param string $data
     * @return bool
     */
    public function verify(Signature $signature, string $data) : bool
    {
        return $signature->verify($this, $data);
    }

    /**
     * Encode the key into WIF format.
     *
     * @return string
     * @throws Exception
     */
    public function encode() : string
    {
        $pointSerializer = new CompressedPointSerializer(Factory::getMathAdapter());
        $data = $pointSerializer->serialize($this->_ecc->getPoint());
        $data = Buffer::hex($data);

        return $this->_serializer->encode($data);
    }

    /**
     * @return string
     * @throws Exception
     */
    public function __toString() : string
    {
        return $this->encode();
    }
}