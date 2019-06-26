<?php declare(strict_types=1);

namespace ECCEOS;

use GMP;
use ECCEOS\Serializer\SignatureSerializer;
use ECCEOS\Utils\RecoverPublicKey;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\Buffertools;
use BitWasp\Buffertools\BufferInterface;
use Mdanter\Ecc\Crypto\Signature\Signature as ECCSignature;

use Exception;
use InvalidArgumentException;

class Signature
{
    /**
     * @var ECCSignature
     */
    protected $_sig = null;

    /**
     * @var int
     */
    protected $_recoverParam = 0;

    /**
     * @var SignatureSerializer
     */
    protected $_serializer;


    /**
     * Constructor.
     *
     * If $key is provided. A signature will be created from $data using
     * the given key. Note that this is the actual message and not a hash.
     * The function will first hash the data using the private key before
     * creating a signature.
     *
     * Otherwise if private key is not provided. $data should contain a signature in WIF format
     * and will be parsed into it's internal representation.
     *
     * @param string $data
     * @param PrivateKey|null $key
     * @throws Exception
     */
    public function __construct(string $data, PrivateKey $key = null)
    {
        $this->_serializer = new SignatureSerializer();

        if ($key !== null) {
            $this->_sign($key, $data);
        } else {
            $this->_parse($data);
        }
    }

    /**
     * Recover the public key from a signature.
     *
     * @param string|null $data     data used to create the signature
     * @return PublicKey
     * @throws InvalidArgumentException
     */
    public function recoverPublicKey(string $data)
    {
        $hash = Factory::calculateSignatureHash($data);
        $point = RecoverPublicKey::recover(Factory::getSecp256k1(),
            $hash, $this->_sig, $this->_recoverParam);

        return new PublicKey($point);
    }

    /**
     * @param PublicKey $key
     * @param string $data
     * @return bool
     */
    public function verify(PublicKey $key, string $data) : bool
    {
        // Create EC public key.
        $ecKey = Factory::createPublicKey($key->getX(), $key->getY());

        // Hash the data.
        $hash = Factory::calculateSignatureHash($data);

        // Verify against this signature.
        $signer = Factory::getSigner();
        return $signer->verify($ecKey, $this->_sig, $hash);
    }

    /**
     * @return string
     * @throws Exception
     */
    public function encode(): string
    {
        return $this->_serializer->encode($this->toBuffer());
    }

    /**
     * Convert signature data to buffer object.
     *
     * @return BufferInterface
     * @throws Exception
     */
    public function toBuffer()
    {
        $r = gmp_strval($this->_sig->getR(), 16);
        $s = gmp_strval($this->_sig->getS(), 16);

        $i = $this->_recoverParam;
        $i += 4;  // compressed
        $i += 27; // compact  //  24 or 27 :( forcing odd-y 2nd key candidate)

        return Buffertools::concat(Buffer::int($i), Buffer::hex($r . $s));
    }

    /**
     * @return string
     * @throws Exception
     */
    public function __toString() : string
    {
        return $this->encode();
    }

    /**
     * Create a signature.
     *
     * @param PrivateKey $key
     * @param string $data
     * @throws Exception
     */
    protected function _sign(PrivateKey $key, string $data)
    {
        $generator = Factory::getSecp256k1();

        // Hash data using private key
        $hash = Factory::calculateSignatureHash($data);

        $key = $generator->getPrivateKeyFrom($key->getGMP());

        // Generate the random K
        $K = Factory::getRNG($key, $hash)->generate($generator->getOrder());
        $this->_sig = Factory::getSigner()->sign($key, $hash, $K);

        // Calculate recover parameter
        $ecPriv = Factory::createPrivateKey($key->getSecret());
        $Q = $ecPriv->getPublicKey()->getPoint();
        $param = RecoverPublicKey::calculateParam($generator, $hash, $this->_sig, $Q);

        $this->_recoverParam = $param;
    }

    /**
     * Parse a WIF encoded signature.
     *
     * @param string $data
     * @throws InvalidChecksumException
     */
    protected function _parse(string $data)
    {
        $decoded = $this->_serializer->decode($data);

        if ($decoded->getSize() != 65) {
            throw new Exception("Signature must be 65 bytes long.");
        }

        // Read and validate recover param.
        $param = (int) $decoded->slice(0, 1)->getInt();
        if ($param - 27 !== ($param - 27) % 7) {
            throw new Exception("Invalid recovery parameter");
        }

        // Paramters are compressed. so we need to remove those bits.
        $this->_recoverParam = $param - 27 - 4;

        // Get R and S
        $r = $decoded->slice(1, 32)->getGmp();
        $s = $decoded->slice(33, 65)->getGmp();
        $this->_sig = new ECCSignature($r, $s);
    }

    /**
     * Create a signature from private key and data.
     *
     * @param PrivateKey $key
     * @param string $data
     * @return Signature
     * @throws Exception
     */
    public static function sign(PrivateKey $key, string $data)
    {
        return new self($data, $key);
    }
}