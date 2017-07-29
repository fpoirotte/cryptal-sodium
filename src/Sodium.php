<?php

namespace fpoirotte\Cryptal\Plugins;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\Padding\None;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\PaddingInterface;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;

class Sodium implements CryptoInterface, PluginInterface
{
    protected $tagLength;
    protected $padding;
    protected $cipher;
    private $key;

    public function __construct(
        CipherEnum          $cipher,
        ModeEnum            $mode,
        PaddingInterface    $padding,
        $key,
        $tagLength = self::DEFAULT_TAG_LENGTH
    ) {
        if (!($padding instanceof None)) {
            throw new \InvalidArgumentException(
                'Invalid padding scheme specified ' .
                '(hint: use fpoirotte\Cryptal\Padding\None)'
            );
        }

        if ($cipher == CipherEnum::CIPHER_CHACHA20()) {
            if ($mode != ModeEnum::MODE_ECB()) {
                throw new \InvalidArgumentException('Unsupported mode');
            }
            if ($tagLength !== SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES) {
                $expected = SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;
                throw new \InvalidArgumentException("Invalid tag length requested: sould be $expected");
            }
            if (strlen($key) !== SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES) {
                $expected = SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;
                throw new \InvalidArgumentException("Invalid key size: should be $expected bytes long");
            }
        } elseif ($cipher == CipherEnum::CIPHER_AES_256()) {
            if (!sodium_crypto_aead_aes256gcm_is_available()) {
                throw new \InvalidArgumentException('AES instructions not available');
            }
            if ($mode != ModeEnum::MODE_GCM()) {
                throw new \InvalidArgumentException('Unsupported mode');
            }
            if ($tagLength !== SODIUM_CRYPTO_AEAD_AES256GCM_ABYTES) {
                $expected = SODIUM_CRYPTO_AEAD_AES256GCM_ABYTES;
                throw new \InvalidArgumentException("Invalid tag length requested: sould be $expected");
            }
            if (strlen($key) !== SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES) {
                $expected = SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES;
                throw new \InvalidArgumentException("Invalid key size: should be $expected bytes long");
            }
        } else {
            throw new \InvalidArgumentException('Unsupported cipher algorithm');
        }

        $this->tagLength    = $tagLength;
        $this->cipher       = $cipher;
        $this->key          = $key;
    }

    public function encrypt($iv, $data, &$tag = null, $aad = '')
    {
        $blockSize  = $this->getBlockSize();
        $missing    = $blockSize - (strlen($data) % $blockSize);
        $data      .= $this->padding->getPaddingData($blockSize, $missing);

        if ($this->cipher == CipherEnum::CIPHER_CHACHA20()) {
            $res = sodium_crypto_aead_chacha20poly1305_encrypt($data, $aad, $iv, $this->key);
        } else {
            $res = sodium_crypto_aead_aes256gcm_encrypt($data, $aad, $iv, $this->key);
        }
        $tag = substr($res, -$this->tagLength);
        return (string) substr($res, 0, -$this->tagLength);
    }

    public function decrypt($iv, $data, $tag = null, $aad = '')
    {
        $blockSize  = $this->getBlockSize();
        $options    = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;
        $data      .= $tag;

        if ($this->cipher == CipherEnum::CIPHER_CHACHA20()) {
            $res = sodium_crypto_aead_chacha20poly1305_decrypt($data, $aad, $iv, $this->key);
        } else {
            $res = sodium_crypto_aead_aes256gcm_decrypt($data, $aad, $iv, $this->key);
        }

        $padLen     = $this->padding->getPaddingSize($res, $blockSize);
        return $padLen ? (string) substr($res, 0, -$padLen) : $res;
    }

    public function getIVSize()
    {
        if ($this->cipher == CipherEnum::CIPHER_AES_256()) {
            return SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES;
        } elseif ($this->cipher == CipherEnum::CIPHER_CHACHA20()) {
            return SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES;
        } else {
            throw new \InvalidArgumentException('Unsupported cipher');
        }
    }

    public function getBlockSize()
    {
        if ($this->cipher == CipherEnum::CIPHER_AES_256()) {
            return 16;
        } elseif ($this->cipher == CipherEnum::CIPHER_CHACHA20()) {
            // ChaCha20 does not really use blocks.
            return 1;
        } else {
            throw new \InvalidArgumentException('Unsupported cipher');
        }
    }

    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        $registry->addCipher(
            __CLASS__,
            CipherEnum::CIPHER_CHACHA20(),
            ModeEnum::MODE_ECB(),
            ImplementationTypeEnum::TYPE_COMPILED()
        );

        if (sodium_crypto_aead_aes256gcm_is_available()) {
            $registry->addCipher(
                __CLASS__,
                CipherEnum::CIPHER_AES_256(),
                ModeEnum::MODE_GCM(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );
        }
    }

    public function getCipher()
    {
        return $this->cipher;
    }

    public function getKey()
    {
        return $this->key;
    }
}
