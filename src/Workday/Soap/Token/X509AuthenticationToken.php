<?php

namespace ivol\Workday\Soap\Token;

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class X509AuthenticationToken implements Token
{
    /** @var string */
    private $certificate;
    /** @var string */
    private $privateKey;
    /** @var string */
    private $passPhrase;
    /** @var UsernameToken */
    private $userNameToken;
    private $digestMethodAlgorithm = XMLSecurityDSig::SHA512;
    private $signatureMethodAlgorithm = XMLSecurityKey::RSA_SHA1;

    /**
     * @param string $certificate
     * @param string $privateKey
     * @param string $passPhrase
     * @param UsernameToken $userNameToken
     */
    public function __construct($certificate, $privateKey, $passPhrase, UsernameToken $userNameToken)
    {
        $this->certificate = (string) $certificate;
        $this->privateKey = (string) $privateKey;
        $this->passPhrase = (string) $passPhrase;
        $this->userNameToken = $userNameToken;
    }

    /**
     * @return string
     */
    public function getCertificate()
    {
        return $this->certificate;
    }

    /**
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * @return string
     */
    public function getPassPhrase()
    {
        return $this->passPhrase;
    }

    /**
     * @return UsernameToken
     */
    public function getUserNameToken()
    {
        return $this->userNameToken;
    }

    /**
     * @return string
     */
    public function getDigestMethodAlgorithm()
    {
        return $this->digestMethodAlgorithm;
    }

    /**
     * @param string $digestMethodAlgorithm
     * @noinspection PhpUnused
     */
    public function setDigestMethodAlgorithm($digestMethodAlgorithm)
    {
        $this->digestMethodAlgorithm = $digestMethodAlgorithm;
    }

    /**
     * @return string
     */
    public function getSignatureMethodAlgorithm()
    {
        return $this->signatureMethodAlgorithm;
    }

    /**
     * @param string $signatureMethodAlgorithm
     * @noinspection PhpUnused
     */
    public function setSignatureMethodAlgorithm($signatureMethodAlgorithm)
    {
        $this->signatureMethodAlgorithm = $signatureMethodAlgorithm;
    }
}