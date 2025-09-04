<?php

namespace ivol\Workday\Soap\Token\OAuth2;

use ivol\Workday\Soap\Token\Token;

class RefreshToken implements Token
{
    /** @var string */
    private $clientId;
    /** @var string */
    private $clientSecret;
    /** @var string */
    private $refreshToken;
    /** @var string */
    private $tokenUrl;

    /**
     * @param string $clientId
     * @param string $clientSecret
     * @param string $refreshToken
     */
    public function __construct($clientId, $clientSecret, $refreshToken, $tokenUrl)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->refreshToken = $refreshToken;
        $this->tokenUrl = $tokenUrl;
    }

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * @return string
     */
    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    /**
     * @return string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * @return string
     */
    public function getTokenUrl()
    {
        return $this->tokenUrl;
    }

    public function toJson()
    {
        return json_encode([
            'client_id' => $this->getClientId(),
            'client_secret' => $this->getClientSecret(),
            'refresh_token' => $this->getRefreshToken()
        ]);
    }

}