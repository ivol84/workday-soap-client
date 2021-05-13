<?php

namespace ivol\Workday\Soap\Token;

/**
 * Token used to build proper workday username for WWS services.
 * Internally used in X509 Authentication to set Username token without password
 */
class UsernameToken implements Token
{
    /** @var string */
    private $userName;

    /** @var string */
    private $tenant;

    /**
     * UsernameToken constructor.
     * @param string $userName
     * @param string $tenant
     */
    public function __construct($userName, $tenant)
    {
        $this->userName = (string) $userName;
        $this->tenant = (string) $tenant;
    }

    /**
     * @return string
     */
    public function getUserName()
    {
        return $this->userName;
    }

    public function getWWSUserName()
    {
        return sprintf("%s@%s", $this->getUserName(), $this->getTenant());
    }

    /**
     * @return string
     */
    public function getTenant()
    {
        return $this->tenant;
    }
}