<?php

namespace ivol\Workday\Soap\Token;

/**
 * Token for username password authentication
 */
class UsernamePasswordToken extends UsernameToken
{
    /** @var string */
    private $password;

    public function __construct($userName, $password, $tenant)
    {
        parent::__construct($userName, $tenant);
        $this->password = (string) $password;
    }

    /**
     * @return string
     */
    public function getPassword()
    {
        return $this->password;
    }
}