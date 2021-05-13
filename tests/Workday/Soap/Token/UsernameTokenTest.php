<?php
namespace ivol\Workday\Soap\Token;

use PHPUnit_Framework_TestCase;

class UsernameTokenTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function getWWSUserName()
    {
        $token = new UsernameToken("ivol", "ivol_dpt2");

        $this->assertEquals('ivol@ivol_dpt2', $token->getWWSUserName());
    }
}