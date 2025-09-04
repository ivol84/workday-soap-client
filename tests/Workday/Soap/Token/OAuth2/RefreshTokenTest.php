<?php

namespace Workday\Soap\Token\OAuth2;

use ivol\Workday\Soap\Token\OAuth2\RefreshToken;
use PHPUnit_Framework_TestCase;

class RefreshTokenTest extends PHPUnit_Framework_TestCase
{
    /** @test */
    public function toJsonReturnsCorrectJson()
    {
        $sut = new RefreshToken("client_id", 'clientSecret', 'refreshToken', 'tokenUrl');

        $this->assertEquals('{"client_id":"client_id","client_secret":"clientSecret","refresh_token":"refreshToken"}', $sut->toJson());
    }
}