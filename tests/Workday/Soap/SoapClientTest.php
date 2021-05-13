<?php /** @noinspection PhpUnhandledExceptionInspection */

namespace ivol\Workday\Soap;

use ivol\Workday\Soap\Header\Builder;
use ivol\Workday\Soap\Token\UsernamePasswordToken;
use PHPUnit_Framework_TestCase;

class SoapClientTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @noinspection PhpParamsInspection
     */
    public function __doRequestCallsBuilderToSetAuthenticationHeaders()
    {
        $builder = $this->createMock(Builder::class);
        $builder->expects($this->once())->method('addAuthentication')->will($this->returnArgument(0));
        $sut = new SoapClient(null, [
            'token' => new UsernamePasswordToken("root", "root", "root"),
            'uri' => "https://test.com",
            'location' => "https://test.com",
        ]);
        $sut->setBuilder($builder);

        $sut->__doRequest("", "", "", 0);
    }

    /**
     * @test
     * @noinspection PhpParamsInspection
     */
    public function __doRequestDoenstCallBuilderInCaseNoTokenConfigured()
    {
        $builder = $this->createMock(Builder::class);
        $builder->expects($this->never())->method('addAuthentication');
        $sut = new SoapClient(null, [
            'uri' => "https://test.com",
            'location' => "https://test.com",
        ]);
        $sut->setBuilder($builder);

        $sut->__doRequest("", "", "", 0);
    }


}