<?php

namespace ivol\Workday\Soap\Header;

use DOMDocument;
use DOMNode;
use DOMXPath;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use ivol\Workday\Request\Loader;
use ivol\Workday\Soap\SoapClient;
use ivol\Workday\Soap\Token\OAuth2\RefreshToken;
use ivol\Workday\Soap\Token\UsernamePasswordToken;
use ivol\Workday\Soap\Token\UsernameToken;
use ivol\Workday\Soap\Token\X509AuthenticationToken;
use ivol\X509\CertificateFactory;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit_Framework_MockObject_MockObject;
use PHPUnit_Framework_TestCase;
use Psr\Http\Message\RequestInterface;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RuntimeException;

class BuilderTest extends PHPUnit_Framework_TestCase
{
    /** @var (SoapClient&MockObject)|PHPUnit_Framework_MockObject_MockObject */
    private $client;
    /** @var Builder */
    private $sut;

    protected function setUp()
    {
        $this->client = $this->getMockBuilder(SoapClient::class)->disableOriginalConstructor()->getMock();
        $this->sut = new Builder($this->client);
    }

    /**
     * @test
     * @throws Exception
     */
    public function addAuthenticationForX509AuthenticationToken()
    {
        list($certificate, $privateKey, $passPhrase) = CertificateFactory::create();
        $userNameToken = new UsernameToken("root", "root_tenant");
        $token = new X509AuthenticationToken($certificate, $privateKey, $passPhrase,
            $userNameToken);

        $response = $this->sut->addAuthentication(Loader::load(), $token);

        list($userName, $password) = $this->getUsernamePasswordFromResponse($response);
        $this->assertEquals($userNameToken->getWWSUserName(), $userName);
        $this->assertNull($password);
        $this->validateSignature($response, $certificate);
    }

    /**
     * @test
     */
    public function addAuthenticationForUsernamePasswordToken()
    {
        $userNamePasswordToken = new UsernamePasswordToken("root","root", "root_tenant");

        $response = $this->sut->addUsernamePasswordAuthentication(Loader::load(), $userNamePasswordToken);

        list($userName, $password) = $this->getUsernamePasswordFromResponse($response);
        $this->assertEquals($userNamePasswordToken->getWWSUserName(), $userName);
        $this->assertEquals($userNamePasswordToken->getPassword(), $password);
    }

    /** @test */
    public function addAuthenticationForRefreshToken()
    {
        $responseFromOauth = '{"access_token": "7c3obrknwd6nnkxv0r64jdpbx","refresh_token": "yxsiqvdkakj0tp9a4i2xe1fbg4blgrq1ntg0cidyjgnfg","token_type": "Bearer" }';
        $handlerStack = HandlerStack::create(new MockHandler([new Response(200, [], $responseFromOauth)]));
        $historyContainer = [];
        $handlerStack->push(Middleware::history($historyContainer));
        $this->sut->setHttpClient(new Client(['handler' => $handlerStack]));
        $this->client->expects($this->once())->method('addHttpHeaders')->with([
            'Authorization' => 'Bearer 7c3obrknwd6nnkxv0r64jdpbx'
        ]);

        $this->assertEquals('', $this->sut->addAuthentication('',
            new RefreshToken('clientId', 'clientSecret', 'refreshToken',
                'https://some_url')));
        $this->assertCount(1, $historyContainer);
        /** @var RequestInterface $request */
        $request = $historyContainer[0]['request'];
        $this->assertEquals("POST", $request->getMethod());
        $this->assertEquals('client_id=clientId&client_secret=clientSecret&grant_type=refresh_token&refresh_token=refreshToken', $request->getBody()->getContents());
    }

    /**
     * @test
     * @expectedException  GuzzleHttp\Exception\ServerException
     */
    public function addAuthenticationForRefreshTokenOnErrorGettingAccessToken()
    {
        $handlerStack = HandlerStack::create(new MockHandler([new Response(500)]));
        $this->sut->setHttpClient(new Client(['handler' => $handlerStack]));

        $this->sut->addAuthentication('',
            new RefreshToken('clientId', 'clientSecret', 'refreshToken',
                'https://some_url'));
    }

    /**
     * @test
     * @expectedException RuntimeException
     */
    public function addAuthenticationForRefreshTokenOnInvalidFormatOfAccessToken()
    {
        $responseFromOauth = '{"access_token123": "7c3obrknwd6nnkxv0r64jdpbx","refresh_token": "yxsiqvdkakj0tp9a4i2xe1fbg4blgrq1ntg0cidyjgnfg","token_type": "Bearer" }';
        $handlerStack = HandlerStack::create(new MockHandler([new Response(200, [], $responseFromOauth)]));
        $this->sut->setHttpClient(new Client(['handler' => $handlerStack]));

        $this->sut->addAuthentication('',
            new RefreshToken('clientId', 'clientSecret', 'refreshToken',
                'https://some_url'));
    }

    /**
     * @param string $xml
     * @return DOMDocument
     */
    private function createDom($xml)
    {
        $dom = new DOMDocument();
        $dom->loadXML($xml);
        return $dom;
    }

    private function createXPathWithSecurityNamespaces(DOMDocument $dom)
    {
        $soapNS = $dom->documentElement->namespaceURI;
        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace(Builder::SOAP_HEADER_WSSOAP_PREFIX, $soapNS);
        $xpath->registerNamespace(Builder::SOAP_HEADER_WSSE_PREFIX, Builder::WSSENS);
        $xpath->registerNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        return $xpath;
    }

    /**
     * @param string $response
     * @return array[$username, $password]
     */
    private function getUsernamePasswordFromResponse($response)
    {
        $xpath = $this->createXPathWithSecurityNamespaces($this->createDom($response));
        $usernameToken = $xpath->query(Builder::SOAP_SECURITY_XPATH . '/wsse:' . Builder::SOAP_NAMESPACE_USERNAME_TOKEN_SUFFIX)->item(0);
        $nodes = $usernameToken->childNodes;
        $username = $password = null;
        /** @var DOMNode $node */
        foreach ($nodes as $node) {
            switch ($node->localName) {
                case Builder::SOAP_NAMESPACE_USERNAME_SUFFIX:
                    $username = $node->textContent;
                    break;
                case Builder::SOAP_NAMESPACE_PASSWORD_SUFFIX:
                    $password = $node->textContent;
                    break;
            }
        }
        return [$username, $password];
    }

    /**
     * @param string $response
     * @param $expectedCertificate
     * @throws Exception
     */
    private function validateSignature($response, $expectedCertificate)
    {
        $dom = $this->createDom($response);
        $dsig = new XMLSecurityDSig();
        $signature = $dsig->locateSignature($dom);
        $this->assertTrue($dsig->validateReference());
        $this->assertEquals(CertificateFactory::reformatCertificateText($expectedCertificate), $this->getX509Certificate($signature));

    }

    /**
     * @param DOMNode $signature
     * @return string $x509Certificate]
     */
    private function getX509Certificate(DOMNode $signature)
    {
        $dom = new DOMDocument();
        $dom->appendChild($dom->importNode($signature, true));
        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        return  $xpath->query('//ds:X509Certificate')->item(0)->nodeValue;
    }


}