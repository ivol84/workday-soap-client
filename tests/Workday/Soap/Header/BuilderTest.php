<?php

namespace ivol\Workday\Soap\Header;

use DOMDocument;
use DOMNode;
use DOMXPath;
use Exception;
use ivol\Workday\Request\Loader;
use ivol\Workday\Soap\Token\UsernamePasswordToken;
use ivol\Workday\Soap\Token\UsernameToken;
use ivol\Workday\Soap\Token\X509AuthenticationToken;
use ivol\X509\CertificateFactory;
use PHPUnit_Framework_TestCase;
use RobRichards\XMLSecLibs\XMLSecurityDSig;

class BuilderTest extends PHPUnit_Framework_TestCase
{
    /** @var Builder */
    private $sut;

    protected function setUp()
    {
        $this->sut = new Builder();
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