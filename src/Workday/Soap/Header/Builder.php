<?php /** @noinspection ALL */

namespace ivol\Workday\Soap\Header;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use GuzzleHttp\Client;
use ivol\Workday\Soap\SoapClient;
use ivol\Workday\Soap\Token\OAuth2\RefreshToken;
use ivol\Workday\Soap\Token\Token;
use ivol\Workday\Soap\Token\UsernamePasswordToken;
use ivol\Workday\Soap\Token\UsernameToken;
use ivol\Workday\Soap\Token\X509AuthenticationToken;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RuntimeException;

class Builder
{
    const WSSENS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    const SOAP_HEADER_XPATH = '//wssoap:Envelope/wssoap:Header';
    const SOAP_SECURITY_XPATH = '//wssoap:Envelope/wssoap:Header/wsse:Security';
    const SOAP_NAMESPACE_HEADER_SUFFIX = 'Header';
    const SOAP_NAMESPACE_USERNAME_SUFFIX = 'Username';
    const SOAP_NAMESPACE_PASSWORD_SUFFIX = 'Password';
    const SOAP_NAMESPACE_USERNAME_TOKEN_SUFFIX = 'UsernameToken';
    const SOAP_NAMESPACE_SECURITY_SUFFIX = 'Security';
    const SOAP_HEADER_WSSE_PREFIX = 'wsse';
    const SOAP_HEADER_WSSOAP_PREFIX = 'wssoap';
    const SOAP_TRANSFORMATION_ALGORITHM = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    private $httpClient;
    /** @var SoapClient */
    private $soapClient;

    /** @param SoapClient $soapClient */
    public function __construct(SoapClient $soapClient)
    {
        $this->soapClient = $soapClient;
        $this->httpClient = new Client();
    }

    /**
     * Add authentication headers depends on Token type.
     * @param string $request
     * @param Token $token
     * @return string|false on error
     * @see Token implementations
     *
     */
    public function addAuthentication($request, Token $token)
    {
        if ($token instanceof UsernamePasswordToken) {
            $method = 'addUsernamePasswordAuthentication';
        } else if ($token instanceof X509AuthenticationToken) {
            $method = 'addX509Authentication';
        } else if ($token instanceof RefreshToken) {
            $method = 'addRefreshTokenAuthentication';
        } else {
            throw new RuntimeException("Unsupported token:" . get_class($token));
        }
        return $this->$method($request, $token);
    }

    /**
     * @param string $request
     * @param X509AuthenticationToken $x509AuthenticationToken
     * @return false|string
     * @throws \Exception
     */
    public function addX509Authentication($request, X509AuthenticationToken $x509AuthenticationToken)
    {
        $domDocument = $this->createXmlDocumentFromRequest($request);
        $headerElement = $this->getHeader($domDocument);
        $securityElement = $this->getSecurityElement($domDocument, $headerElement);
        $this->addUsernameTokenElement($domDocument, $securityElement, $x509AuthenticationToken->getUserNameToken());
        $signature = new XMLSecurityDSig();
        // Use the c14n exclusive canonicalization
        $signature->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        // Sign using SHA-512
        $signature->addReference(
            $domDocument,
            $x509AuthenticationToken->getDigestMethodAlgorithm(),
            array(self::SOAP_TRANSFORMATION_ALGORITHM),
            ['force_uri' => true]
        );
        // Create a new (private) Security key
        $privateKey = new XMLSecurityKey($x509AuthenticationToken->getSignatureMethodAlgorithm(), array('type' => 'private'));
        // Load the private key
        $privateKey->passphrase = $x509AuthenticationToken->getPassPhrase();
        $privateKey->loadKey($x509AuthenticationToken->getPrivateKey());
        // Add the associated public key to the signature
        $signature->sign($privateKey);
        $signature->add509Cert($x509AuthenticationToken->getCertificate());
        $signature->appendSignature($securityElement);
        return $domDocument->saveXML();
    }

    /**
     * @param $request
     * @param RefreshToken $refreshToken
     * @return false|string
     */
    public function addRefreshTokenAuthentication($request, RefreshToken $refreshToken)
    {
        $response = $this->httpClient->post($refreshToken->getTokenUrl(), [
            'form_params' => [
                'client_id' => $refreshToken->getClientId(),
                'client_secret' => $refreshToken->getClientSecret(),
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken->getRefreshToken()
            ]
        ]);
        $responseArray = json_decode($response->getBody()->getContents(), true);
        if (!isset($responseArray['access_token'])) {
            throw new RuntimeException("Cannot get access token from response " . var_export($responseArray, true));
        }
        $this->soapClient->addHttpHeaders(['Authorization' => 'Bearer ' . $responseArray['access_token']]);

        return $request;
    }

    /**
     * @param string $request
     * @param UsernamePasswordToken $token
     * @return false|string
     * @noinspection PhpUnused
     */
    public function addUsernamePasswordAuthentication($request, UsernamePasswordToken $token)
    {
        $domDocument = $this->createXmlDocumentFromRequest($request);
        $headerElement = $this->getHeader($domDocument);
        $securityElement = $this->getSecurityElement($domDocument, $headerElement);
        $this->addUsernameTokenElement($domDocument, $securityElement, $token);
        return $domDocument->saveXML();
    }

    public function setHttpClient(Client $httpClient)
    {
        $this->httpClient = $httpClient;
    }

    /**
     * @param DOMDocument $domDocument
     * @param DOMElement|DOMNode $securityElement
     * @param UsernameToken $usernameToken
     * @return DOMElement
     * @noinspection PhpUnused
     */
    private function addUsernameTokenElement(DOMDocument $domDocument, $securityElement, UsernameToken $usernameToken)
    {
        $userNameTokenElement = $domDocument->createElementNS(self::WSSENS, sprintf("%s:%s",
            self::SOAP_HEADER_WSSE_PREFIX, self::SOAP_NAMESPACE_USERNAME_TOKEN_SUFFIX));
        $securityElement->insertBefore($userNameTokenElement, $securityElement->firstChild);
        $usernameElement = $domDocument->createElementNS(self::WSSENS, sprintf("%s:%s",
            self::SOAP_HEADER_WSSE_PREFIX, self::SOAP_NAMESPACE_USERNAME_SUFFIX));
        $usernameTextNode = $domDocument->createTextNode($usernameToken->getWWSUserName());
        $usernameElement->appendChild($usernameTextNode);
        $userNameTokenElement->appendChild($usernameElement);
        if ($usernameToken instanceof UsernamePasswordToken) {
            $passwordElement = $domDocument->createElementNS(self::WSSENS, sprintf("%s:%s",
                self::SOAP_HEADER_WSSE_PREFIX, self::SOAP_NAMESPACE_PASSWORD_SUFFIX));
            $passwordTextNode = $domDocument->createTextNode($usernameToken->getPassword());
            $passwordElement->appendChild($passwordTextNode);
            $userNameTokenElement->appendChild($passwordElement);
        }
        return $userNameTokenElement;
    }

    /**
     * @param $request
     * @return DOMDocument
     */
    private function createXmlDocumentFromRequest($request)
    {
        $domDocument = new DOMDocument();
        $domDocument->loadXML($request);
        return $domDocument;
    }

    /**
     * @param DOMDocument $domDocument
     * @param $soapPath
     * @return DOMNode|null
     */
    private function findFirstElementByXPath(DOMDocument $domDocument, $soapPath)
    {
        list(, $soapNS) = $this->getDocumentNamespaceInfo($domDocument);
        $SOAPXPath = new DOMXPath($domDocument);
        $SOAPXPath->registerNamespace(self::SOAP_HEADER_WSSOAP_PREFIX, $soapNS);
        $SOAPXPath->registerNamespace(self::SOAP_HEADER_WSSE_PREFIX, self::WSSENS);
        $elements = $SOAPXPath->query($soapPath);
        return $elements->item(0);
    }

    /**
     * @param $domDocument
     * @return array[DomElement, Namespace, prefix]
     */
    private function getDocumentNamespaceInfo(DOMDocument $domDocument)
    {
        $envelope = $domDocument->documentElement;
        $soapNS = $envelope->namespaceURI;
        $soapPFX = $envelope->prefix;
        return [$envelope, $soapNS, $soapPFX];

    }

    /**
     * @param DOMDocument $domDocument
     * @param DOMElement $headerElement
     * @return DOMElement|DOMNode|null
     */
    private function getSecurityElement(DOMDocument $domDocument, DOMElement $headerElement)
    {
        $securityElement = $this->findFirstElementByXPath($domDocument, self::SOAP_SECURITY_XPATH);
        if (!$securityElement) {
            $securityElement = $domDocument->createElementNS(self::WSSENS, sprintf("%s:%s",
                self::SOAP_HEADER_WSSE_PREFIX, self::SOAP_NAMESPACE_SECURITY_SUFFIX));
            $headerElement->appendChild($securityElement);
        }
        return $securityElement;
    }

    /**
     * @param DOMDocument $domDocument
     * @return DOMElement|DOMNode
     */
    private function getHeader(DOMDocument $domDocument)
    {
        $header = $this->findFirstElementByXPath($domDocument, self::SOAP_HEADER_XPATH);
        list($envelope, $soapNS, $soapPFX) = $this->getDocumentNamespaceInfo($domDocument);
        if (!$header) {
            $header = $domDocument->createElementNS($soapNS, sprintf("%s:%s", $soapPFX,
                self::SOAP_NAMESPACE_HEADER_SUFFIX));
            $envelope->insertBefore($header, $envelope->firstChild);
        }
        return $header;
    }
}