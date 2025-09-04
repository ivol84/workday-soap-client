<?php

namespace ivol\Workday\Soap;

use ivol\Workday\Soap\Header\Builder;
use ivol\Workday\Soap\Header\BuilderTest;
use ivol\Workday\Soap\Token\Token;
use SoapClient as SoapClientBase;
use SoapFault;

class SoapClient extends SoapClientBase
{
    /** @var BuilderTest */
    private $builder;
    /** @var Token */
    private $token;
    /** @var string */
    private $requestWithSoapHeaders;
    /** @var array */
    private $headers = [];
    /** @var resource */
    private $context;

    /**
     * @param $wsdl
     * @param array|null $options See \SoapClient options in php.net. You may use token option to setup authentication
     * @throws SoapFault
     */
    public function __construct($wsdl, array $options = [])
    {
        $this->context = stream_context_create();
        $this->token = isset($options['token']) ? $options['token'] : null;
        $options['stream_context'] = $this->context;
        parent::__construct($wsdl, $options);
        $this->builder = new Builder($this);
    }

    /**
     * @param array $headers
     */
    public function addHttpHeaders($headers)
    {
        $this->headers = array_merge($this->headers, $headers);
    }

    public function removeHeader($headerName)
    {
        unset($this->headers[$headerName]);
    }

    /**
     * @param BuilderTest $headerBuilder
     */
    public function setBuilder($headerBuilder)
    {
        $this->builder = $headerBuilder;
    }

    public function __getLastRequest()
    {
        return is_null($this->requestWithSoapHeaders) ? parent::__getLastRequest() : $this->requestWithSoapHeaders;
    }

    public function __doRequest($request, $location, $action, $version, $one_way = 0)
    {
        $this->requestWithSoapHeaders = $this->token ? $this->builder->addAuthentication($request, $this->token) : $request;
        foreach ($this->headers as $headerName => $headerValue) {
            stream_context_set_option(
                $this->context,
                "http",
                "header",
                sprintf("%s: %s\r\n", $headerName, $headerValue)
            );
        }
        return parent::__doRequest($this->requestWithSoapHeaders, $location, $action, $version, $one_way);
    }
}