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
    private $requestWithHeaders;

    /**
     * @param $wsdl
     * @param array|null $options See \SoapClient options in php.net. You may use token option to setup authentication
     * @throws SoapFault
     */
    public function __construct($wsdl, array $options = null)
    {
        $this->builder = new Builder();
        $this->token = isset($options['token']) ? $options['token'] : null;
        parent::__construct($wsdl, $options);
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
        return is_null($this->requestWithHeaders) ? parent::__getLastRequest() : $this->requestWithHeaders;
    }

    public function __doRequest($request, $location, $action, $version, $one_way = 0)
    {
        $this->requestWithHeaders = $this->token ? $this->builder->addAuthentication($request, $this->token) : $request;
        return parent::__doRequest($this->requestWithHeaders, $location, $action, $version, $one_way);
    }
}