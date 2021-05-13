# workday-soap-client

[![Build Status](https://travis-ci.org/ivol84/workday-soap-client.svg?branch=master)](https://travis-ci.org/ivol84/workday-soap-client)

This library allows authenticating requests passed to WWS. It allows 2 types of authentication:
* X509 Authentication 
* UserNameToken authentication

# Usage

```
<?php

use ivol\Workday\Soap\SoapClient;

$wsdl = 'add your link to WWS wsdl here';
$options = [
    'token' => new UsernamePasswordToken("root","root", "root_tenant") // for list of available tokens - check ivol\Workday\Soap\Token
];

$client = new SoapClient($wsdl, $options);
$client->Get_Postings([]);

```
# License
Workday-soap-client is released under the MIT License.