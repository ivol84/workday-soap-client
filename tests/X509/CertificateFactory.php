<?php

namespace ivol\X509;

class CertificateFactory
{
    /**
     * @return array[$certificateString, $privateKey, $passPhrase]
     */
    public static function create()
    {
        $config = array(
            "digest_alg" => "sha256",
            "private_key_bits" => 1024,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        // Create the private and public key
        $privateKeyRes = openssl_pkey_new($config);
        $passPhraze = uniqid();
        openssl_pkey_export($privateKeyRes, $privKey, $passPhraze);
        $csr = openssl_csr_new([], $privateKeyRes, array('digest_alg' => 'sha256'));
        // Generate a self-signed cert, valid for 365 days
        $x509 = openssl_csr_sign($csr, null, $privateKeyRes, $days=365, array('digest_alg' => 'sha256'));
        openssl_x509_export($x509, $certificate);
        return [$certificate, $privKey, $passPhraze];
    }

    public static function reformatCertificateText($certText)
    {
        return str_replace(["-----BEGIN CERTIFICATE-----", "\n", "-----END CERTIFICATE-----"], "", $certText);
    }

}