<?php

namespace SPID_CIE_OIDC_PHP\Federation;

use SPID_CIE_OIDC_PHP\Core\JWT;

class EntityStatement
{
    public function __construct($config)
    {
        $this->config = $config;
    }


    public function getConfiguration($decoded = 'N')
    {
        $crt = $this->config->rp_cert_public;
        $crt_jwk = JWT::getCertificateJWK($crt);

        $payload = array(
            "iss" => $this->config->rp_client_id,
            "sub" => $this->config->rp_client_id,
            "iat" => strtotime("now"),
            "exp" => strtotime("+1 year"),
            "jwks" => array(
                "keys" => array( $crt_jwk )
            ),
            "authority_hints" => array(
                $this->config->rp_authority_hint
            ),
            "trust_marks" => array(),
            "metadata" => array(
                "openid_relying_party" => array(
                    "application_type" => "web",
                    "client_registration_types" => array( "automatic" ),
                    "client_name" => $this->config->rp_client_name,
                    "contacts" => array( $this->config->rp_contact ),
                    "grant_types" => array( "authorization_code" ),
                    "jwks" => array(
                        "keys" => array( $crt_jwk )
                    ),
                    "redirect_uris" => array( $this->config->rp_client_id . '/oidc/redirect' ),
                    "response_types" => array( "code" ),
                    "subject_type" => "pairwise"
                )
            )
        );

        $header = array(
            "typ" => "entity-statement+jwt",
            "alg" => "RS256",
            "kid" => $crt_jwk['kid']
        );

        $key = $this->config->rp_cert_private;
        $key_jwk = JWT::getKeyJWK($key);
        $jws = JWT::makeJWS($header, $payload, $key_jwk);

        return $decoded == 'Y' ? json_encode($payload) : $jws;
    }
}
