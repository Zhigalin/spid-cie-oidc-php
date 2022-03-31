<?php

/**
 * spid-cie-oidc-php
 * https://github.com/italia/spid-cie-oidc-php
 *
 * 2022 Michele D'Amico (damikael)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author     Michele D'Amico <michele.damico@linfaservice.it>
 * @license    http://www.apache.org/licenses/LICENSE-2.0  Apache License 2.0
 */

namespace SPID_CIE_OIDC_PHP\Setup;

use Composer\Script\Event;
use SPID_CIE_OIDC_PHP\Setup\Colors;
use Symfony\Component\Filesystem\Filesystem;

// readline replacement
if (!function_exists('readline')) {
    function readline()
    {
        $fp = fopen("php://stdin", "r");
        $line = rtrim(fgets($fp, 1024));
        return $line;
    }
}

/**
 *  Composer setup class for spid-cie-oidc-php
 *
 *  allows to set all the necessary configurations interactively
 */

class Setup
{
    /**
    *  main setup function called by "composer install" command
    */
    public static function setup(Event $event)
    {
        $filesystem = new Filesystem();
        $colors = new Colors();
        $version = $event->getComposer()->getConfig()->get("version");

        if ($colors->hasColorSupport()) {
            // Clear the screen
            echo "\e[H\e[J";
        }

        echo $colors->getColoredString("SPID CIE OIDC PHP SDK Setup\nversion " . $version . "\n\n", "green");

        // retrieve path and inputs
        $_home_dir = PHP_OS_FAMILY === "Windows" ? getenv("HOMEDRIVE") . getenv("HOMEPATH") : getenv("HOME");
        $_www_dir = "/var/www/html";
        $_install_dir = getcwd();
        $_service_name = "";

        $_rp_client_id = "https://localhost:8002";
        $_rp_client_name = "Name of Relying Party";
        $_rp_authority_hint = "http://localhost:8000/";
        $_rp_contact = "rp@example.it";

        $_rp_url = "https://www.organization.org";
        $_rp_country_name = "IT";
        $_rp_locality_name = "Rome";
        $_rp_code_type = "VATNumber";
        $_rp_code = "";
        $_rp_email = "info@organization.org"; // must be not null otherwise metadata will not generated
        $_rp_telephone = "+3912345678"; // must be not null otherwise metadata will not generated

        // billing
        $_rp_fpa_id_paese = "IT";
        $_rp_fpa_id_codice = "";
        $_rp_fpa_denominazione = "";
        $_rp_fpa_indirizzo = "";
        $_rp_fpa_numero_civico = "";
        $_rp_fpa_cap = "";
        $_rp_fpa_comune = "";
        $_rp_fpa_provincia = "";
        $_rp_fpa_nazione = "IT";
        $_rp_fpa_organization_name = "";
        $_rp_fpa_organization_email_address = "";
        $_rp_fpa_organization_telephone_number = "";

        $config = file_exists('config/rp-config.json') ?
        json_decode(file_get_contents('config/rp-config.json'), true) : array();

        $config['production'] = false;

        if (!isset($config['install_dir'])) {
            echo "Please insert path for current directory (" .
            $colors->getColoredString($_install_dir, "green") . "): ";
            $config['install_dir'] = readline();
            if ($config['install_dir'] == null || $config['install_dir'] == "") {
                $config['install_dir'] = $_install_dir;
            }
        }

        if (!isset($config['www_dir'])) {
            echo "Please insert path for web root directory (" .
            $colors->getColoredString($_www_dir, "green") . "): ";
            $config['www_dir'] = readline();
            if ($config['www_dir'] == null || $config['www_dir'] == "") {
                $config['www_dir'] = $_www_dir;
            }
        }

        if (!isset($config['service_name'])) {
            echo "Please insert name for service endpoint (" .
            $colors->getColoredString($_service_name, "green") . "): ";
            $config['service_name'] = str_replace("'", "\'", readline());
            if ($config['service_name'] == null || $config['service_name'] == "") {
                $config['service_name'] = $_service_name;
            }
        }

        if (!isset($config['rp_client_id'])) {
            echo "Please insert client_id (" .
            $colors->getColoredString($_rp_client_id, "green") . "): ";
            $config['rp_client_id'] = str_replace("'", "\'", readline());
            if ($config['rp_client_id'] == null || $config['rp_client_id'] == "") {
                $config['rp_client_id'] = $_rp_client_id;
            }
        }

        if (!isset($config['rp_client_name'])) {
            echo "Please insert client_name (" .
            $colors->getColoredString($_rp_client_name, "green") . "): ";
            $config['rp_client_name'] = str_replace("'", "\'", readline());
            if ($config['rp_client_name'] == null || $config['rp_client_name'] == "") {
                $config['rp_client_name'] = $_rp_client_name;
            }
        }

        if (!isset($config['rp_authority_hint'])) {
            echo "Please insert authority_hint (" .
            $colors->getColoredString($_rp_authority_hint, "green") . "): ";
            $config['rp_authority_hint'] = str_replace("'", "\'", readline());
            if ($config['rp_authority_hint'] == null || $config['rp_authority_hint'] == "") {
                $config['rp_authority_hint'] = $_rp_authority_hint;
            }
        }

        if (!isset($config['rp_contact'])) {
            echo "Please insert contact email (" .
            $colors->getColoredString($_rp_contact, "green") . "): ";
            $config['rp_contact'] = str_replace("'", "\'", readline());
            if ($config['rp_contact'] == null || $config['rp_contact'] == "") {
                $config['rp_contact'] = $_rp_contact;
            }
        }

        if (!isset($config['rp_is_pa'])) {
            echo "Is your Organization a Public Administration (" .
            $colors->getColoredString("Y", "green") . "): ";
            $config['rp_is_pa'] = readline();
            $config['rp_is_pa'] = ($config['rp_is_pa'] != null &&
                    strtoupper($config['rp_is_pa']) == "N") ? false : true;
        }


        switch ($config['rp_is_pa']) {
            case true:
                if (
                    !isset($config['rp_code_type'])
                    || !isset($config['rp_code'])
                    || $config['rp_code_type'] != 'IPACode'
                ) {
                    echo "Please insert your Organization's IPA Code (" .
                        $colors->getColoredString($_rp_code, "green") . "): ";
                    $config['rp_code'] = readline();
                    if ($config['rp_code'] == null || $config['rp_code'] == "") {
                        $config['rp_code'] = $_rp_code;
                    }
                    $config['rp_code_type'] = "IPACode";
                    $config['rp_organization_identifier'] = "PA:IT-" . $config['rp_code'];
                }
                break;

            case false:
                if (
                    !isset($config['rp_code_type'])
                    || !isset($config['rp_code'])
                    || (
                        $config['rp_code_type'] != 'VATNumber'
                        && $config['rp_code_type'] != 'FiscalCode'
                    )
                ) {
                    echo "Please insert 1 for VATNumber or 2 for FiscalCode (" .
                        $colors->getColoredString(($_rp_code_type == 'VATNumber') ? '1' : '2', "green") . "): ";
                    $_rp_code_typ_choice = readline();
                    if ($_rp_code_typ_choice == null || $_rp_code_typ_choice == "") {
                        $_rp_code_typ_choice = '1';
                    }
                    if ($_rp_code_typ_choice != '1' && $_rp_code_typ_choice != '2') {
                        echo "Your Organization Code type is not correctly set. It must be 1 (VATNumber) or 2 (FiscalCode). Please retry installation.\n";
                        die();
                    }
                    $config['rp_code_type'] = $_rp_code_typ_choice == 1 ? 'VATNumber' : 'FiscalCode';
                    echo "Please insert your Organization's " . $config['rp_code_type'] . " (" .
                        $colors->getColoredString($_rp_code, "green") . "): ";
                    $config['rp_code'] = readline();
                    if ($config['rp_code'] == null || $config['rp_code'] == "") {
                        $config['rp_code'] = $_rp_code;
                    }
                    $config['rp_organization_identifier'] = ($_rp_code_typ_choice == 1 ? "VATIT-" : "CF:IT-") . $config['rp_code'];
                    $_rp_fpa_id_codice = $config['rp_code'];
                }

                if (!isset($config['rp_fpa_id_paese'])) {
                    echo "Please insert your IdPaese for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_id_paese, "green") . "): ";
                    $config['rp_fpa_id_paese'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_id_paese'] == null || $config['rp_fpa_id_paese'] == "") {
                        $config['rp_fpa_id_paese'] = $_rp_fpa_id_paese;
                    }
                }

                if (!isset($config['rp_fpa_id_codice'])) {
                    echo "Please insert your IdCodice for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_id_codice, "green") . "): ";
                    $config['rp_fpa_id_codice'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_id_codice'] == null || $config['rp_fpa_id_codice'] == "") {
                        $config['rp_fpa_id_codice'] = $_rp_fpa_id_codice;
                    }
                }

                if (!isset($config['rp_fpa_denominazione'])) {
                    echo "Please insert your Denominazione for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_denominazione, "green") . "): ";
                    $config['rp_fpa_denominazione'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_denominazione'] == null || $config['rp_fpa_denominazione'] == "") {
                        $config['rp_fpa_denominazione'] = $_rp_fpa_denominazione;
                    }
                }

                if (!isset($config['rp_fpa_indirizzo'])) {
                    echo "Please insert your Indirizzo for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_indirizzo, "green") . "): ";
                    $config['rp_fpa_indirizzo'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_indirizzo'] == null || $config['rp_fpa_indirizzo'] == "") {
                        $config['rp_fpa_indirizzo'] = $_rp_fpa_indirizzo;
                    }
                }

                if (!isset($config['rp_fpa_numero_civico'])) {
                    echo "Please insert your NumeroCivico for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_numero_civico, "green") . "): ";
                    $config['rp_fpa_numero_civico'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_numero_civico'] == null || $config['rp_fpa_numero_civico'] == "") {
                        $config['rp_fpa_numero_civico'] = $_rp_fpa_numero_civico;
                    }
                }

                if (!isset($config['rp_fpa_cap'])) {
                    echo "Please insert your CAP for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_cap, "green") . "): ";
                    $config['rp_fpa_cap'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_cap'] == null || $config['rp_fpa_cap'] == "") {
                        $config['rp_fpa_cap'] = $_rp_fpa_cap;
                    }
                }

                if (!isset($config['rp_fpa_comune'])) {
                    echo "Please insert your Comune for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_comune, "green") . "): ";
                    $config['rp_fpa_comune'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_comune'] == null || $config['rp_fpa_comune'] == "") {
                        $config['rp_fpa_comune'] = $_rp_fpa_comune;
                    }
                }

                if (!isset($config['rp_fpa_provincia'])) {
                    echo "Please insert your Provincia for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_provincia, "green") . "): ";
                    $config['rp_fpa_provincia'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_provincia'] == null || $config['rp_fpa_provincia'] == "") {
                        $config['rp_fpa_provincia'] = $_rp_fpa_provincia;
                    }
                }

                if (!isset($config['rp_fpa_nazione'])) {
                    echo "Please insert your Nazione for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_nazione, "green") . "): ";
                    $config['rp_fpa_nazione'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_nazione'] == null || $config['rp_fpa_nazione'] == "") {
                        $config['rp_fpa_nazione'] = $_rp_fpa_nazione;
                    }
                }

                if (!isset($config['rp_fpa_organization_name'])) {
                    echo "Please insert your OrganizationName for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_organization_name, "green") . "): ";
                    $config['rp_fpa_organization_name'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_organization_name'] == null || $config['rp_fpa_organization_name'] == "") {
                        $config['rp_fpa_organization_name'] = $_rp_fpa_organization_name;
                    }
                }

                if (!isset($config['rp_fpa_organization_email_address'])) {
                    echo "Please insert your OrganizationEmailAddress for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_organization_email_address, "green") . "): ";
                    $config['rp_fpa_organization_email_address'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_organization_email_address'] == null || $config['rp_fpa_organization_email_address'] == "") {
                        $config['rp_fpa_organization_email_address'] = $_rp_fpa_organization_email_address;
                    }
                }

                if (!isset($config['rp_fpa_organization_telephone_number'])) {
                    echo "Please insert your OrganizationTelephoneNumber for CessionarioCommittente (" .
                    $colors->getColoredString($_rp_fpa_organization_telephone_number, "green") . "): ";
                    $config['rp_fpa_organization_telephone_number'] = str_replace("'", "\'", readline());
                    if ($config['rp_fpa_organization_telephone_number'] == null || $config['rp_fpa_organization_telephone_number'] == "") {
                        $config['rp_fpa_organization_telephone_number'] = $_rp_fpa_organization_telephone_number;
                    }
                }

                break;

            default:
                echo "Your Organization type is not correctly set. Please retry installation. Found: " . $config['rp_is_pa'] . "\n";
                die();
                break;
        }

        if (!isset($config['rp_country_name'])) {
            echo "Please insert your Organization's Country ISO 3166-1 code (" .
            $colors->getColoredString($_rp_country_name, "green") . "): ";
            $config['rp_country_name'] = readline();
            if ($config['rp_country_name'] == null || $config['rp_country_name'] == "") {
                $config['rp_country_name'] = $_rp_country_name;
            }
        }

        if (!isset($config['rp_locality_name'])) {
            echo "Please insert your Organization's Locality Name (" .
            $colors->getColoredString($_rp_locality_name, "green") . "): ";
            $config['rp_locality_name'] = readline();
            if ($config['rp_locality_name'] == null || $config['rp_locality_name'] == "") {
                $config['rp_locality_name'] = $_rp_locality_name;
            }
        }

        if (!isset($config['rp_email'])) {
            echo "Please insert Organization Contact Email Address (" .
              $colors->getColoredString($_rp_email, "green") . "): ";
            $config['rp_email'] = str_replace("'", "\'", readline());
            if ($config['rp_email'] == null || $config['rp_email'] == "") {
                $config['rp_email'] = $_rp_email;
            }
        }

        if (!isset($config['rp_telephone'])) {
            echo "Please insert Organization Contact Telephone Number (" .
              $colors->getColoredString($_rp_telephone, "green") . "): ";
            $config['rp_telephone'] = str_replace("'", "\'", readline());
            if ($config['rp_telephone'] == null || $config['rp_telephone'] == "") {
                $config['rp_telephone'] = $_rp_telephone;
            }
        }




        echo $colors->getColoredString("\nCurrent directory: " . $config['install_dir'], "yellow");
        echo $colors->getColoredString("\nWeb root directory: " . $config['www_dir'], "yellow");
        echo $colors->getColoredString("\nService Name: " . $config['service_name'], "yellow");
        echo $colors->getColoredString("\nclient_id: " . $config['rp_client_id'], "yellow");
        echo $colors->getColoredString("\nclient_name: " . $config['rp_client_name'], "yellow");
        echo $colors->getColoredString("\nauthority_hint: " . $config['rp_authority_hint'], "yellow");
        echo $colors->getColoredString("\ncontact: " . $config['rp_contact'], "yellow");
        echo $colors->getColoredString("\nIs organization a Public Administration: ", "yellow");
        echo $colors->getColoredString(($config['rp_is_pa']) ? "Y" : "N", "yellow");
        echo $colors->getColoredString("\nOrganization Code Type: " . $config['rp_code_type'], "yellow");
        echo $colors->getColoredString("\nOrganization Code: " . $config['rp_code'], "yellow");
        echo $colors->getColoredString("\nOrganization Identifier: " . $config['rp_organization_identifier'], "yellow");
        echo $colors->getColoredString("\nCertificate CountryName: " . $config['rp_country_name'], "yellow");
        echo $colors->getColoredString("\nCertificate LocalityName: " . $config['rp_locality_name'], "yellow");
        echo $colors->getColoredString("\nOrganization Contact Email Address: " . $config['rp_email'], "yellow");
        echo $colors->getColoredString("\nOrganization Contact Telephone Number: " . $config['rp_telephone'], "yellow");
        if (!$config['rp_is_pa']) {
            echo $colors->getColoredString("\nCessionarioCommittente IdPaese: " . $config['rp_fpa_id_paese'], "yellow");
            echo $colors->getColoredString("\nCessionarioCommittente IdCodice: " . $config['rp_fpa_id_codice'], "yellow");
            echo $colors->getColoredString("\nCessionarioCommittente Denominazione: " . $config['rp_fpa_denominazione'], "yellow");
            echo $colors->getColoredString("\nCessionarioCommittente Indirizzo: " . $config['rp_fpa_indirizzo'], "yellow");
            echo $colors->getColoredString("\nCessionarioCommittente NumeroCivico: " . $config['rp_fpa_numero_civico'], "yellow");
            echo $colors->getColoredString("\nCessionarioCommittente CAP: " . $config['rp_fpa_cap'], "yellow");
            echo $colors->getColoredString("\nCessionarioCommittente Comune: " . $config['rp_fpa_comune'], "yellow");
            echo $colors->getColoredString("\nCessionarioCommittente Provincia: " . $config['rp_fpa_provincia'], "yellow");
            echo $colors->getColoredString("\nCessionarioCommittente Nazione: " . $config['rp_fpa_nazione'], "yellow");
            echo $colors->getColoredString("\nCessionarioCommittente OrganizationName: " . $config['rp_fpa_organization_name'], "yellow");
            echo $colors->getColoredString("\nCessionarioCommittente OrganizationEmailAddress: " . $config['rp_fpa_organization_email_address'], "yellow");
            echo $colors->getColoredString("\nCessionarioCommittente OrganizationTelephoneNumber: " . $config['rp_fpa_organization_telephone_number'], "yellow");
        }


        echo $colors->getColoredString("\nProduction: " . $config['production'], "yellow");

        echo "\n\n";

        if (!file_exists('config')) {
            echo $colors->getColoredString("\nConfig directory not found. Making directory ./config", "yellow");
            $filesystem->mkdir('config');
        }

        // create vhost directory if not exists
        if (!file_exists($config['www_dir'] && $config['service_name']!='')) {
            echo $colors->getColoredString("\nWebroot directory not found. Making directory " .
                    $config['www_dir'], "yellow");
            echo $colors->getColoredString("\nPlease remember to configure your virtual host.\n\n", "yellow");
            $filesystem->mkdir($config['www_dir']);
        }

        // create certificates
        if (file_exists($config['install_dir'] . "/cert/rp.crt") && file_exists($config['install_dir'] . "/cert/rp.pem")) {
            echo $colors->getColoredString("\nSkipping certificates generation", "white");
        } else {
            $filesystem->mkdir(
                $config['install_dir'] . "/cert"
            );
            echo $colors->getColoredString("\nConfiguring OpenSSL... ", "white");
            if (!file_exists("config/openssl.cnf")) {
                $openssl_config = fopen("config/openssl.cnf", "w");
                fwrite($openssl_config, "oid_section = spid_oids\n");

                fwrite($openssl_config, "\n[ req ]\n");
                fwrite($openssl_config, "default_bits = 3072\n");
                fwrite($openssl_config, "default_md = sha256\n");
                fwrite($openssl_config, "distinguished_name = dn\n");
                fwrite($openssl_config, "encrypt_key = no\n");
                fwrite($openssl_config, "prompt = no\n");
                fwrite($openssl_config, "req_extensions  = req_ext\n");

                fwrite($openssl_config, "\n[ spid_oids ]\n");
                //fwrite($openssl_config, "organizationIdentifier=2.5.4.97\n");
                fwrite($openssl_config, "spid-privatesector-SP=1.3.76.16.4.3.1\n");
                fwrite($openssl_config, "spid-publicsector-SP=1.3.76.16.4.2.1\n");
                fwrite($openssl_config, "uri=2.5.4.83\n");

                fwrite($openssl_config, "\n[ dn ]\n");
                fwrite($openssl_config, "organizationName=" . $config['rp_client_name'] . "\n");
                fwrite($openssl_config, "commonName=" . $config['rp_client_name'] . "\n");
                fwrite($openssl_config, "uri=" . $config['rp_client_id'] . "\n");
                fwrite($openssl_config, "organizationIdentifier=" . $config['rp_organization_identifier'] . "\n");
                fwrite($openssl_config, "countryName=" . $config['rp_country_name'] . "\n");
                fwrite($openssl_config, "localityName=" . $config['rp_locality_name'] . "\n");
                //fwrite($openssl_config, "serialNumber=" . $config['rp_code'] . "\n");

                fwrite($openssl_config, "\n[ req_ext ]\n");
                fwrite($openssl_config, "certificatePolicies = @spid_policies\n");

                fwrite($openssl_config, "\n[ spid_policies ]\n");
                switch ($config['rp_is_pa']) {
                    case true:
                        fwrite($openssl_config, "policyIdentifier = spid-publicsector-SP\n");
                        break;
                    case false:
                        fwrite($openssl_config, "policyIdentifier = spid-privatesector-SP\n");
                        break;

                    default:
                        echo $colors->getColoredString("Your Organization type is not correctly set. Please retry installation. Found: " . $config['rp_is_pa'] . "\n", "red");
                        fwrite($openssl_config, "ERROR- Interrupted\n");
                        fclose($openssl_config);
                        die();
                        break;
                }
                echo $colors->getColoredString("OK\n", "green");
            }

            shell_exec(
                "openssl req -new -x509 -config " . "config/openssl.cnf -days 730 " .
                    " -keyout " . $config['install_dir'] . "/cert/rp.pem" .
                    " -out " . $config['install_dir'] . "/cert/rp.crt" .
                    " -extensions req_ext "
            );

            $config['rp_cert_private'] = $config['install_dir'] . "/cert/rp.pem";
            $config['rp_cert_public'] = $config['install_dir'] . "/cert/rp.crt";
        }

        file_put_contents($config['install_dir'] . "/config/rp-config.json", json_encode($config));

        // set link to www
        $cmd_link = $config['www_dir'] . "/" . $config['service_name'];
        if (!file_exists($cmd_link)) {
            echo $colors->getColoredString("\nCreate symlink... ", "white");
            $cmd_target = $config['install_dir'] . "/www";
            symlink($cmd_target, $cmd_link);
            echo $colors->getColoredString("OK", "green");
        } else {
            echo $colors->getColoredString("\nSymlink already exists, please check manually", "white");
        }

        // copy spid button assets
        echo $colors->getColoredString("\nCopy spid button assets... ", "white");
        $path = $config['install_dir'] . "/www/assets/spid-sp-access-button/";

        foreach (["/css", "/img", "/js"] as $value) {
            $dest = $path . $value;
            $filesystem->mkdir($dest);
            $filesystem->mirror(
                $config['install_dir'] . "/vendor/italia/spid-sp-access-button/src/production" . $value,
                $dest
            );
        }

        echo $colors->getColoredString("OK", "green");

        // reset permissions
        echo $colors->getColoredString("\nSetting directories and files permissions... ", "white");

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(
                $config['install_dir'],
                \RecursiveDirectoryIterator::SKIP_DOTS
            ),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isLink()) {
                continue;
            }

            if ($item->isDir()) {
                $filesystem->chmod($item, 0755);
            } else {
                $filesystem->chmod($item, 0644);
            }
        }

        $filesystem->chmod($config['install_dir'], 0755);


        echo $colors->getColoredString("\n\nSPID CIE OIDC PHP SDK successfully installed! Enjoy the OIDC identities\n\n", "green");
    }

    /**
    *  uninstall function called by "composer uninstall" command
    */
    public static function remove()
    {
        $filesystem = new Filesystem();
        $colors = new Colors();
        $config = file_exists('config/rp-config.json') ?
                json_decode(file_get_contents('config/rp-config.json'), true) : array();

        // retrieve path and inputs
        $_install_dir = getcwd();
        $_home_dir = PHP_OS_FAMILY === "Windows"
          ? getenv("HOMEDRIVE") . getenv("HOMEPATH")
          : getenv("HOME");
        $_www_dir = $_home_dir . "/public_html";
        $_service_name = "oidc";

        if (!empty($config['install_dir'])) {
            $install_dir = $config['install_dir'];
        } else {
            echo "Please insert root path where sdk is installed (" .
            $colors->getColoredString($_install_dir, "green") . "): ";
            $install_dir = readline();
            if ($install_dir == null || $install_dir == "") {
                $install_dir = $_install_dir;
            }
        }

        if (!empty($config['www_dir'])) {
            $www_dir = $config['www_dir'];
        } else {
            echo "Please insert path for www (" .
            $colors->getColoredString($_www_dir, "green") . "): ";
            $www_dir = readline();
            if ($www_dir == null || $www_dir == "") {
                $www_dir = $_www_dir;
            }
        }

        if (!empty($config['service_name'])) {
            $service_name = $config['service_name'];
        } else {
            echo "Please insert name for service endpoint (" .
            $colors->getColoredString($_service_name, "green") . "): ";
            $service_name = readline();
            if ($service_name == null || $service_name == "") {
                $service_name = $_service_name;
            }
        }

        echo $colors->getColoredString("\nRemove service symlink [" .
        $www_dir . "/" . $service_name . "]... ", "white");
        $filesystem->remove($www_dir . "/" . $service_name);
        echo $colors->getColoredString("OK", "green");

        echo $colors->getColoredString("\nRemove spid-sp-access-button assets... ", "white");
        $filesystem->remove($install_dir . "/www/assets/spid-sp-access-button");
        echo $colors->getColoredString("OK", "green");

        echo $colors->getColoredString("\nRemove vendor directory... ", "white");
        $filesystem->remove($install_dir . "/vendor");
        echo $colors->getColoredString("OK", "green");

        echo $colors->getColoredString("\nRemove composer lock file... ", "white");
        $filesystem->remove($install_dir . "/composer.lock");
        echo $colors->getColoredString("OK", "green");

        //echo $colors->getColoredString("\nRemove cert directory [" . $install_dir . "/cert]... ", "white");
        //shell_exec("rm -Rf " . $install_dir . "/cert");
        //echo $colors->getColoredString("OK", "green");

        echo $colors->getColoredString("\n\nSPID CIE OIDC PHP successfully removed\n\n", "green");
    }
}
