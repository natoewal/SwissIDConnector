<?php
/**
 * File containing SwissIDConnector class
 *
 * @package SwissIDConnector
 * @version 0.9
 * @author Sean Natoewal <sean@natoewal.nl>
 * @copyright Copyright (c) Sean Natoewal <sean@natoewal.nl>
 * @license https://opensource.org/licenses/MIT
 * @link https://github.com/natoewal/SwissIDConnector
 */

namespace Natoewal\SwissID;

use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use \Exception;

/**
 * SwissIDConnector class
 *
 * Class to interact with the SwissID IdP
 *
 * @package SwissIDConnector
 * @version 0.9
 * @author Sean Natoewal <sean@natoewal.nl>
 * @copyright Copyright (c) Sean Natoewal <sean@natoewal.nl>
 * @license https://opensource.org/licenses/MIT
 * @link https://github.com/natoewal/SwissIDConnector
 */
class SwissIDConnector {

    /**
     * The RP's client_id
     *
     * @var string
     */
    private string $clientID;

    /**
     * The RP's client_secret
     *
     * @var string
     */
    private string $clientSecret;

    /**
     * The RP's redirect URI registered with SwissID
     *
     * @var string|null
     */
    private ?string $redirectURI;

    /**
     * The environment for which this object was initialized
     *
     * @var string
     */
    private string $environment;

    /**
     * SwissID's OpenID configuration endpoints
     *
     * @var array
     */
    private array $openidConfigurationEndpoints;

    /**
     * SwissID's OpenID configuration
     *
     * @var array
     */
    private array $openidConfiguration;

    /**
     * SwissID's step-up URIs
     *
     * @var array
     */
    private array $stepUpURIs;

    /**
     * SwissID's JSON Web Key Set
     *
     * @var array
     */
    private array $keys;

    /**
     * The scope, requested at the time of authentication
     *
     * @var string
     */
    private string $scope;

    /**
     * The claims, requested at the time of authentication
     *
     * @var string
     */
    private string $claims;

    /**
     * The Quality of Authentication (QoA), requested at the time of authentication
     *
     * @var string
     */
    private string $qoa;

    /**
     * The Quality of Registration (QoR), requested at the time of authentication
     *
     * @var string
     */
    private string $qor;

    /**
     * The language of the end-user interface, requested at the time of authentication
     *
     * @var string
     */
    private string $locale;

    /**
     * The login hint, requested at the time of authentication
     *
     * @var string
     */
    private string $loginHint;

    /**
     * Whether and for what the IdP should prompt the end-user, requested at the time of authentication
     *
     * @var string
     */
    private string $prompt;

    /**
     * The allowable elapsed time in seconds since the last time the end-user was actively authenticated by SwissID, requested at the time of authentication
     *
     * @var int
     */
    private int $maxAge;

    /**
     * Indicator on whether this object was initialized
     *
     * @var bool
     */
    private bool $connectorInitialized;

    /**
     * Indicator on whether the OIDC configuration was loaded
     *
     * @var bool
     */
    private bool $oidcConfigurationLoaded;

    /**
     * Indicator on whether the authentication was initialized
     *
     * @var bool
     */
    private bool $authenticationInitialized;

    /**
     * Indicator on whether the authorization code was exchanged
     *
     * @var array
     */
    private array $authorizationCodeExchanged;

    /**
     * Indicator on whether the step-up was initialized
     *
     * @var array
     */
    private array $stepUpInitialized;

    /**
     * Authorization code
     *
     * @var string
     */
    private string $authorizationCode;

    /**
     * Access token
     *
     * @var string
     */
    private string $accessToken;

    /**
     * Expiration timestamp of access token
     *
     * @var int
     */
    private int $accessTokenExpirationTimestamp;

    /**
     * Refresh token
     *
     * @var string
     */
    private string $refreshToken;

    /**
     * Expiration timestamp of refresh token
     *
     * @var int
     */
    private int $refreshTokenExpirationTimestamp;

    /**
     * Identity token
     *
     * @var stdClass
     */
    private \stdClass $idToken;

    /**
     * Endpoint from which the identity token was obtained
     *
     * @var string
     */
    private string $idTokenEndpoint;

    /**
     * State used for the authentication or step-up request
     *
     * @var string
     */
    private string $state;

    /**
     * Nonce used for the authentication or step-up request
     *
     * @var string
     */
    private string $nonce;

    /**
     * Error
     *
     * @var array
     */
    private array $error;

    /**
     * Leeway in seconds for when checking a token's nbf, iat or expiration time
     *
     * @var int
     */
    private int $leeway;

    /**
     * Constructor
     *
     * After instantiating this object, make sure to check if any error have occurred
     *
     * - If a brand new instance needs to be created, all parameters must be specified
     * - If an existing instance needs to be restored from persistent storage, the first three parameters must be specified
     *
     * @param string $clientID The RP's client_id
     * @param string $clientSecret The RP's client secret
     * @param string $environment The environment for which to instantiate this object. Valid values are 'PRE-PROD', 'PROD'
     * @param string $redirectURI The RP's redirect URI registered with SwissID
     * @throws Exception In case an error occurred
     * @see SwissIDConnector::hasError()
     */
    public function __construct(string $clientID, string $clientSecret, string $environment, string $redirectURI = null) {

        /**
         * Verify parameters
         */
        $parameters = array(
            'environment' => $environment
        );
        $this->verifyParameters($parameters);

        /**
         * Determine whether the required parameters have been set for the different scenarios
         */
        $requiredParameters4RestoreSession = (isset($_SESSION[\get_class($this)]));
        $requiredParameters4Initialization = (!isset($_SESSION[\get_class($this)]) && !\is_null($clientID) && !\is_null($clientSecret) && !\is_null($environment) && !\is_null($redirectURI));
        $requiredParameters4RestorePersistent = (!\is_null($clientID) && !\is_null($clientSecret) && !\is_null($environment) && \is_null($redirectURI));

        if (!$requiredParameters4RestoreSession && !$requiredParameters4Initialization && !$requiredParameters4RestorePersistent) {
            /**
             * If an invalid number of parameters have been specified,
             * throw an exception
             */
            $this->throwException(__LINE__, 'An invalid number of parameters have been specified');
        }

        /**
         * Set redirect URI, if specified
         */
        if (!is_null($redirectURI)) {
            $this->redirectURI = $redirectURI;
        }

        /**
         * Initialize class member variables
         */
        $this->initializeClassMemberVars();

        if ($requiredParameters4RestoreSession) {
            /**
             * If an an existing instance needs to be restored from the session,
             * reconstruct class member variables from the session
             */
            foreach ($_SESSION[\get_class($this)] as $key => $val) {
                $this->$key = $val;
            }
        }

        /**
         * Load OIDC Configuration
         */
        $this->loadOIDCConfig($clientID, $clientSecret, $environment);

        return;
    }

    /**
     * Method to initialize the class member variables to their default state
     *
     * @return void
     */
    private function initializeClassMemberVars(): void {
        /**
         * Return if there is nothing to do
         */
        if (isset($this->connectorInitialized) && $this->connectorInitialized) {
            return;
        }

        /**
         * Set class member variables to their default state
         */
        $this->openidConfigurationEndpoints = array(
            'PRE-PROD' => 'https://login.sandbox.pre.swissid.ch/idp/oauth2/.well-known/openid-configuration',
            'PROD' => 'https://login.swissid.ch/idp/oauth2/.well-known/openid-configuration'
        );
        $this->stepUpURIs = array(
            'LOT1' => array(
                'PRE-PROD' => 'https://login.sandbox.pre.swissid.ch/idcheck/rp/stepup/lot1',
                'PROD' => 'https://account.swissid.ch/idcheck/rp/stepup/lot1'
            )
        );
        $this->connectorInitialized = true;
        $this->oidcConfigurationLoaded = false;
        $this->authenticationInitialized = false;
        $this->authorizationCodeExchanged = array(
            'AUTH' => array(
                'ANY' => false
            ),
            'STEP_UP' => array(
                'LOT1' => false
            )
        );
        $this->stepUpInitialized = array(
            'LOT1' => false
        );
        $this->state = \bin2hex(\random_bytes(16));
        $this->leeway = 0;
        
        return;
    }

    /**
     * Method to load SwissID's OpenID configuration
     *
     * @param string $clientID The RP's client_id
     * @param string $clientSecret The RP's client secret
     * @param string $environment The environment for which to instantiate this object. Valid values are 'PRE-PROD', 'PROD'
     * @return void
     * @throws Exception In case an error occurred
     */
    private function loadOIDCConfig(string $clientID = null, string $clientSecret = null, string $environment = null): void {

        /**
         * Return if there is nothing to do
         */
        if ($this->oidcConfigurationLoaded) {
            return;
        }

        /**
         * Try to read SwissID's OpenID configuration
         */
        if (!$openidConfigurationEncoded = @\file_get_contents($this->openidConfigurationEndpoints[$environment])) {
            /**
             * If SwissID's OpenID configuration could not be read,
             * throw an exception
             */
            $this->throwException(__LINE__, 'An error has occurred while trying to read the openid configuration');
        } elseif (!$openidConfigurationDecoded = \json_decode($openidConfigurationEncoded, $associativeP = true)) {
            /**
             * If an error has occurred while trying to decode the JSON response,
             * throw an exception
             */
            $this->throwException(__LINE__, \json_last_error() . ': ' . \json_last_error_msg());
        } else {
            /**
             * On success, update the class member variables
             */
            $this->clientID = $clientID;
            $this->clientSecret = $clientSecret;
            $this->environment = $environment;
            $this->openidConfiguration = $openidConfigurationDecoded;

            /**
             * Try to read SwissID's JSON Web Key Set
             */
            if (!$keysEncoded = @\file_get_contents($this->openidConfiguration['jwks_uri'])) {
                /**
                 * If SwissID's JSON Web Key Set could not be read,
                 * throw an exception
                 */
                $this->throwException(__LINE__, 'An error has occurred while trying to read the keys');
            } elseif (!$keysDecoded = \json_decode($keysEncoded, $associativeP = true)) {
                /**
                 * If an error has occurred while trying to decode the JSON response,
                 * throw an exception
                 */
                $this->throwException(__LINE__, \json_last_error() . ': ' . \json_last_error_msg());
            } else {
                /**
                 * On success, update the class member variables
                 */
                $this->keys = $keysDecoded;
                $this->oidcConfigurationLoaded = true;
                
                return;
            }
        }
    }

    /**
     * Method to verify the state parameter returned
     *
     * @return void
     * @throws Exception In case an error occurred
     */
    private function verifyStateParameter(): void {
        if (!\filter_has_var(INPUT_GET, 'state')) {
            /**
             * If no state parameter was returned,
             * throw an exception
             */
            $this->throwException(__LINE__, 'No state parameter was returned');
        }
        elseif (\filter_input(INPUT_GET, 'state') != $this->state) {
            $this->throwException(__LINE__, 'The state parameter returned '.\filter_input(INPUT_GET, 'state').' does not match with the one sent '.$this->state);
        }

        return;
    }

    /**
     * Method to exchange the authorization code after a callback
     *
     * @param string $exchangeContext The context in which an authorization code needs to be exchanged. Valid values are 'AUTH' and 'STEP_UP'
     * @param string $scenario The scenario for which an authorization code needs to be exchanged.
     * @return void
     * @throws Exception In case an error occurred
     */
    private function exchangeAuthorizationCode(string $exchangeContext, string $scenario): void {

        if (!$this->authorizationCodeExchanged[$exchangeContext][$scenario]) {
            if (\filter_has_var(INPUT_GET, 'error') && \filter_has_var(INPUT_GET, 'error_description')) {
                /**
                 * If an error occurred while trying to complete the authentication,
                 * set the error and return
                 */
                $this->error = array(
                    'line' => __LINE__,
                    'error' => \filter_input(INPUT_GET, 'error'),
                    'errorDescription' => \filter_input(INPUT_GET, 'error_description')
                );
                return;
            } elseif (\filter_has_var(INPUT_GET, 'code')) {
                /**
                 * If an authorization code was obtained,
                 * try to redeem it at the token endpoint
                 */
                $this->authorizationCode = \filter_input(INPUT_GET, 'code');

                $params = array(
                    'grant_type' => 'authorization_code',
                    'code' => $this->authorizationCode,
                    'redirect_uri' => $this->redirectURI
                );

                $hasCURLError = false;
                if (!$ch = \curl_init()) {
                    $hasCURLError = true;
                }
                $cOpt1 = \curl_setopt($ch, CURLOPT_HEADER, 0);
                $cOpt2 = \curl_setopt($ch, CURLOPT_USERPWD, $this->clientID . ':' . $this->clientSecret);
                $cOpt3 = \curl_setopt($ch, CURLOPT_URL, $this->openidConfiguration['token_endpoint']);
                $cOpt4 = \curl_setopt($ch, CURLOPT_POST, 1);
                $cOpt5 = \curl_setopt($ch, CURLOPT_POSTFIELDS, \http_build_query($params));
                $cOpt6 = \curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                if (!$rs = \curl_exec($ch)) {
                    $hasCURLError = true;
                }
                $httpStatus = (int) \curl_getinfo($ch, CURLINFO_HTTP_CODE);
                \curl_close($ch);
                if ($hasCURLError || !$cOpt1 || !$cOpt2 || !$cOpt3 || !$cOpt4 || !$cOpt5 || !$cOpt6) {
                    /**
                     * If something went wrong with CURL
                     * throw an exception
                     */
                    $this->throwException(__LINE__, 'Could not initialize the connection to exchange the authorization code');
                } elseif (!$rs2 = \json_decode($rs, $associativeP = true)) {
                    /**
                     * If an error has occurred while trying to decode the JSON response,
                     * throw an exception
                     */
                    $this->throwException(__LINE__, \json_last_error() . ': ' . \json_last_error_msg());
                } elseif ($httpStatus !== 200) {
                    /**
                     * If the HTTP status was different from 200,
                     * throw an exception
                     */
                    $this->throwException(__LINE__, 'Unexpected HTTP status ' . $httpStatus);
                } elseif ($rs2['nonce'] !== $this->nonce) {
                    /**
                     * If the nonce sent
                     * does match with the value of the nonce returned
                     * throw an exception
                     */
                    $this->throwException(__LINE__, 'The nonce sent ' . $this->nonce . ' does not match with the value of the nonce ' . $rs2['nonce'] . ' returned');
                }

                /**
                 * Store the access and refresh token
                 */
                $this->accessToken = $rs2['access_token'];
                $this->accessTokenExpirationTimestamp = \time() + (int) $rs2['expires_in'];
                $this->refreshToken = $rs2['refresh_token'];
                $this->refreshTokenExpirationTimestamp = \strtotime('+6 months', \time());

                /**
                 * Verify and set the ID token
                 */
                $this->verifyAndSetIDToken($rs2['id_token'], 'TOKEN', $this->accessToken);

                /**
                 * Mark the authentication as being completed
                 */
                $this->authorizationCodeExchanged[$exchangeContext][$scenario] = true;

                /**
                 * Store state of this object in the session
                 */
                $_SESSION[\get_class($this)] = \get_object_vars($this);

                return;
            } elseif (!\filter_has_var(INPUT_GET, 'code')) {
                /**
                 * If no authorization code was obtained,
                 * throw an exception
                 */
                $this->throwException(__LINE__, 'No authorization code could be obtained');
            }
        } else {
            /**
             * Return if there is nothing to do
             */
            return;
        }
    }

    /**
     * Method to get an ID token from the user info endpoint
     *
     * @return void
     * @throws Exception In case an error occurred
     */
    private function getIDTokenFromUserInfoEndpoint(): void {

        $refreshAccessToken = false;
        if (!isset($this->accessToken) && !isset($this->refreshToken)) {
            /**
             * If there is no access token or refresh token,
             * throw an exception
             */
            $this->throwException(__LINE__, 'There is no access token or refresh token available');
        } elseif (isset($this->accessToken)) {
            /**
             * If an access token is available,
             * determine if the access token has expired
             */
            $accessTokenExpired = (\time() > $this->accessTokenExpirationTimestamp);

            if ($accessTokenExpired) {
                if (!isset($this->refreshToken)) {
                    /**
                     * If the access token has expired
                     * and no refresh token is available
                     * throw an exception
                     */
                    $this->throwException(__LINE__, 'The access token has expired and no refresh token is available');
                }
                $refreshAccessToken = true;
            }
        } elseif (!isset($this->accessToken)) {
            /**
             * If no access token is available,
             * determine if the refresh token has expired
             */
            $refreshTokenExpired = (\time() > $this->refreshTokenExpirationTimestamp);

            if ($refreshTokenExpired) {
                /**
                 * If the refresh token has expired
                 * throw an exception
                 */
                $this->throwException(__LINE__, 'The refresh token has expired');
            }

            $refreshAccessToken = true;
        }

        /**
         * Try to obtain a new access token using the refresh token, if needed
         */
        if ($refreshAccessToken) {
            $this->refreshAccessToken();
        }

        /**
         * Use the access token to get the end-user info from the user info endpoint
         */
        $hasCURLError = false;
        if (!$ch = \curl_init()) {
            $hasCURLError = true;
        }
        $cOpt1 = \curl_setopt($ch, CURLOPT_HEADER, 0);
        $cOpt2 = \curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'Authorization: Bearer ' . $this->accessToken));
        $cOpt3 = \curl_setopt($ch, CURLOPT_URL, $this->openidConfiguration['userinfo_endpoint']);
        $cOpt4 = \curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if (!$jwt = \curl_exec($ch)) {
            $hasCURLError = true;
        }
        $httpStatus = (int) \curl_getinfo($ch, CURLINFO_HTTP_CODE);
        \curl_close($ch);
        if ($hasCURLError || !$cOpt1 || !$cOpt2 || !$cOpt3 || !$cOpt4) {
            /**
             * If something went wrong with CURL
             * throw an exception
             */
            $this->throwException(__LINE__, 'Could not initialize the connection get the end-user info');
        } elseif ($httpStatus === 401) {
            /**
             * If the HTTP status equals 401,
             * throw an exception
             */
            $this->throwException(__LINE__, 'The access token provided is expired, revoked, malformed, or invalid for other reasons');
        } elseif ($httpStatus !== 200) {
            /**
             * If the HTTP status was different from 200,
             * throw an exception
             */
            $this->throwException(__LINE__, 'Unexpected HTTP status ' . $httpStatus);
        }

        /**
         * Verify and set the ID token
         */
        $this->verifyAndSetIDToken($jwt, 'USERINFO');

        return;
    }

    /**
     * Method to verify an ID token
     *
     * @param string $idToken The JWT identity token to verify
     * @param string $endpoint The endpoint from where the token to verify was obtained. Valid values are 'TOKEN' and 'USERINFO'
     * @param string $accessToken The access token that was provided together with the identity token, if any
     * @return void
     * @throws Exception In case an error occurred
     */
    private function verifyAndSetIDToken(string $idToken, string $endpoint, string $accessToken = null): void {
        /**
         * Set leeway
         */
        JWT::$leeway = $this->leeway;

        $rs = \explode('.', $idToken);
        if (\count($rs) !== 3) {
            /**
             * If the response from the endpoint is not formatted as expected,
             * throw an exception
             */
            $this->throwException(__LINE__, 'Unexpected id token format');
        } elseif (!$rs2 = \json_decode(base64_decode($rs[0]), true)) {
            /**
             * If an error has occurred while trying to decode the JSON response,
             * throw an exception
             */
            $this->throwException(__LINE__, \json_last_error() . ': ' . \json_last_error_msg());
        } else {
            /**
             * Try to decode the token, based on the applicable algorithm
             *
             * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation #1
             * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation #9
             * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation #10
             */
            $alg = $rs2['alg'];
            if ($alg === 'RS256') {
                /**
                 * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation #7
                 */
                $decodedIDToken = JWT::decode($idToken, JWK::parseKeySet($this->keys), array('RS256'));
            } elseif ($alg === 'HS256') {
                // https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation #8
                $decodedIDToken = JWT::decode($idToken, $this->clientSecret, array('HS256'));
            }
            if ($decodedIDToken->iss !== $this->openidConfiguration['issuer']) {
                /**
                 * If the Issuer Identifier for the OpenID Provider
                 * does match with the value of the iss (issuer) Claim
                 * throw an exception
                 *
                 * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation #2
                 */
                $this->throwException(__LINE__, 'The Issuer Identifier for the OpenID Provider ' . $this->openidConfiguration['issuer'] . ' does not match with the value of the iss (issuer) Claim ' . $decodedIDToken['iss']);
            }
            if ($endpoint === 'TOKEN' && $decodedIDToken->aud !== $this->clientID) {
                /**
                 * If the client_id value registered at the Issuer
                 * does match with the value of the aud (audience) Claim
                 * throw an exception
                 *
                 * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation #3
                 */
                $this->throwException(__LINE__, 'The client_id value registered at the Issuer ' . $this->clientID . ' does not match with the value of the aud (audience) Claim ' . $decodedIDToken['aud']);
            } elseif ($endpoint === 'TOKEN') {
                if ($decodedIDToken->azp !== $this->clientID) {
                    /**
                     * If the client_id value registered at the Issuer
                     * does match with the value of the azp (authorized party) Claim
                     * throw an exception
                     *
                     * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation #5
                     */
                    $this->throwException(__LINE__, 'The client_id value registered at the Issuer ' . $this->clientID . ' does not match with the value of the azp (authorized party) Claim ' . $decodedIDToken['azp']);
                }
                if ($decodedIDToken->nonce !== $this->nonce) {
                    /**
                     * If the nonce sent
                     * does match with the value of the nonce Claim
                     * throw an exception
                     *
                     * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation #11
                     */
                    $this->throwException(__LINE__, 'The nonce sent ' . $this->nonce . ' does not match with the value of the nonce Claim ' . $decodedIDToken['nonce']);
                }
                if (isset($this->maxAge) && \time() - $decodedIDToken->auth_time > $this->maxAge) {
                    /**
                     * If too much time has elapsed since the last End-User authentication
                     * throw an exception
                     *
                     * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation #13
                     *
                     */
                    $this->throwException(__LINE__, 'Too much time has elapsed since the last End-User authentication');
                }
            }

            /**
             * If the identity token came together with an access token,
             * validate the token hashes (at_hash, c_hash)
             */
            if (!\is_null($accessToken) && isset($decodedIDToken->at_hash)) {
                $hash = \str_replace(['+', '/'], ['-', '_'], \rtrim(\base64_encode(\hex2bin(\substr(\hash('sha256', $accessToken), 0, 32))), '='));
                if ($hash !== $decodedIDToken->at_hash) {
                    /**
                     * If the hashes are not the same
                     * throw an exception
                     */
                    $this->throwException(__LINE__, 'Validation of the access token issued together with an ID token by the autorization endpoint failed');
                }
            }

            /**
             * On success, update the class member variables
             */
            $this->idTokenEndpoint = $endpoint;
            $this->idToken = $decodedIDToken;
            return;
        }
    }

    /**
     * Method to obtain a new access token on the basis of a refresh token
     *
     * @return void
     * @throws Exception In case an error occurred
     */
    private function refreshAccessToken(): void {

        if (!isset($this->refreshToken)) {
            /**
             * If no refresh token is available,
             * throw an exception
             */
            $this->throwException(__LINE__, 'There is no refresh token available');
        }

        /**
         * Try to redeem the refresh token at the token endpoint
         */
        $params = array(
            'grant_type' => 'refresh_token',
            'refresh_token' => $this->refreshToken
        );

        $hasCURLError = false;
        if (!$ch = \curl_init()) {
            $hasCURLError = true;
        }
        $cOpt1 = \curl_setopt($ch, CURLOPT_HEADER, 0);
        $cOpt2 = \curl_setopt($ch, CURLOPT_USERPWD, $this->clientID . ':' . $this->clientSecret);
        $cOpt3 = \curl_setopt($ch, CURLOPT_URL, $this->openidConfiguration['token_endpoint']);
        $cOpt4 = \curl_setopt($ch, CURLOPT_POST, 1);
        $cOpt5 = \curl_setopt($ch, CURLOPT_POSTFIELDS, \http_build_query($params));
        $cOpt6 = \curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if (!$rs = \curl_exec($ch)) {
            $hasCURLError = true;
        }
        $httpStatus = (int) \curl_getinfo($ch, CURLINFO_HTTP_CODE);
        \curl_close($ch);

        if ($hasCURLError || !$cOpt1 || !$cOpt2 || !$cOpt3 || !$cOpt4 || !$cOpt5 || !$cOpt6) {
            /**
             * If something went wrong with CURL
             * throw an exception
             */
            $this->throwException(__LINE__, 'Could not initialize the connection to refresh the access token');
        } elseif ($httpStatus === 400) {
            /**
             * If the HTTP status equals 400,
             * throw an exception
             */
            $this->throwException(__LINE__, 'The refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client');
        } elseif ($httpStatus !== 200) {
            /**
             * If the HTTP status was different from 200,
             * throw an exception
             */
            $this->throwException(__LINE__, 'Unexpected HTTP status ' . $httpStatus);
        } elseif (!$rs2 = \json_decode($rs, $associativeP = true)) {
            /**
             * If an error has occurred while trying to decode the JSON response,
             * throw an exception
             */
            $this->throwException(__LINE__, \json_last_error() . ': ' . \json_last_error_msg());
        }

        /**
         * Store the access and refresh token
         */
        $this->accessToken = $rs2['access_token'];
        $this->accessTokenExpirationTimestamp = \time() + (int) $rs2['expires_in'];
        $this->refreshToken = $rs2['refresh_token'];

        return;
    }

    /**
     * Method to verify a set of user-specified parameters
     *
     * @param array $parameters An associative array of parameters
     * @return void
     * @throws Exception In case an error occurred
     */
    private function verifyParameters(array $parameters): void {

        foreach ($parameters as $parameterName => $parameterValue) {
            $rs = $this->verifyParameter($parameterName, $parameterValue);
            if (!$rs['valid']) {
                /**
                 * If an invalid parameter has been specified,
                 * throw an exception
                 */
                $this->throwException(__LINE__, 'The ' . $parameterName . ' parameter "' . $parameterValue . '" is invalid. Valid values are ' . $rs['allowedValues']);
            }
        }

        return;
    }

    /**
     * Method to verify a user-specified parameter
     *
     * Returns an array containing:
     *
     * - valid, whether the parameter was valid
     * - alowedValues, the allowed values for the parameter specified
     *
     * @param string $type The type of parameter to verify. Valid values are 'environment', 'scope', 'claims', 'nonce', 'state', 'qoa', 'qor', 'locale', 'loginHint', 'prompt', 'maxAge', 'tokenType', 'stepUpType', 'leeway'
     * @param string $value the value to verify for the parameter specified
     * @return array
     * @throws Exception In case an error occurred
     */
    private function verifyParameter(string $type, string $value = null): array {
        switch ($type) {
            case 'environment':
                $allowedValues = array('PRE-PROD', 'PROD');
                return array(
                    'valid' => \in_array($value, $allowedValues),
                    'allowedValues' => \implode(', ', $allowedValues)
                );
            case 'scope':
                $valid = true;
                $allowedValues = array('openid', 'profile', 'email', 'phone', 'address');
                $requestedScopes = \explode(' ', $value);
                $requestedScopesCount = array_count_values($requestedScopes);
                if (max($requestedScopesCount) > 1) {
                    // check for duplicate in the requested scopes
                    $valid = false;
                }
                else {
                    // check if the requested scopes are within the allowed scopes
                    foreach ($requestedScopes as $requestedScope) {
                        if (!in_array($requestedScope, $allowedValues)) {
                            $valid = false;
                            break;
                        }
                    }
                }
                return array(
                    'valid' => $valid,
                    'allowedValues' => \implode(', ', $allowedValues)
                );
            case 'claims':
                return array(
                    'valid' => false,
                    'allowedValues' => 'Claims are a future placeholder. Currently not supported.'
                );
            case 'nonce':
                return array(
                    'valid' => true,
                    'allowedValues' => '*'
                );
            case 'state':
                return array(
                    'valid' => true,
                    'allowedValues' => '*'
                );
            case 'qoa':
                $allowedValues = array('qoa1', 'qoa2');
                return array(
                    'valid' => (\is_null($value) || \in_array($value, $allowedValues)),
                    'allowedValues' => \implode(', ', $allowedValues)
                );
            case 'qor':
                $allowedValues = array('qor0', 'qor1', 'qor2');
                return array(
                    'valid' => (\is_null($value) || \in_array($value, $allowedValues)),
                    'allowedValues' => \implode(', ', $allowedValues)
                );
            case 'locale':
                $allowedValues = array('de', 'fr', 'it', 'en');
                return array(
                    'valid' => (\is_null($value) || \in_array($value, $allowedValues)),
                    'allowedValues' => \implode(', ', $allowedValues)
                );
            case 'loginHint':
                return array(
                    'valid' => (\is_null($value) || \filter_var($value, FILTER_VALIDATE_EMAIL)),
                    'allowedValues' => 'a valid e-mail address'
                );
            case 'prompt':
                $allowedValues = array('none', 'login', 'consent');
                return array(
                    'valid' => (\is_null($value) || \in_array($value, $allowedValues)),
                    'allowedValues' => \implode(', ', $allowedValues)
                );
            case 'maxAge':
                return array(
                    'valid' => (\is_null($value) || (\is_numeric($value) && $value >= 0)),
                    'allowedValues' => 'a postive numeric value'
                );
            case 'tokenType':
                $allowedValues = array('ACCESS', 'REFRESH');
                return array(
                    'valid' => \in_array($value, $allowedValues),
                    'allowedValues' => \implode(', ', $allowedValues)
                );
            case 'stepUpType':
                $allowedValues = array('LOT1');
                return array(
                    'valid' => (\in_array($value, $allowedValues)),
                    'allowedValues' => \implode(', ', $allowedValues)
                );
            case 'leeway':
                return array(
                    'valid' => (\is_numeric($value)),
                    'allowedValues' => 'a numeric value'
                );
            default:
                /**
                 * If an invalid type has been specified,
                 * throw an exception
                 */
                $this->throwException(__LINE__, 'The type parameter "' . $type . '" is invalid. Valid values are environment, scope, claims, nonce, state, qoa, qor, locale, loginHint, prompt, maxAge, tokenType, stepUpType');
        }
    }

    /**
     * Method to throw an exception
     *
     * @param int $line The line at which the exception occurred
     * @param string $message The message to include in the exception
     * @return void
     * @throws Exception
     */
    private function throwException(int $line, string $message): void {
        $this->close();
        throw new Exception('Line ' . $line . ': ' . $message);
    }

    /**
     * Method to set the leeway for when checking a
     * token's nbf, iat or expiration time as described
     * {@link https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#nbfDef JSON Web Token (JWT)}
     *
     * @param int $leeway The leeway in seconds
     * @return void
     */
    public function setLeeway(int $leeway) : void {

        /**
         * Verify leeway parameter
         */
        $parameters = array(
            'leeway' => $leeway
        );
        $this->verifyParameters($parameters);

        /**
         * Set leeway
         */
        $this->leeway = $leeway;
        
        return;
    }

    /**
     * Method to authenticate the end-user
     *
     * After calling this method, make sure to check if any error have occurred
     * 
     * As per the {@link https://tools.ietf.org/id/draft-ietf-oauth-security-topics-13.html#rfc.section.3.1 OAuth 2.0 Security Best Current Practice},
     * as PKCE is not used, the state parameter SHOULD be used for CSRF protection and
     * can therefore not be specified as a parameter by the RP; instead, for example, store
     * the client's state in the session, retrieve the state used in the call and reconcile
     * them afterwards.
     *
     * @param string $scope The scope requested. Default value is 'openid'. Valid values are any combination of the following 'openid', 'profile', 'email', 'phone', 'address'
     * @param string $claims The claims requested. Future placeholder. Currently not supported.
     * @param string $qoa The Quality of Authentication (QoA) requested. Valid values are 'qoa1', 'qoa2'
     * @param string $qor The Quality of Registration (QoR) requested. Valid values are 'qor0', 'qor1', 'qor2'
     * @param string $locale The language of the end-user interface. Valid values are 'de', 'fr', 'it', 'en'
     * @param string $loginHint The login hint
     * @param string $prompt Whether and for what the IdP should prompt the end-user. Valid values are 'none', 'login', 'consent'
     * @param int $maxAge The allowable elapsed time in seconds since the last time the end-user was actively authenticated by SwissID. A valid value is an integer >= 0
     * @return void
     * @throws Exception In case an error occurred
     * @see SwissIDConnector::hasError()
     * @see SwissIDConnector::getState()
     */
    public function authenticate(string $scope = 'openid', string $claims = null, string $qoa = null, string $qor = null, string $locale = null, string $loginHint = null, string $prompt = null, int $maxAge = null): void {
        if (!$this->authenticationInitialized) {
            /**
             * Generate and set nonce
             */
            $this->nonce = \bin2hex(\random_bytes(16));

            /**
             * Set and save parameters
             */
            $parameters = array(
                'nonce' => $this->nonce,
                'state' => $this->state,
                'scope' => $scope,
                'qoa' => $qoa,
                'qor' => $qor,
                'locale' => $locale,
                'loginHint' => $loginHint,
                'prompt' => $prompt,
                'maxAge' => $maxAge
            );
            foreach ($parameters as $parameterName => $parameterValue) {
                if (!\is_null($parameterValue)) {
                    $this->$parameterName = $parameterValue;
                } else {
                    $$parameterName = (isset($this->$parameterName)) ? $this->$parameterName : null;
                    $parameters[$parameterName] = $$parameterName;
                }
            }

            /**
             * Verify parameters
             */
            $this->verifyParameters($parameters);

            /**
             * If this object was correctly initialized,
             * but the authentication was not initialized,
             * try to initialize the authentication
             */
            $claims = (\is_null($qor)) ? null : '{"userinfo":{"urn:swissid:qor":{"value":"' . $qor . '"}}}';
            $params = array(
                'response_type' => 'code',
                'client_id' => $this->clientID,
                'redirect_uri' => $this->redirectURI,
                'nonce' => $this->nonce,
                'state' => $this->state,
                'scope' => $scope,
                'acr_values' => $qoa,
                'ui_locales' => $locale,
                'login_hint' => $loginHint,
                'prompt' => $prompt,
                'max_age' => $maxAge,
                'claims' => $claims
            );
            $params2 = array();
            foreach ($params as $key => $val) {
                if (!\is_null($val)) {
                    $params2[$key] = $val;
                }
            }

            /**
             * Mark the authentication as being initialized
             */
            $this->authenticationInitialized = true;

            /**
             * Store state of this object in the session
             */
            $_SESSION[\get_class($this)] = \get_object_vars($this);

            /**
             * Redirect
             */
            $redirectLocation = $this->openidConfiguration['authorization_endpoint'] . '?' . \http_build_query($params2);
            \header('Location: ' . $redirectLocation);
            exit;
            return;
        } elseif (!$this->authorizationCodeExchanged['AUTH']['ANY']) {
            /**
             * https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
             * Verify the state parameter, after a callback
             */
            $this->verifyStateParameter();

            /**
             * Exchange the authorization code,
             * if not already done, which is the case after a callback
             */
            $this->exchangeAuthorizationCode('AUTH', 'ANY');
            return;
        } else {
            /**
             * Return if there is nothing to do
             */
            return;
        }
    }


    /**
     * Method to initiate the step-up of the end-user
     *
     * By default, most parameters are assumed to be the same as at the time of authentication,
     * but if needed, they can be changed for initiating the step-up.
     *
     * After calling this method, make sure to check if any error have occurred
     *
     * As per the {@link https://tools.ietf.org/id/draft-ietf-oauth-security-topics-13.html#rfc.section.3.1 OAuth 2.0 Security Best Current Practice},
     * as PKCE is not used, the state parameter SHOULD be used for CSRF protection and
     * can therefore not be specified as a parameter by the RP; instead, for example, store
     * the client's state in the session, retrieve the state used in the call and reconcile
     * them afterwards.
     *
     * @param string $stepUpType The type of step-up to initiate. Valid values are 'LOT1'
     * @param string $scope The scope requested, if different from at the time of authentication. Default value is 'openid'. Valid values are any combination of the following 'openid', 'profile', 'email', 'phone', 'address'
     * @param string $claims The claims requested, if different from at the time of authentication. Future placeholder. Currently not supported.
     * @param string $qoa The Quality of Authentication (QoA) requested, if different from at the time of authentication. Valid values are 'qoa1', 'qoa2'
     * @param string $qor The Quality of Registration (QoR) requested, if different from at the time of authentication. Valid values are 'qor0', 'qor1', 'qor2'
     * @param string $locale The language of the end-user interface, if different from at the time of authentication. Valid values are 'de', 'fr', 'it', 'en'
     * @param string $loginHint The login hint, if different from at the time of authentication.
     * @param string $prompt Whether and for what the IdP should prompt the end-user, if different from at the time of authentication. Valid values are 'none', 'login', 'consent'
     * @param int $maxAge The allowable elapsed time in seconds since the last time the end-user was actively authenticated by SwissID, if different from at the time of authentication. A valid value is an integer >= 0
     * @return void
     * @throws Exception In case an error occurred
     * @see SwissIDConnector::hasError()
     * @see SwissIDConnector::getState()
     */
    public function stepUp(string $stepUpType, string $scope = null, string $claims = null, string $qoa = null, string $qor = null, string $locale = null, string $loginHint = null, string $prompt = null, int $maxAge = null): void {
        /**
         * Verify step-up type parameter
         */
        $parameters = array();
        $parameters['stepUpType'] = $stepUpType;
        $this->verifyParameters($parameters);

        if (!$this->stepUpInitialized[$stepUpType]) {
            /**
             * Generate and set nonce
             */
            $this->nonce = \bin2hex(\random_bytes(16));

            /**
             * Set and save parameters
             */
            $parameters = array(
                'nonce' => $this->nonce,
                'state' => $this->state,
                'scope' => $scope,
                'qoa' => $qoa,
                'locale' => $locale,
                'loginHint' => $loginHint,
                'prompt' => $prompt,
                'maxAge' => $maxAge
            );
            foreach ($parameters as $parameterName => $parameterValue) {
                if (!\is_null($parameterValue)) {
                    $this->$parameterName = $parameterValue;
                } else {
                    $$parameterName = (isset($this->$parameterName)) ? $this->$parameterName : null;
                    $parameters[$parameterName] = $$parameterName;
                }
            }

            /**
             * Verify parameters
             */
            $this->verifyParameters($parameters);

            /**
             * If this object was correctly initialized,
             * but the step-up at the target QoR was not initialized,
             * try to initialize the step-up
             */
            $claims = (\is_null($qor)) ? null : '{"userinfo":{"urn:swissid:qor":{"value":"' . $qor . '"}}}';
            $params = array(
                'response_type' => 'code',
                'client_id' => $this->clientID,
                'redirect_uri' => $this->redirectURI,
                'nonce' => $this->nonce,
                'state' => $this->state,
                'scope' => $scope,
                'acr_values' => $qoa,
                'ui_locales' => $locale,
                'login_hint' => $loginHint,
                'prompt' => $prompt,
                'max_age' => $maxAge,
                'claims' => $claims
            );
            $params2 = array();
            foreach ($params as $key => $val) {
                if (!\is_null($val)) {
                    $params2[$key] = $val;
                }
            }

            /**
             * Mark the step-up as being initialized
             */
            $this->stepUpInitialized[$stepUpType] = true;

            /**
             * Store state of this object in the session
             */
            $_SESSION[\get_class($this)] = \get_object_vars($this);

            /**
             * Redirect
             */
            $redirectLocation = $this->stepUpURIs['LOT' . \substr($stepUpType, -1)][$this->environment] . '?' . \http_build_query($params2);
            \header('Location: ' . $redirectLocation);
            exit;
            return;
        } elseif (!$this->authorizationCodeExchanged['STEP_UP'][$stepUpType]) {
            /**
             * https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
             * Verify the state parameter, after a callback
             */
            $this->verifyStateParameter();
            
            /**
             * Exchange the authorization code,
             * if not already done, which is the case after a callback
             */
            $this->exchangeAuthorizationCode('STEP_UP', $stepUpType);
            return;
        } else {
            /**
             * Return if there is nothing to do
             */
            return;
        }
    }

    /**
     * Method to get the current state parameter used
     *
     * @return string
     */
    public function getState() : string {
        return $this->state;
    }

    /**
     * Method to reconnect to the IdP using a still valid access-token,
     * refresh-token or both
     *
     * @param string $accessToken A previously obtained access token
     * @param int $accessTokenExpirationTimestamp The expiration timestamp of the previously obtained access token
     * @param string $refreshToken A previously obtained refresh token
     * @param int $refreshTokenExpirationTimestamp The expiration timestamp of the previously obtained refresh token
     * @return void
     * @throws Exception In case an error occurred
     */
    public function reconnect(string $accessToken = null, int $accessTokenExpirationTimestamp = null, string $refreshToken = null, int $refreshTokenExpirationTimestamp = null): void {
        /**
         * If an invalid number of parameters have been specified,
         * throw an exception
         */
        if (is_null($accessToken) && is_null($refreshToken)) {
            $this->throwException(__LINE__, 'No parameters have been specified');
        } elseif ((!is_null($accessToken) && is_null($accessTokenExpirationTimestamp)) || (!is_null($refreshToken) && is_null($refreshTokenExpirationTimestamp))) {
            $this->throwException(__LINE__, 'An invalid number of parameters have been specified');
        }

        /**
         * If expired tokens have been provided
         * throw an exception
         */
        if ((!is_null($accessToken) && time() > $accessTokenExpirationTimestamp) || (!is_null($refreshToken) && time() > $refreshTokenExpirationTimestamp)) {
            $this->throwException(__LINE__, 'The provided token(s) has/have expired, please provide (a) valid one(s)');
        }

        /**
         * Store the token(s)
         */
        if (!\is_null($accessToken)) {
            $this->accessToken = $accessToken;
            $this->accessTokenExpirationTimestamp = $accessTokenExpirationTimestamp;
        }
        if (!\is_null($refreshToken)) {
            $this->refreshToken = $refreshToken;
            $this->refreshTokenExpirationTimestamp = $refreshTokenExpirationTimestamp;
        }

        return;
    }


    /**
     * Method to get a token of a specific type
     *
     * If available, returns an array containing:
     *
     * - token, the token
     * - expirationTimestamp, timestamp at which the token expires
     *
     * Otherwise, returns null
     *
     * @param string $tokenType The type of token to get. Valid values are 'ACCESS', 'REFRESH'
     * @return array|null
     * @throws Exception In case an error occurred
     */
    public function getToken(string $tokenType): ?array {

        /**
         * Verify parameters
         */
        $parameters = array(
            'tokenType' => $tokenType
        );
        $this->verifyParameters($parameters);

        /**
         * Return corresponding token
         */
        if ($tokenType === 'ACCESS' && !isset($this->accessToken)) {
            /**
             * If there is no access token,
             * return null
             */
            return null;
        } elseif ($tokenType === 'REFRESH' && !isset($this->refreshToken)) {
            /**
             * If there is no refresh token,
             * return null
             */
            return null;
        } elseif ($tokenType === 'ACCESS') {
            /**
             * Return the access token
             */
            return array(
                'token' => $this->accessToken,
                'expirationTimestamp' => $this->accessTokenExpirationTimestamp
            );
        } elseif ($tokenType === 'REFRESH') {
            /**
             * Return the refresh token
             */
            return array(
                'token' => $this->refreshToken,
                'expirationTimestamp' => $this->refreshTokenExpirationTimestamp
            );
        }
    }

    /**
     * Method to retrieve a claim for the end-user
     *
     * Returns the value of the claim or 'claimNotAvailable' if the claim is not available
     *
     * @param string $claim The claim to retrieve
     * @return string
     */
    public function getClaim(string $claim): string {
        if (!isset($this->idToken)) {
            /**
             * Obtain a new ID token, if not available
             */
            $this->getIDTokenFromUserInfoEndpoint();
        }

        if (!\property_exists($this->idToken, $claim)) {
            /**
             * If non-existing, return null value
             */
            return 'claimNotAvailable';
        } else {
            /**
             * On success, return the claim
             */
            return $this->idToken->$claim;
        }
    }

    /**
     * Method to determine whether this object has an error
     *
     * @return bool
     */
    public function hasError(): bool {
        return isset($this->error);
    }

    /**
     * Method to get the error for this object
     *
     * If no error has occurred, this method returns null, otherwise an array containing:
     *
     * - line, the line number at which the error occurred
     * - error, the error
     * - errorDescription, the error description
     *
     * @return array|null
     */
    public function getError(): ?array {
        return $this->error;
    }

    /**
     * Method to close this object
     *
     * @return void
     */
    function close() : void {
        /**
         * Unset the state of this object in the session
         */
       if (isset($_SESSION[\get_class($this)])) {
            unset($_SESSION[\get_class($this)]);
        }
        return;
    }

}
