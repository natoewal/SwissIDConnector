<?php
/**
 * Example file
 *
 * Obtaining offline access to the end-user's identity details, by
 * using a previously obtained access token, refresh token or both
 *
 * @package SwissIDConnector
 * @version 0.9
 * @author Sean Natoewal <sean@natoewal.nl>
 * @copyright Copyright (c) Sean Natoewal <sean@natoewal.nl>
 * @license https://opensource.org/licenses/MIT
 * @link https://github.com/natoewal/SwissIDConnector
 */

/**
 * Include the SwissIDConnector class
 */
require('SwissIDConnector.class.php');

/**
 * Start the session
 */
session_start();

/**
 * Include composer autoloader
 */
require(__DIR__ . '/../vendor/autoload.php');

/**
 * Alias namespace
 */
use \Natoewal\SwissID\SwissIDConnector;

/**
 * First, let's construct an array containing the RP-specific configuration
 */
$configuration = array(
    'clientID' => 'bfx8b-3df97-3d923-2737d', // replace this by the client_id received from SwissID
    'clientSecret' => 'ni72b9MfrjxXqmqoA9LsRvcK58h1AofQ', // replace this by the client_secret received from SwissID
    'redirectURL' => 'https://example.com/example5.php', // replace this with your redirect URL registered with SwissID
    'environment' => 'PRE-PROD' // replace this with the SwissID environment you are trying to interact with
);

try {
    /**
     * Instantiate a new SwissIDConnector
     */
    $swissIDConnector = new SwissIDConnector($configuration['clientID'], $configuration['clientSecret'], $configuration['environment']);
    $swissIDConnector->setLeeway(60); // Set leeway to account for clock skew as described in {@link https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#nbfDef JSON Web Token (JWT)}

    /**
     * Using a previously obtained, still valid, access token, refresh token or both
     */
    $accessToken = 'bRCRCtgdcUOyLeBWNWKmEklqWoE';
    $accessTokenExpirationDatetime = '1642001271';
    $refreshToken = null;//'TpneTnXOEF_gft6LjTnB02SPmnA';
    $refreshTokenExpirationDatetime = null;//'1657634558';

    /**
     * Reconnect based on the previously obtained tokens
     */
    $swissIDConnector->reconnect($accessToken, $accessTokenExpirationDatetime, $refreshToken, $refreshTokenExpirationDatetime);

    /**
     * Display the identity details
     */
    $givenName = $swissIDConnector->getClaim('given_name');
    $familyName = $swissIDConnector->getClaim('family_name');
    echo 'Hi there '.$givenName.' '.$familyName.', welcome back';

    /**
     * Obtain the latest access- and, optionally, the refresh token
     * details for getting offline access to the identity details
     * at a future point in time, if needed, after having requested
     * the identity details
     */
    if (!is_null($accessTokenDetails = $swissIDConnector->getToken('ACCESS'))) {
        $accessToken = $accessTokenDetails['token'];
        $accessTokenExpirationTimestamp = $accessTokenDetails['expirationTimestamp'];
    }
    if (!is_null($refreshTokenDetails = $swissIDConnector->getToken('REFRESH'))) {
        $refreshToken = $refreshTokenDetails['token'];
        $refreshTokenExpirationTimestamp = $refreshTokenDetails['expirationTimestamp'];
    }

    /**
     * Close the SwissIDConnector
     */
    $swissIDConnector->close();

    exit;
} catch (Exception $e) {
    /**
     * Catch exceptions
     */
    echo 'Oops, a technical error occurred. Please try again, and if the problem persists, contact us ('.$e->getMessage().')';
    exit;
}