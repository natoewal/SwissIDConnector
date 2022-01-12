<?php
/**
 * Example file
 *
 * Authenticating the end-user at a specific Quality of Registration (QoR),
 * qor1, and, if not available, guiding the end-user in attaining that QoR
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
    'redirectURL' => 'https://example.com/example4.php', // replace this with your redirect URL registered with SwissID
    'environment' => 'PRE-PROD' // replace this with the SwissID environment you are trying to interact with
);

/**
 * Create an array in the session to keep track of the client's state
 */
if (!isset($_SESSION['clientStates'])) {
    $_SESSION['clientStates'] = array();
}

try {
    /**
     * Instantiate a new SwissIDConnector
     */
    $swissIDConnector = new SwissIDConnector($configuration['clientID'], $configuration['clientSecret'], $configuration['environment'], $configuration['redirectURL']);
    $swissIDConnector->setLeeway(60); // Set leeway to account for clock skew as described in {@link https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#nbfDef JSON Web Token (JWT)}

    /**
     * Get the state parameter being used for being able to reconcile
     * it with the client's state, in this case containing
     * information on when the client initiated the process
     */
    if (!isset($_SESSION['clientStates'][$swissIDConnector->getState()])) {
        $_SESSION['clientStates'][$swissIDConnector->getState()] = array(
            'startDatetime' => time()
        );
    }

    /**
     * Authenticate the end-user at QoR1
     */
    $scope = 'openid profile'; // Request the mandatory openid and optional profile scope
    $claims = null;
    $qoa = null;
    $qor = 'qor1'; // Request the required Quality of Registration (QoR), qor1
    $locale = Locale::lookup(['de','fr','it','en'], \filter_input(INPUT_SERVER, 'HTTP_ACCEPT_LANGUAGE'), true, 'en'); // Set locale client's language and fallback to English by default
    $loginHint = null;
    $prompt = null;
    $maxAge = null;
    $initiateStepUp = false;
    $swissIDConnector->authenticate($scope, $claims, $qoa, $qor, $locale, $loginHint, $prompt, $maxAge);
    if ($swissIDConnector->hasError()) {
        /**
         * Handle errors
         */
        $error = $swissIDConnector->getError();
        switch ($error['error']) {
            case 'authentication_cancelled':
                /**
                 * Handle the scenario in which the end-user cancelled the login process
                 */
                echo 'You did complete the login process. Please ...';
                exit;
            case 'access_denied':
                /**
                 * Handle the scenario in which the end-user gave no consent
                 * to the scopes and/or claims requested
                 */
                echo 'You did not give consent to the scopes and/or claims requested. Please ...';
                exit;
            case 'interaction_required':
                /**
                 * Handle the scenario in which the authentication request contained the
                 * parameter"prompt=none" and the end-end-user is not yet authenticated
                 */
                echo 'You are required to login again, please authenicate yourself. Please ...';
                exit;
            case 'unmet_authentication_requirements':
                /**
                 * Handle the scenario in which the requested QoR is not available,
                 * by marking that the end-user needs to attain a verified identity
                 */
                $initiateStepUp = true;
                exit;
            default:
                /**
                 * Handle the scenario in which something unforeseen took place
                 */
                echo 'Oops, something happened which we did not foresee. Please ...';
                exit;
        }
    }
    else {
        /**
         * Determine the QoR
         */
        $qor = $swissIDConnector->getClaim('urn:swissid:qor');
        if ($qor != 'qor1') {
            /**
             * Handle the scenario in which the requested QoR is not available,
             * by marking that the end-user needs to attain a verified identity
             */
            $initiateStepUp = true;
        }
        else {
            /**
             * Get the state parameter being used to reconcile it with
             * the client's state, in this case containing information
             * on when the client initiated the process.
             */
            if (isset($_SESSION['clientStates'][$swissIDConnector->getState()])) {
                $startDatetime = $_SESSION['clientStates'][$swissIDConnector->getState()]['startDatetime'];
            } else {
                $startDatetime = 'an unknown datetime';
            }
        
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
             * Obtain the subject-identifier to create a new account binding
             * or to identify an existing account binding, if needed
             */
            $sub = $swissIDConnector->getClaim('sub');

            /**
             * Display the verified identity details
             */
            $givenName = $swissIDConnector->getClaim('given_name');
            $familyName = $swissIDConnector->getClaim('family_name');
            $dateOfBirth = $swissIDConnector->getClaim('urn:swissid:date_of_birth');
            echo 'Hi there '.$givenName.' '.$familyName.', after you initiated this process on '.date('Y-m-d @ h:i:s', $startDatetime).' (FYI, now it is '.date('h:i:s', time()).'), we figured out that you were born on '.$dateOfBirth;

            /**
             * Close the SwissIDConnector
             */
            $swissIDConnector->close();

            exit;
        }
    }

    /**
     * Initiate a step-up for the end-user to attain a verified identity
     * at the required QoR
     */
    if ($initiateStepUp) {
        $swissIDConnector->stepUp('LOT1', $scope, $claims, $qoa, $qor, $locale, $loginHint, $prompt, $maxAge);
        if ($swissIDConnector->hasError()) {
            /**
             * Handle errors
             */
            $error = $swissIDConnector->getError();
            switch ($error['error']) {
                case 'cancelled_by_user':
                    /**
                     * Handle the scenario in which the end-user cancelled the step-up process
                     */
                    echo 'You did complete the step-up process. Please ...';
                    exit;
                case 'manual_check_needed':
                    /**
                     * Handle the scenario in which the step-up is subject to a manual check
                     */
                    echo 'Thanks you. SwissID still needs a bit more time to manually verify your identity. Please ...';
                    break;
                case 'no_user_consent':
                    /**
                     * Handle the scenario in which the end-user gave no consent
                     * to the scopes and/or claims requested
                     */
                    echo 'You did not give consent to the scopes and/or claims requested. Please ...';
                    exit;
                default:
                    /**
                     * Handle the scenario in which something unforeseen took place
                     * or if a technical error has occurred
                     */
                    echo 'Oops, an error has occurred. Please try again, and if the problem persists, contact us';
                    exit;
            }
        }
    }
} catch (Exception $e) {
    /**
     * Catch exceptions
     */
    echo 'Oops, a technical error occurred. Please try again, and if the problem persists, contact us ('.$e->getMessage().')';
    exit;
}