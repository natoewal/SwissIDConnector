# SwissIDConnector

## About

SwissIDConnector is a lightweight class to interact with the SwissID IdP, supporting the full scope of functionality provided by the IdP in a manner that is not only easy, but also future-proof to the maximum extent possible as it relies on the basic concepts used by the SwissID IdP and on its dynamic configuration.

For more information about SwissID, please visit [their website](https://www.swissid.ch)

## Requirements
PHP
CURL extension
JSON extension

## Preparation

This project assumes you have composer installed.

1. Download PHP-JWT dependency via composer:
```sh
composer require firebase/php-jwt
```

2. Include the SwissIDConnector class
```sh
require('SwissIDConnector.class.php');
```

3. Start the session
```sh
session_start();
```

4. Include composer autoloader
```sh
require(__DIR__ . '/../vendor/autoload.php');
```

## Usage

Please see the following included examples for more information about its usage:

| File | README |
| ------ | ------ |
| example1.php | Authenticating the end-user at the lowest Quality of Registration (QoR) available |
| example2.php | Authenticating the end-user with a specific Quality of Authentication (QoA), using two-factor authentication, which, if not available, automatically guides the end-user in attaining that QoA |
| example3.php | Authenticating the end-user at the highest Quality of Registration (QoR) available |
| example4.php | Authenticating the end-user at a specific Quality of Registration (QoR),qor1, and, if not available, guiding the end-user in attaining that QoR |
| example5.php | Obtaining offline access to the end-user's identity details, by using a previously obtained access token, refresh token or both |
