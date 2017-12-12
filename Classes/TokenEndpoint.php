<?php

namespace Flowpack\OAuth2\Client\Google;

/*
 * This file is part of the Flowpack.OAuth2.Client.Google package.
 *
 * (c) Contributors of the Flowpack Team - flowpack.org
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Flowpack\OAuth2\Client\Endpoint\AbstractHttpTokenEndpoint;
use Flowpack\OAuth2\Client\Endpoint\TokenEndpointInterface;
use Flowpack\OAuth2\Client\Exception as OAuth2Exception;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Request;
use Neos\Flow\Http\Uri;
use Neos\Flow\Log\SecurityLoggerInterface;

/**
 * @Flow\Scope("singleton")
 */
class TokenEndpoint extends AbstractHttpTokenEndpoint implements TokenEndpointInterface
{
    /**
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $securityLogger;

    /**
     *
     * @param string $tokenToInspect
     * @return array
     * @throws OAuth2Exception
     */
    public function requestValidatedTokenInformation($tokenToInspect)
    {
        $requestArguments = [
            'input_token' => $tokenToInspect['access_token'],
            'id_token' => $tokenToInspect['id_token']
        ];

        $request = Request::create(new Uri('https://www.googleapis.com/oauth2/v3/tokeninfo?' . http_build_query($requestArguments)));
        $response = $this->requestEngine->sendRequest($request);
        $responseContent = $response->getContent();
        if ($response->getStatusCode() !== 200) {
            throw new OAuth2Exception(sprintf('The response was not of type 200 but gave code and error %d "%s"', $response->getStatusCode(), $responseContent), 1383758360);
        }

        $responseArray = json_decode($responseContent, true, 16, JSON_BIGINT_AS_STRING);
        $responseArray['aud'] = (string)$responseArray['aud'];
        $responseArray['sub'] = (string)$responseArray['sub'];
        $clientIdentifier = (string)$this->clientIdentifier;

        if ($responseArray['aud'] !== $clientIdentifier) {
            $this->securityLogger->log('Requesting validated token information from the Google endpoint did not succeed.', LOG_NOTICE, ['response' => var_export($responseArray, true), 'clientIdentifier' => $clientIdentifier]);
            return false;
        }

        return $responseArray;
    }

    /**
     * @param $shortLivedToken
     * @return string
     */
    public function requestLongLivedToken($shortLivedToken)
    {
        return $this->requestAccessToken('refresh_token', ['refresh_token' => $shortLivedToken]);
    }
}
