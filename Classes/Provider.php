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

use Flowpack\OAuth2\Client\Provider\AbstractClientProvider;
use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Configuration\ConfigurationManager;
use Neos\Flow\Log\SecurityLoggerInterface;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;

class Provider extends AbstractClientProvider
{
    /**
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $securityLogger;

    /**
     * @Flow\Inject
     * @var ConfigurationManager
     */
    protected $configurationManager;

    /**
     * @Flow\Inject
     * @var ObjectManagerInterface
     */
    protected $objectManager;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var AccountRepository
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var TokenEndpoint
     */
    protected $endpoint;

    /**
     * @Flow\Inject
     * @var AuthorizationFlow
     */
    protected $authorizationFlow;

    /**
     * @Flow\Inject
     * @var \Neos\Flow\Persistence\PersistenceManagerInterface
     */
    protected $persistenceManager;

    /**
     * Tries to authenticate the given token. Sets isAuthenticated to TRUE if authentication succeeded.
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @throws \Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException
     * @return void
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!($authenticationToken instanceof AbstractClientToken)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1383754993);
        }

        $credentials = $authenticationToken->getCredentials();
        $scope = $this->buildScopeParameter();
        $tokenInformation = $this->endpoint->requestValidatedTokenInformation($credentials, $scope);

        if ($tokenInformation === false) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        // From here, we surely know the user is considered authenticated against the remote service,
        // yet to check if there is an immanent account present.
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        /** @var $account \Neos\Flow\Security\Account */
        $account = null;
        $isNewCreatedAccount = false;
        $providerName = $this->name;
        $accountRepository = $this->accountRepository;
        $this->securityContext->withoutAuthorizationChecks(function () use ($tokenInformation, $providerName, $accountRepository, &$account) {
            $account = $accountRepository->findByAccountIdentifierAndAuthenticationProviderName($tokenInformation['sub'], $providerName);
        });

        if ($account === null) {
            $account = new Account();
            $isNewCreatedAccount = true;
            $account->setAccountIdentifier($tokenInformation['sub']);
            $account->setAuthenticationProviderName($providerName);

            // adding in Settings.yaml specified roles to the account
            // so the account can be authenticate against a role in the frontend for example
            $roles = [];
            foreach ($this->options['authenticateRoles'] as $roleIdentifier) {
                $roles[] = $this->policyService->getRole($roleIdentifier);
            }
            $account->setRoles($roles);
            $this->accountRepository->add($account);
        }

        $authenticationToken->setAccount($account);

        // request long-live token and attach that to the account
        $longLivedToken = $this->endpoint->requestLongLivedToken($credentials['access_token']);
        $account->setCredentialsSource($longLivedToken['access_token']);
        $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        $this->accountRepository->update($account);
        $this->persistenceManager->persistAll();

        // Only if defined a Party for the account is created
        if ($this->options['partyCreation'] && $isNewCreatedAccount) {
            $this->authorizationFlow->createPartyAndAttachToAccountFor($authenticationToken);
        }
    }

    /**
     * Returns the class names of the tokens this provider is responsible for.
     *
     * @return array The class name of the token this provider is responsible for
     */
    public function getTokenClassNames()
    {
        return [Token::class];
    }

    /**
     * Returns the scopes
     *
     * @return array
     */
    protected function buildScopeParameter()
    {
        $scopes = $this->configurationManager->getConfiguration(ConfigurationManager::CONFIGURATION_TYPE_SETTINGS, 'Neos.Flow.security.authentication.providers.GoogleOAuth2Provider.providerOptions.scopes');
        $scope = implode(' ', $scopes);
        $scopes = ['scope' => $scope];

        return $scopes;
    }
}
