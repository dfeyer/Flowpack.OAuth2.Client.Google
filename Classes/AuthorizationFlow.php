<?php

namespace Flowpack\OAuth2\Client\Google;

use Flowpack\OAuth2\Client\Exception\InvalidPartyDataException;
use Flowpack\OAuth2\Client\Flow\AbstractFlow;
use Flowpack\OAuth2\Client\Flow\FlowInterface;
use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use Neos\Flow\Annotations as Flow;
use Neos\Party\Domain\Model\ElectronicAddress;
use Neos\Party\Domain\Model\Person;
use Neos\Party\Domain\Model\PersonName;

/**
 */
class AuthorizationFlow extends AbstractFlow implements FlowInterface
{
    /**
     * @Flow\Inject
     * @var ApiClient
     */
    protected $api;

    /**
     * Creates a party for the given account
     *
     * @param AbstractClientToken $token
     * @throws InvalidPartyDataException
     */
    public function createPartyAndAttachToAccountFor(AbstractClientToken $token)
    {
        $this->initializeUserData($token);
        $userData = $this->authenticationServicesUserData[(string)$token];

        $party = new Person();
        $party->setName(new PersonName('', $userData['given_name'], '', $userData['family_name']));
        // Todo: this is not covered by the Person implementation, we should have a solution for that
        #$party->setBirthDate(\DateTime::createFromFormat('!m/d/Y', $userData['birthday'], new \DateTimeZone('UTC')));
        #$party->setGender(substr($userData['gender'], 0, 1));
        $electronicAddress = new ElectronicAddress();
        $electronicAddress->setType(ElectronicAddress::TYPE_EMAIL);
        $electronicAddress->setIdentifier($userData['email']);
        $electronicAddress->isApproved(true);
        $party->addElectronicAddress($electronicAddress);
        $party->setPrimaryElectronicAddress($electronicAddress);

        $partyValidator = $this->validatorResolver->getBaseValidatorConjunction('Neos\Party\Domain\Model\Person');
        $validationResult = $partyValidator->validate($party);
        if ($validationResult->hasErrors()) {
            throw new InvalidPartyDataException('The created party does not satisfy the requirements', 1384266207);
        }

        $account = $token->getAccount();
        $account->setParty($party);
        $this->accountRepository->update($account);
        $this->partyRepository->add($party);

        $this->persistenceManager->persistAll();
    }

    /**
     * Returns the token class name this flow is responsible for
     *
     * @return string
     */
    public function getTokenClassName()
    {
        return Token::class;
    }

    /**
     * getting all the defined data from facebook
     * @param AbstractClientToken $token
     */
    protected function initializeUserData(AbstractClientToken $token)
    {
        $query = '/userinfo/v2/me';
        $credentials = $token->getCredentials();
        $this->api->setCurrentAccessToken($credentials['access_token']);
        $content = $this->api->query($query)->getContent();
        $this->authenticationServicesUserData[(string)$token] = json_decode($content, true);
    }
}
