<?php

namespace SocialiteProviders\Azure;

use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;

class Provider extends AbstractProvider implements ProviderInterface
{
    /**
     * The base Azure Graph URL.
     *
     * @var string
     */
    protected $graphUrl = 'https://graph.windows.net/myorganization/me';

    /**
     * The Graph API version for the request.
     *
     * @var string
     */
    protected $version = '1.5';

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            'https://login.windows.net/common/oauth2/authorize', $state
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return 'https://login.windows.net/common/oauth2/token';
    }

    public function getAccessToken($code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            'form_params' => $this->getTokenFields($code),
        ]);

        return $this->parseAccessToken($response->getBody());
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get($this->graphUrl, [
            'query' => [
                'api-version' => $this->version,
            ],
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id' => $user['objectId'], 'nickname' => null, 'name' => $user['displayName'],
            'email' => $user['userPrincipalName'], 'avatar' => null,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
            'resource' => 'https://graph.windows.net',
        ]);
    }
}
