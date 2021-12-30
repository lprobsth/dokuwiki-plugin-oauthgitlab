<?php

namespace dokuwiki\plugin\oauthgitlab;

use dokuwiki\plugin\oauth\Service\AbstractOAuth2Base;
use OAuth\Common\Http\Uri\Uri;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

/**
 * Custom Service for GitLab oAuth
 */
class Gitlab extends AbstractOAuth2Base
{
    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        $hlp = plugin_load('helper', 'oauthgitlab');
        $this->baseurl = rtrim($hlp->getConf('url'), '/');

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri($this->baseurl.'/api/v4/');
        }
    }


    /** @inheritdoc */
    public function getAuthorizationEndpoint()
    {
        $plugin = plugin_load('helper', 'oauthgitlab');
        return new Uri($plugin->getConf('url').'/oauth/authorize');
    }

    /** @inheritdoc */
    public function getAccessTokenEndpoint()
    {
        $plugin = plugin_load('helper', 'oauthgitlab');
        return new Uri($plugin->getConf('url').'/oauth/token');
    }

    /**
     * @inheritdoc
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     * Logout from GitLab
     *
     * @return void
     * @throws \OAuth\Common\Exception\Exception
     */
    public function logout()
    {
        $plugin = plugin_load('helper', 'oauthgitlab');

        $token = $this->getStorage()->retrieveAccessToken($this->service());

        $parameters = [
            'client_id' => $this->credentials->getConsumerId(),
            'client_secret' => $this->credentials->getConsumerSecret(),
            'token' => $token,
        ];

        $this->httpClient->retrieveResponse(
            new Uri($plugin->getConf('url').'oauth/revoke'),
            $parameters,
            $this->getExtraOAuthHeaders()
        );
    }
}