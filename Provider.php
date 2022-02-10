<?php

namespace SocialiteProviders\Microsoft;

use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Microsoft\MicrosoftUser as User;

class Provider extends AbstractProvider
{
    /**
     * Unique Provider Identifier.
     */
    public const IDENTIFIER = 'MICROSOFT';

    /**
     * {@inheritdoc}
     * https://msdn.microsoft.com/en-us/library/azure/ad/graph/howto/azure-ad-graph-api-permission-scopes.
     */
    protected $scopes = ['XboxLive.signin'];

    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return
            $this->buildAuthUrlFromBase(
                sprintf(
                    'https://login.live.com/oauth20_authorize.srf',
                    $this->config['tenant'] ?: 'consumers'
                ),
                $state
            );
    }

    /**
     * {@inheritdoc}
     * https://developer.microsoft.com/en-us/graph/docs/concepts/use_the_api.
     */
    protected function getTokenUrl()
    {
        return sprintf('https://login.live.com/oauth20_token.srf', $this->config['tenant'] ?: 'consumers');
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        // XboxLive XBL
        $xboxLiveXBLresponse = $this->getHttpClient()->post(
            'https://user.auth.xboxlive.com/user/authenticate',
            [
                'headers' => [
                    'Accept'        => 'application/json',
                ],
                'json' => [
                    'Properties' => [
                        'AuthMethod' => 'RPS',
                        'SiteName' => 'user.auth.xboxlive.com',
                        'RpsTicket' => 'd='.$token
                    ],
                    'RelyingParty' => 'http://auth.xboxlive.com',
                    'TokenType' => 'JWT'
                ]
            ]
        );
        $xboxLiveXBLAuth = json_decode($xboxLiveXBLresponse->getBody()->getContents(), true);

        // XboxLive XSTS
        $xboxLiveXSTSresponse = $this->getHttpClient()->post(
            'https://xsts.auth.xboxlive.com/xsts/authorize',
            [
                'headers' => [
                    'Accept'        => 'application/json',
                ],
                'json' => [
                    'Properties' => [
                        'SandboxId' => 'RETAIL',
                        'UserTokens' => [
                            $xboxLiveXBLAuth['Token']
                        ],
                    ],
                    'RelyingParty' => 'rp://api.minecraftservices.com/',
                    'TokenType' => 'JWT'
                ]
            ]
        );
        $xboxLiveXSTSAuth = json_decode($xboxLiveXSTSresponse->getBody()->getContents(), true);

        // auth to mc
        $mcLoginResponse = $this->getHttpClient()->post(
            'https://api.minecraftservices.com/authentication/login_with_xbox',
            [
                'headers' => [
                    'Accept'        => 'application/json',
                ],
                'json' => [
                    'identityToken' => 'XBL3.0 x='.$xboxLiveXBLAuth['DisplayClaims']['xui'][0]['uhs'].';'.$xboxLiveXSTSAuth['Token']
                ]
            ]
        );
        $mcLoginAccessToken = json_decode($mcLoginResponse->getBody()->getContents(), true)['access_token'];

        // get mc profile
        $mcProfileResponse = $this->getHttpClient()->get(
            'https://api.minecraftservices.com/minecraft/profile',
            [
                'headers' => [
                    'Authorization' => 'Bearer '.$mcLoginAccessToken
                ]
            ]
        );

        return json_decode($mcProfileResponse->getBody()->getContents(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id'       => $user['id'],
            'name'     => $user['name'],
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
            'scope'      => parent::formatScopes(parent::getScopes(), $this->scopeSeparator),
        ]);
    }

    /**
     * Add the additional configuration key 'tenant' to enable the branded sign-in experience.
     *
     * @return array
     */
    public static function additionalConfigKeys()
    {
        return ['tenant'];
    }
}
