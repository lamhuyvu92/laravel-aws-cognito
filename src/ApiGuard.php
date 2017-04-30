<?php
namespace App\LaravelAwsCognito;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use pmill\AwsCognito\CognitoClient;

class ApiGuard implements Guard
{
    use GuardHelpers;

    /**
     * @var CognitoClient
     */
    protected $cognitoClient;

    /**
     * @var string
     */
    protected $accessToken;

    /**
     * ApiGuard constructor.
     *
     * @param UserProvider $userProvider
     * @param CognitoClient $cognitoClient
     */
    public function __construct(UserProvider $userProvider, CognitoClient $cognitoClient)
    {
        $this->provider = $userProvider;
        $this->cognitoClient = $cognitoClient;
    }

    /**
     * @return Authenticatable
     */
    public function user()
    {
        return $this->user;
    }

    /**
     * @return string
     */
    public function accessToken()
    {
        return $this->accessToken;
    }

    /**
     * @param array $credentials
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        $username = array_get($credentials, 'username');
        $password = array_get($credentials, 'password');
        $this->attempt($username, $password);
        return $this->check();
    }

    /**
     * @return bool
     */
    public function validateToken()
    {
        $authorizationHeader = request()->header('Authorization');
        $accessToken = trim(str_replace('Bearer', '', $authorizationHeader));
        $this->attemptWithToken($accessToken);
        return $this->check();
    }

    /**
     * @param string $accessToken
     */
    public function attemptWithToken($accessToken)
    {
        $username = $this->cognitoClient->verifyAccessToken($accessToken);
        $this->user = $this->provider->retrieveByCredentials([
            'username' => $username,
        ]);
    }

    /**
     * @param string $username
     * @param string $password
     */
    public function attempt($username, $password)
    {
        $authenticationResponse = $this->cognitoClient->authenticate($username, $password);
        $this->accessToken = array_get($authenticationResponse, 'AccessToken');
        $this->user = $this->provider->retrieveByCredentials([
            'username' => $username,
        ]);
    }
}
