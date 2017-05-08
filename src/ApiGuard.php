<?php
namespace pmill\LaravelAwsCognito;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use pmill\AwsCognito\CognitoClient;
use pmill\LaravelAwsCognito\Exceptions\CognitoUserNotFoundException;

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
    protected $usernameField;

    /**
     * @var AuthenticationResponse
     */
    protected $authenticationResponse;

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
        $this->usernameField = config('aws-cognito-auth.username_field');
    }

    /**
     * @return Authenticatable
     */
    public function user()
    {
        return $this->user;
    }

    public function logout()
    {
        $this->accessToken = null;
        $this->user = null;
    }

    /**
     * @param array $credentials
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        $username = array_get($credentials, $this->usernameField);
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
            $this->usernameField => $username,
        ]);
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return AuthenticationResponse
     * @throws CognitoUserNotFoundException
     */
    public function attempt($username, $password)
    {
        $cognitoAuthenticationResponse = $this->cognitoClient->authenticate($username, $password);

        $authenticationResponse = new AuthenticationResponse;
        $authenticationResponse->setAccessToken(array_get($cognitoAuthenticationResponse, 'AccessToken'));
        $authenticationResponse->setExpiresIn(array_get($cognitoAuthenticationResponse, 'ExpiresIn'));
        $authenticationResponse->setIdToken(array_get($cognitoAuthenticationResponse, 'IdToken'));
        $authenticationResponse->setRefreshToken(array_get($cognitoAuthenticationResponse, 'RefreshToken'));
        $authenticationResponse->setTokenType(array_get($cognitoAuthenticationResponse, 'TokenType'));

        $this->user = $this->provider->retrieveByCredentials([
            $this->usernameField => $username,
        ]);

        if (!$this->user) {
            throw new CognitoUserNotFoundException();
        }

        return $this->authenticationResponse = $authenticationResponse;
    }

    /**
     * @return AuthenticationResponse
     */
    public function authenticationResponse()
    {
        return $this->authenticationResponse;
    }
}
