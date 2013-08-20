using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net;
using RestSharp;
using WorldDomination.Web.Authentication;
using WorldDomination.Web.Authentication.Providers;
using WorldDomination.Web.Authentication.Providers.Google;

namespace Jabbr.AuthenticationProviders
{
    public class GoogleInMotivProvider : BaseProvider, IAuthenticationProvider
    {
        private readonly string _clientId;

        private readonly string _clientSecret;

        private readonly IList<string> _scope;

        public string Name
        {
            get
            {
                return "Google";
            }
        }

        public IAuthenticationServiceSettings DefaultAuthenticationServiceSettings
        {
            get
            {
                return new GoogleInMotivProviderAuthenticationServiceSettings(Name);
            }
        }

        public GoogleInMotivProvider(ProviderParams providerParams)
        {
            providerParams.Validate();
            _clientId = providerParams.Key;
            _clientSecret = providerParams.Secret;
            _scope = new List<string>
                {
                    "https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/userinfo.email"
                };
        }

        private static string RetrieveAuthorizationCode(NameValueCollection queryStringParameters)
        {
            if (queryStringParameters == null)
                throw new ArgumentNullException("queryStringParameters");
            if (queryStringParameters.Count <= 0)
                throw new ArgumentOutOfRangeException("queryStringParameters");
            
            string str1 = queryStringParameters["code"];
            string str2 = queryStringParameters["error"];
           
            if (!string.IsNullOrEmpty(str2))
                throw new AuthenticationException(
                    "Failed to retrieve an authorization code from Google. The error provided is: " + str2);
            
            if (string.IsNullOrEmpty(str1))
                throw new AuthenticationException(
                    "No code parameter provided in the response query string from Google.");
            
            return str1;
        }

        private AccessTokenResult RetrieveAccessToken(string authorizationCode, Uri redirectUri)
        {
            if (string.IsNullOrEmpty(authorizationCode))
                throw new ArgumentNullException("authorizationCode");
            if (!(redirectUri == null))
            {
                if (!string.IsNullOrEmpty(redirectUri.AbsoluteUri))
                {
                    IRestResponse<AccessTokenResult> restResponse;
                    try
                    {
                        var restRequest = new RestRequest("/o/oauth2/token", Method.POST);
                        restRequest.AddParameter("client_id", _clientId);
                        restRequest.AddParameter("client_secret", _clientSecret);
                        restRequest.AddParameter("redirect_uri", redirectUri.AbsoluteUri);
                        restRequest.AddParameter("code", authorizationCode);
                        restRequest.AddParameter("grant_type","authorization_code");
                        restResponse =
                            RestClientFactory.CreateRestClient("https://accounts.google.com").Execute<AccessTokenResult>(restRequest);
                    }
                    catch (Exception ex)
                    {
                        throw new AuthenticationException("Failed to obtain an Access Token from Google.", ex);
                    }
                    if (restResponse == null || restResponse.StatusCode != HttpStatusCode.OK)
                        throw new AuthenticationException(
                            string.Format(
                                "Failed to obtain an Access Token from Google OR the the response was not an HTTP Status 200 OK. Response Status: {0}. Response Description: {1}",
                                restResponse == null
                                    ? "-- null response --"
                                    : ((object)restResponse.StatusCode).ToString(),
                                restResponse == null ? string.Empty : restResponse.StatusDescription));
                    if (string.IsNullOrEmpty(restResponse.Data.AccessToken) || restResponse.Data.ExpiresIn <= 0
                        || string.IsNullOrEmpty(restResponse.Data.TokenType))
                        throw new AuthenticationException(
                            "Retrieved a Google Access Token but it doesn't contain one or more of either: access_token, expires_in or token_type");
                    
                    return restResponse.Data;
                }
            }
            throw new ArgumentNullException("redirectUri");
        }

        private UserInfoResult RetrieveUserInfo(string accessToken)
        {
            if (string.IsNullOrEmpty(accessToken))
                throw new ArgumentNullException("accessToken");
            IRestResponse<UserInfoResult> restResponse;
            try
            {
                var restRequest = new RestRequest("/oauth2/v2/userinfo", Method.GET);
                restRequest.AddParameter("access_token", accessToken);
                restResponse = RestClientFactory.CreateRestClient("https://www.googleapis.com").Execute<UserInfoResult>(restRequest);
            }
            catch (Exception ex)
            {
                throw new AuthenticationException("Failed to obtain User Info from Google.", ex);
            }
            if (restResponse == null || restResponse.StatusCode != HttpStatusCode.OK)
                throw new AuthenticationException(
                    string.Format(
                        "Failed to obtain User Info from Google OR the the response was not an HTTP Status 200 OK. Response Status: {0}. Response Description: {1}",
                        restResponse == null
                            ? "-- null response --"
                            : (restResponse.StatusCode).ToString(),
                        restResponse == null ? string.Empty : restResponse.StatusDescription));
            if (string.IsNullOrEmpty(restResponse.Data.Id))
                throw new AuthenticationException(
                    "We were unable to retrieve the User Id from Google API, the user may have denied the authorization.");
            
            return restResponse.Data;
        }

        public Uri RedirectToAuthenticate(IAuthenticationServiceSettings authenticationServiceSettings)
        {
            var settings = authenticationServiceSettings as GoogleInMotivProviderAuthenticationServiceSettings;

            if (settings == null)
                throw new ArgumentNullException("authenticationServiceSettings");

            if (settings.CallBackUri == null)
                throw new ArgumentException("authenticationServiceSettings.CallBackUri");
            
            
            string scopeUri = _scope == null || _scope.Count <= 0
                                  ? string.Empty
                                  : string.Format("&scope={0}", string.Join(" ", _scope));
            string stateUri = string.IsNullOrEmpty(settings.State)
                                  ? string.Empty
                                  : "&state=" + settings.State;
            string domainUri = !String.IsNullOrWhiteSpace(settings.DomainName)
                                   ? "&hd=" + settings.DomainName
                                   : String.Empty;

            return
                new Uri(
                    string.Format(
                        "https://accounts.google.com/o/oauth2/auth?client_id={0}&redirect_uri={1}&response_type=code{2}{3}{4}",
                        _clientId,
                        authenticationServiceSettings.CallBackUri.AbsoluteUri,
                        stateUri,
                        scopeUri,
                        domainUri
                        ));
        }

        public IAuthenticatedClient AuthenticateClient(IAuthenticationServiceSettings authenticationServiceSettings, NameValueCollection queryStringParameters)
        {
            if (authenticationServiceSettings == null)
                throw new ArgumentNullException("authenticationServiceSettings");

            var accessTokenResult = RetrieveAccessToken(RetrieveAuthorizationCode(queryStringParameters), authenticationServiceSettings.CallBackUri);
            var userInfoResult = RetrieveUserInfo(accessTokenResult.AccessToken);
            
            return new AuthenticatedClient(Name.ToLowerInvariant())
                {
                    AccessToken = accessTokenResult.AccessToken,
                    AccessTokenExpiresOn =
                        DateTime.UtcNow.AddSeconds(accessTokenResult.ExpiresIn),
                    UserInformation = new UserInformation
                        {
                            Id = userInfoResult.Id,
                            Gender =
                                (string.IsNullOrEmpty(
                                    userInfoResult.Gender)
                                     ? GenderType.Unknown
                                     : GenderTypeHelpers.ToGenderType(
                                         userInfoResult.Gender)),
                            Name = userInfoResult.Name,
                            Email = userInfoResult.Email,
                            Locale = userInfoResult.Locale,
                            Picture = userInfoResult.Picture,
                            UserName = userInfoResult.GivenName
                        }
                };
        }
    }
}