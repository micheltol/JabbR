using System;
using System.Collections.Generic;
using System.Net;
using RestSharp;
using SimpleAuthentication.Core.Exceptions;
using SimpleAuthentication.Core.Providers.Google;
using SimpleAuthentication.Core.Tracing;

namespace SimpleAuthentication.Core.Providers
{
    // REFERENCE: https://developers.google.com/accounts/docs/OAuth2Login

    public class InMotivProvider : BaseOAuth20Provider<AccessTokenResult>
    {
        private const string AccessTokenKey = "access_token";
        private const string ExpiresInKey = "expires_in";
        private const string TokenTypeKey = "token_type";

        public InMotivProvider(ProviderParams providerParams)
            : base("Google", providerParams)
        {
            AuthenticateRedirectionUrl = new Uri("https://accounts.google.com/o/oauth2/auth");
        }

        #region BaseOAuth20Token<AccessTokenResult> Implementation

        protected override IRestResponse<AccessTokenResult> ExecuteRetrieveAccessToken(string authorizationCode,
                                                                                       Uri redirectUri)
        {
            if (string.IsNullOrEmpty(authorizationCode))
            {
                throw new ArgumentNullException("authorizationCode");
            }

            if (redirectUri == null ||
                string.IsNullOrEmpty(redirectUri.AbsoluteUri))
            {
                throw new ArgumentNullException("redirectUri");
            }

            var restRequest = new RestRequest("/o/oauth2/token", Method.POST);
            restRequest.AddParameter("client_id", PublicApiKey);
            restRequest.AddParameter("client_secret", SecretApiKey);
            restRequest.AddParameter("redirect_uri", redirectUri.AbsoluteUri);
            restRequest.AddParameter("code", authorizationCode);
            restRequest.AddParameter("grant_type", "authorization_code");
            //restRequest.AddParameter("hd", "inmotiv.net");


            var restClient = RestClientFactory.CreateRestClient("https://accounts.google.com");
            TraceSource.TraceVerbose("Retrieving Access Token endpoint: {0}",
                                     restClient.BuildUri(restRequest).AbsoluteUri);

            return restClient.Execute<AccessTokenResult>(restRequest);
        }

        protected new string CreateRedirectionQuerystringParameters(Uri callbackUri, string state)
        {
            if (callbackUri == (Uri) null)
                throw new ArgumentNullException("callbackUri");
            if (string.IsNullOrEmpty(state))
                throw new ArgumentNullException("state");
            return string.Format("client_id={0}&redirect_uri={1}&response_type=code{2}{3}&hd=inmotiv.net",
                                 (object) this.PublicApiKey, (object) callbackUri.AbsoluteUri, (object) this.GetScope(),
                                 (object) this.GetQuerystringState(state));
        }

        public override RedirectToAuthenticateSettings RedirectToAuthenticate(Uri callbackUri)
        {
            if (callbackUri == (Uri)null)
                throw new ArgumentNullException("callbackUri");
            if (this.AuthenticateRedirectionUrl == (Uri)null)
                throw new AuthenticationException("AuthenticationRedirectUrl has no value. Please set the authentication Url location to redirect to.");
            if (string.IsNullOrEmpty(this.PublicApiKey))
                throw new AuthenticationException("PublicApiKey has no value. Please set this value.");
            string state = Guid.NewGuid().ToString();
            string uriString = string.Format("{0}?{1}", (object)this.AuthenticateRedirectionUrl.AbsoluteUri, (object)this.CreateRedirectionQuerystringParameters(callbackUri, state));
            this.TraceSource.TraceInformation("Google redirection uri: {0}.", new object[1]
      {
        (object) uriString
      });
            return new RedirectToAuthenticateSettings()
            {
                RedirectUri = new Uri(uriString),
                State = state
            };
        }

        protected override AccessToken MapAccessTokenResultToAccessToken(AccessTokenResult accessTokenResult)
        {
            if (accessTokenResult == null)
            {
                throw new ArgumentNullException("accessTokenResult");
            }

            if (string.IsNullOrEmpty(accessTokenResult.AccessToken) ||
                accessTokenResult.ExpiresIn <= 0 ||
                string.IsNullOrEmpty(accessTokenResult.TokenType))
            {
                var errorMessage =
                    string.Format(
                        "Retrieved a Google Access Token but it doesn't contain one or more of either: {0}, {1} or {2}.",
                        AccessTokenKey, ExpiresInKey, TokenTypeKey);
                TraceSource.TraceError(errorMessage);
                throw new AuthenticationException(errorMessage);
            }

            return new AccessToken
            {
                PublicToken = accessTokenResult.AccessToken,
                ExpiresOn = DateTime.UtcNow.AddSeconds(accessTokenResult.ExpiresIn)
            };
        }

        protected override UserInformation RetrieveUserInformation(AccessToken accessToken)
        {
            if (accessToken == null)
            {
                throw new ArgumentNullException("accessToken");
            }

            if (string.IsNullOrEmpty(accessToken.PublicToken))
            {
                throw new ArgumentException("accessToken.PublicToken");
            }

            IRestResponse<UserInfoResult> response;

            try
            {
                var restRequest = new RestRequest("/oauth2/v2/userinfo", Method.GET);
                restRequest.AddParameter(AccessTokenKey, accessToken.PublicToken);

                var restClient = RestClientFactory.CreateRestClient("https://www.googleapis.com");

                TraceSource.TraceVerbose("Retrieving user information. Google Endpoint: {0}",
                                         restClient.BuildUri(restRequest).AbsoluteUri);

                response = restClient.Execute<UserInfoResult>(restRequest);
            }
            catch (Exception exception)
            {
                var errorMessage =
                    string.Format("Failed to retrieve any UserInfo data from the Google Api. Error Messages: {0}",
                                  exception.RecursiveErrorMessages());
                TraceSource.TraceError(errorMessage);
                throw new AuthenticationException(errorMessage, exception);
            }

            if (response == null ||
                response.StatusCode != HttpStatusCode.OK)
            {
                var errorMessage = string.Format(
                    "Failed to obtain some UserInfo data from the Google Api OR the the response was not an HTTP Status 200 OK. Response Status: {0}. Response Description: {1}. Error Message: {2}.",
                    response == null ? "-- null response --" : response.StatusCode.ToString(),
                    response == null ? string.Empty : response.StatusDescription,
                    response == null
                        ? string.Empty
                        : response.ErrorException == null
                              ? "--no error exception--"
                              : response.ErrorException.RecursiveErrorMessages());

                TraceSource.TraceError(errorMessage);
                throw new AuthenticationException(errorMessage);
            }

            // Lets check to make sure we have some bare minimum data.
            if (string.IsNullOrEmpty(response.Data.Id))
            {
                const string errorMessage =
                    "We were unable to retrieve the User Id from Google API, the user may have denied the authorization.";
                TraceSource.TraceError(errorMessage);
                throw new AuthenticationException(errorMessage);
            }

            return new UserInformation
            {
                Id = response.Data.Id,
                Gender = string.IsNullOrEmpty(response.Data.Gender)
                             ? GenderType.Unknown
                             : GenderTypeHelpers.ToGenderType(response.Data.Gender),
                Name = response.Data.Name,
                Email = response.Data.Email,
                Locale = response.Data.Locale,
                Picture = response.Data.Picture,
                UserName = response.Data.GivenName
            };
        }

        #endregion

        public override IEnumerable<string> DefaultScopes
        {
            get
            {
                return new[]
                       {
                           "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
                       };
            }
        }
    }
}