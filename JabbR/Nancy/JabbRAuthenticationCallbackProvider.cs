using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.RegularExpressions;

using JabbR.Services;
using Nancy;
using Nancy.SimpleAuthentication;
using SimpleAuthentication.Core;

namespace JabbR.Nancy
{
    public class JabbRAuthenticationCallbackProvider : IAuthenticationCallbackProvider
    {
        private readonly IJabbrRepository repository;
        private readonly IValidatorUserInformationService validatorUserInformationService;

        public JabbRAuthenticationCallbackProvider(IJabbrRepository repository,IValidatorUserInformationService validatorUserInformationService)
        {
            this.repository = repository;
            this.validatorUserInformationService = validatorUserInformationService;
        }

        public dynamic Process(NancyModule nancyModule, AuthenticateCallbackData model)
        {
            Response response;

            if (model.ReturnUrl != null)
            {
                response = nancyModule.Response.AsRedirect("~" + model.ReturnUrl);
            }
            else
            {
                response = nancyModule.AsRedirectQueryStringOrDefault("~/");

                if (nancyModule.IsAuthenticated())
                {
                    response = nancyModule.AsRedirectQueryStringOrDefault("~/account/#identityProviders");
                }
            }

            if (model.Exception != null)
            {
                nancyModule.Request.AddAlertMessage("error", model.Exception.Message);
            }
            else
            {
                var information = model.AuthenticatedClient.UserInformation;
                
                //Exra custom validation to check if the user has a specific domainname.
                if (!validatorUserInformationService.Validate(information))
                {
                    nancyModule.SignOut();
                    return response;
                }

                var claims = new List<Claim>
                                 {
                                     new Claim(ClaimTypes.NameIdentifier, information.Id),
                                     new Claim(
                                         ClaimTypes.AuthenticationMethod,
                                         model.AuthenticatedClient.ProviderName)
                                 };

                if (!String.IsNullOrEmpty(information.UserName))
                {
                    claims.Add(new Claim(ClaimTypes.Name, information.UserName));
                }

                if (!String.IsNullOrEmpty(information.Email))
                {
                    claims.Add(new Claim(ClaimTypes.Email, information.Email));
                }

                nancyModule.SignIn(claims);
            }

            return response;
        }

        public dynamic OnRedirectToAuthenticationProviderError(NancyModule nancyModule, string errorMessage)
        {
            return null;
        }
    }
}
