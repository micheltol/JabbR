namespace JabbR.Services
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using WorldDomination.Web.Authentication;

    public interface IValidatorUserInformationService
    {
        Boolean Validate(UserInformation userInformation);

    }


    public class ValidatorUserInformationService : IValidatorUserInformationService
    {
        private readonly List<string> _validEmailSuffix; 

        public ValidatorUserInformationService(IJabbrConfiguration configurationService)
        {
            _validEmailSuffix = new List<string>(configurationService.ValidEmailSuffix);

        }

        public bool Validate(UserInformation userInformation)
        {
            return _validEmailSuffix.Any(validEmailSuffix => userInformation.Email.EndsWith(validEmailSuffix,StringComparison.InvariantCultureIgnoreCase));
        }
    }
}