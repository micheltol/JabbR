using System;
using WorldDomination.Web.Authentication;

namespace Jabbr.AuthenticationProviders
{
    public class GoogleInMotivProviderAuthenticationServiceSettings : BaseAuthenticationServiceSettings
    {
        public String DomainName {
            get { return "inmotiv.net"; }
        }
        public GoogleInMotivProviderAuthenticationServiceSettings(string keyName) : base(keyName) { }
    }
}