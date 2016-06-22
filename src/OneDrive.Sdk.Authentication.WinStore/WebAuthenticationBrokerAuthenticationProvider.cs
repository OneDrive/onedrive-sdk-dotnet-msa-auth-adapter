// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Net;
    using System.Text;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    using Windows.Security.Authentication.Web;

    public class WebAuthenticationBrokerAuthenticationProvider : AuthenticationProvider
    {
        private readonly string appId;
        private readonly string returnUrl;
        private readonly string[] scopes;
        
        public WebAuthenticationBrokerAuthenticationProvider(string appId, string returnUrl, string[] scopes)
        {
            this.appId = appId;

            this.returnUrl = string.IsNullOrEmpty(returnUrl)
                ? WebAuthenticationBroker.GetCurrentApplicationCallbackUri().ToString()
                : returnUrl;

            this.scopes = scopes;
        }

        internal async Task<AccountSession> GetAccountSessionAsync()
        {
            // Log the user in if we haven't already pulled their credentials from the cache.
            var code = await this.GetAuthorizationCodeAsync(returnUrl);

            if (!string.IsNullOrEmpty(code))
            {
                var authResult = await this.SendTokenRequestAsync(this.GetCodeRedemptionRequestBody(code, returnUrl));
                authResult.CanSignOut = true;

                return authResult;
            }

            return null;
        }
    }
}
