// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    public static class OAuthConstants
    {
        public const string AccessTokenKeyName = "access_token";

        public const string AuthenticationCancelled = "authentication_cancelled";

        public const string AuthorizationCodeGrantType = "authorization_code";

        public const string AuthorizationServiceKey = "authorization_service";

        public const string ClientIdKeyName = "client_id";

        public const string ClientSecretKeyName = "client_secret";

        public const string CodeKeyName = "code";

        public const string DiscoveryResourceKey = "discovery_resource";

        public const string DiscoveryServiceKey = "discovery_service";

        public const string ErrorDescriptionKeyName = "error_description";

        public const string ErrorKeyName = "error";
            
        public const string ExpiresInKeyName = "expires_in";

        public const string GrantTypeKeyName = "grant_type";

        public const string RedirectUriKeyName = "redirect_uri";

        public const string RefreshTokenKeyName = "refresh_token";

        public const string ResponseTypeKeyName = "response_type";

        public const string ScopeKeyName = "scope";

        public const string TokenResponseTypeValueName = "token";

        public const string TokenServiceKey = "token_service";

        public const string TokenTypeKeyName = "token_type";
            
        public const string UserIdKeyName = "user_id";

        internal const string MicrosoftAccountAuthenticationServiceUrl = "https://login.live.com/oauth20_authorize.srf";

        internal const string MicrosoftAccountSignOutUrl = "https://login.live.com/oauth20_logout.srf";

        internal const string MicrosoftAccountTokenServiceUrl = "https://login.live.com/oauth20_token.srf";

        public static class ErrorCodes
        {
            public const string AuthenticationCanceled = "authenticationCanceled";

            public const string AuthenticationFailure = "authenticationFailure";
        }
    }
}
