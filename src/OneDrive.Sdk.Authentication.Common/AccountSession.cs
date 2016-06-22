// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.Net;

    public class AccountSession
    {
        public AccountSession()
        {
        }

        public AccountSession(IDictionary<string, string> authenticationResponseValues, string clientId = null)
        {
            this.ClientId = clientId;

            this.ParseAuthenticationResponseValues(authenticationResponseValues);
        }

        public string AccessToken { get; set; }

        public string AccessTokenType { get; set; }

        public string ClientId { get; set; }

        public DateTimeOffset ExpiresOnUtc { get; set; }

        public string RefreshToken { get; set; }

        public string[] Scopes { get; set; }

        public string UserId { get; set; }

        public bool CanRefresh
        {
            get
            {
                return !string.IsNullOrEmpty(this.RefreshToken);
            }
        }

        public bool IsExpiring
        {
            get
            {
                return this.ExpiresOnUtc <= DateTimeOffset.Now.UtcDateTime.AddMinutes(5);
            }
        }

        public bool ShouldRefresh
        {
            get
            {
                return string.IsNullOrEmpty(this.AccessToken) || this.IsExpiring;
            }
        }

        private void ParseAuthenticationResponseValues(IDictionary<string, string> authenticationResponseValues)
        {
            if (authenticationResponseValues != null)
            {
                foreach (var value in authenticationResponseValues)
                {
                    switch (value.Key)
                    {
                        case OAuthConstants.AccessTokenKeyName:
                            this.AccessToken = value.Value;
                            break;
                        case OAuthConstants.ExpiresInKeyName:
                            this.ExpiresOnUtc = DateTimeOffset.UtcNow.Add(new TimeSpan(0, 0, int.Parse(value.Value)));
                            break;
                        case OAuthConstants.ScopeKeyName:
                            var decodedScopes = WebUtility.UrlDecode(value.Value);
                            this.Scopes = string.IsNullOrEmpty(decodedScopes) ? null : decodedScopes.Split(' ');
                            break;
                        case OAuthConstants.UserIdKeyName:
                            this.UserId = value.Value;
                            break;
                        case OAuthConstants.RefreshTokenKeyName:
                            this.RefreshToken = value.Value;
                            break;
                    }
                }
            }
        }
    }
}
