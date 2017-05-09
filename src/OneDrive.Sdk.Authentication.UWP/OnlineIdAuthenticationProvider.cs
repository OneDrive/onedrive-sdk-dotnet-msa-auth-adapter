// ------------------------------------------------------------------------------
//  Copyright (c) 2015 Microsoft Corporation
// 
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
// 
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
// 
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk
{
    using Microsoft.Graph;
    using Microsoft.OneDrive.Sdk.Authentication;

    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Windows.Security.Authentication.OnlineId;

    public class OnlineIdAuthenticationProvider : MsaAuthenticationProvider
    {
        private const string onlineIdServiceTicketRequestType = "DELEGATION";
        private readonly int ticketExpirationTimeInMinutes = 60;
        private readonly OnlineIdAuthenticator authenticator;
        private readonly CredentialPromptType credentialPromptType;

        public enum PromptType
        {
            PromptIfNeeded = CredentialPromptType.PromptIfNeeded,
            RetypeCredentials = CredentialPromptType.RetypeCredentials,
            DoNotPrompt = CredentialPromptType.DoNotPrompt
        }

        public OnlineIdAuthenticationProvider(
            string[] scopes, PromptType promptType = PromptType.PromptIfNeeded)
            :base(null, null, scopes)
        {
            this.authenticator = new OnlineIdAuthenticator();
            this.credentialPromptType = (CredentialPromptType)promptType;
        }

        public override async Task AuthenticateUserAsync(IHttpProvider httpProvider, string userName = null)
        {
            var authResult = await this.GetAuthenticationResultFromCacheAsync(userName, httpProvider);

            if (authResult == null)
            {
                authResult = await this.GetAccountSessionAsync();

                if (string.IsNullOrEmpty(authResult?.AccessToken))
                {
                    throw new ServiceException(
                        new Error
                        {
                            Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                            Message = "Failed to retrieve a valid authentication token for the user."
                        });
                }
            }
            
            this.CacheAuthResult(authResult);
        }

        /// <summary>
        /// Signs the current user out.
        /// </summary>
        public override async Task SignOutAsync()
        {
            if (this.IsAuthenticated)
            {
                if (this.authenticator.CanSignOut)
                {
                    await this.authenticator.SignOutUserAsync();
                }                

                this.DeleteUserCredentialsFromCache(this.CurrentAccountSession);
                this.CurrentAccountSession = null;
            }
        }

        internal async Task<AccountSession> GetAccountSessionAsync()
        {
            try
            {
                var serviceTicketRequest = new OnlineIdServiceTicketRequest(string.Join(" ", this.scopes), onlineIdServiceTicketRequestType);
                var ticketRequests = new List<OnlineIdServiceTicketRequest> { serviceTicketRequest };
                var authenticationResponse = await this.authenticator.AuthenticateUserAsync(ticketRequests, credentialPromptType);

                var ticket = authenticationResponse.Tickets.FirstOrDefault();

                if (string.IsNullOrEmpty(ticket?.Value))
                {
                    throw new ServiceException(
                        new Error
                        {
                            Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                            Message = string.Format(
                                "Failed to retrieve a valid authentication token from OnlineIdAuthenticator for user {0}.",
                                authenticationResponse.SignInName)
                        });
                }

                var accountSession = new AccountSession
                {
                    AccessToken = string.IsNullOrEmpty(ticket.Value) ? null : ticket.Value,
                    ExpiresOnUtc = DateTimeOffset.UtcNow.AddMinutes(this.ticketExpirationTimeInMinutes),
                    ClientId = this.authenticator.ApplicationId.ToString(),
                    UserId = authenticationResponse.SafeCustomerId
                };

                return accountSession;
            }
            catch (TaskCanceledException taskCanceledException)
            {
                throw new ServiceException(new Error { Code = OAuthConstants.ErrorCodes.AuthenticationCancelled, Message = "Authentication was canceled." }, taskCanceledException);
            }
            catch (Exception exception)
            {
                throw new ServiceException(new Error { Code = OAuthConstants.ErrorCodes.AuthenticationFailure, Message = exception.Message }, exception);
            }
        }

        internal override async Task<AccountSession> ProcessCachedAccountSessionAsync(AccountSession accountSession, IHttpProvider httpProvider)
        {
            if (accountSession != null)
            {
                if (accountSession.ShouldRefresh) // Don't check 'CanRefresh' because this type can always refresh
                {
                    accountSession = await this.GetAccountSessionAsync();
                    
                    if (!string.IsNullOrEmpty(accountSession?.AccessToken))
                    {
                        return accountSession;
                    }
                }
                else
                {
                    return accountSession;
                }
            }

            return null;
        }
    }
}
