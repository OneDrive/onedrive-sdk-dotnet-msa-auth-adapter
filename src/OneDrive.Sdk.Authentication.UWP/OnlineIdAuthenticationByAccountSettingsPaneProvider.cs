// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.OneDrive.Sdk.Authentication;
using Windows.Security.Authentication.OnlineId;
using Microsoft.Graph;
using Windows.Security.Credentials;
using Windows.Security.Authentication.Web.Core;
using Windows.UI.ApplicationSettings;
using Yinyue200.OperationDeferral;
using Windows.Storage;

namespace Microsoft.OneDrive.Sdk
{
    public class OnlineIdAuthenticationByAccountSettingsPaneProvider : OnlineIdAuthenticationProvider
    {
        const string paswordres = "OneDriveSDK_AuthAdapter_AccountSettingsPane";
        public OnlineIdAuthenticationByAccountSettingsPaneProvider(string[] scopes, PromptType promptType = PromptType.PromptIfNeeded) : base(scopes, promptType)
        {
        }
        public async override Task SignOutAsync()
        {
            await base.SignOutAsync();
            ApplicationData.Current.LocalSettings.DeleteContainer(paswordres);
            await Account?.SignOutAsync();
        }

        WebAccount Account { get; set; }
        private async Task<string> GetTokenSilentlyAsync(string providerId, string accountId)
        {
            if (null == providerId || null == accountId)
            {
                return null;
            }

            WebAccountProvider provider = await WebAuthenticationCoreManager.FindAccountProviderAsync(providerId);
            Account = await WebAuthenticationCoreManager.FindAccountAsync(provider, accountId);

            WebTokenRequest request = new WebTokenRequest(provider, string.Join(" ", this.scopes));

            WebTokenRequestResult result = await WebAuthenticationCoreManager.GetTokenSilentlyAsync(request, Account);
            if (result.ResponseStatus == WebTokenRequestStatus.UserInteractionRequired)
            {
                // Unable to get a token silently - you'll need to show the UI
                return null;
            }
            else if (result.ResponseStatus == WebTokenRequestStatus.Success)
            {
                // Success
                return result.ResponseData[0].Token;
            }
            else
            {
                // Other error 
                return null;
            }
        }
        OperationDeferral<string> od;
        private async Task<string> GetTokenByUIAsync()
        {
            try
            {
                od = new OperationDeferral<string>();
                AccountsSettingsPane.GetForCurrentView().AccountCommandsRequested += BuildPaneAsync;
                AccountsSettingsPane.Show();
                return await od.WaitOneAsync();
            }
            finally
            {
                AccountsSettingsPane.GetForCurrentView().AccountCommandsRequested -= BuildPaneAsync;
            }


        }

        private async void BuildPaneAsync(AccountsSettingsPane sender, AccountsSettingsPaneCommandsRequestedEventArgs args)
        {
            var deferral = args.GetDeferral();

            var msaProvider = await WebAuthenticationCoreManager.FindAccountProviderAsync(
                "https://login.microsoft.com", "consumers");

            var command = new WebAccountProviderCommand(msaProvider, GetMsaTokenAsync);

            args.WebAccountProviderCommands.Add(command);

            deferral.Complete();
        }
        private async void GetMsaTokenAsync(WebAccountProviderCommand command)
        {
            WebTokenRequest request = new WebTokenRequest(command.WebAccountProvider, string.Join(" ", this.scopes));
            WebTokenRequestResult result = await WebAuthenticationCoreManager.RequestTokenAsync(request);

            if (result.ResponseStatus == WebTokenRequestStatus.Success)
            {
                Account = result.ResponseData[0].WebAccount;
                string token = result.ResponseData[0].Token;
                od.Complete(token);
            }
            else
            {
                od.Complete(null);
            }
        }

        protected async override Task<AccountSession> GetAccountSessionAsync()
        {
            try
            {
                object proid;
                object userid = null;
                string key = null;
                if(ApplicationData.Current.LocalSettings.CreateContainer(paswordres,ApplicationDataCreateDisposition.Always).Values.TryGetValue("proid", out proid))
                {
                    if (ApplicationData.Current.LocalSettings.Containers[paswordres].Values.TryGetValue("userid", out userid))
                        key = await GetTokenSilentlyAsync(proid?.ToString(), userid?.ToString());
                }
                if (key == null)
                {
                    key = await GetTokenByUIAsync();
                    if(key!=null)
                    {
                        try
                        {
                            ApplicationData.Current.LocalSettings.Containers[paswordres].Values["proid"] = Account.WebAccountProvider.Id;
                            ApplicationData.Current.LocalSettings.Containers[paswordres].Values["userid"] = Account.Id;
                            userid = Account.Id;
                        }
                        catch { }
                    }
                }
                if(key==null)
                {
                    throw new Exception("failed to get token");
                }
                var accountSession = new AccountSession
                {
                    AccessToken = key,
                    ExpiresOnUtc = DateTimeOffset.UtcNow.AddMinutes(this.ticketExpirationTimeInMinutes),
                    ClientId = this.authenticator.ApplicationId.ToString(),
                    UserId = userid.ToString()
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
    }
}
