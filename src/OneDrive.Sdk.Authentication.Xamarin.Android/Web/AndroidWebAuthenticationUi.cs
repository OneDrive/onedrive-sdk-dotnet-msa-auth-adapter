// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using Android.Content;

    public class AndroidWebAuthenticationUi : IWebAuthenticationUi
    {
        public event EventHandler<AuthCompletedEventArgs> Completed;
        public event EventHandler<AuthFailedEventArgs> Failed;

        public AndroidWebAuthenticationUi(Context context)
        {
            this.Context = context;
        }

        public Context Context { get; private set; }

        public Task<IDictionary<string, string>> AuthenticateAsync(Uri requestUri, Uri callbackUri)
        {
            TaskCompletionSource<IDictionary<string, string>> tcs = new TaskCompletionSource<IDictionary<string, string>>();

            this.Completed += (s, e) =>
            {
                tcs.SetResult(e.AuthorizationParameters);
            };

            this.Failed += (s, e) =>
            {
                tcs.SetException(e.Error);
            };

            string stateKey = AndroidAuthenticationState.Default.Add<AndroidWebAuthenticationUi>(this);
            Intent intent = new Intent(this.Context, typeof(AndroidWebAuthenticationActivity));
            intent.PutExtra(AndroidConstants.AuthenticationStateKey, stateKey);
            intent.PutExtra(AndroidConstants.RequestUriKey, requestUri.ToString());
            intent.PutExtra(AndroidConstants.CallbackUriKey, callbackUri.ToString());
            this.Context.StartActivity(intent);
            return tcs.Task;
        }

        internal void OnCompleted(AuthCompletedEventArgs e)
        {
            if (Completed != null)
            {
                Completed(this, e);
            }
        }

        internal void OnFailed(AuthFailedEventArgs e)
        {
            if (Failed != null)
            {
                Failed(this, e);
            }
        }
    }
}