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

        public Context Context { get; }

        public Task<IDictionary<string, string>> AuthenticateAsync(Uri requestUri, Uri callbackUri)
        {
            TaskCompletionSource<IDictionary<string, string>> tcs = new TaskCompletionSource<IDictionary<string, string>>();

            var handler = new AuthenticationResultHandler(this, tcs);

            this.Completed += handler.OnCompleted;
            this.Failed += handler.OnFailed;

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

        private sealed class AuthenticationResultHandler
        {
            private readonly AndroidWebAuthenticationUi _webAuthenticationUi;
            private readonly TaskCompletionSource<IDictionary<string, string>> _tcs;

            public AuthenticationResultHandler(AndroidWebAuthenticationUi webAuthenticationUi, TaskCompletionSource<IDictionary<string, string>> tcs)
            {
                _webAuthenticationUi = webAuthenticationUi;
                _tcs = tcs;
            }

            public void OnCompleted(object sender, AuthCompletedEventArgs e)
            {
                _webAuthenticationUi.Completed -= OnCompleted; // unsubscribe

                _tcs.SetResult(e.AuthorizationParameters);
            }

            public void OnFailed(object sender, AuthFailedEventArgs e)
            {
                _webAuthenticationUi.Failed -= OnFailed; // unsubscribe

                _tcs.SetException(e.Error);
            }
        }
    }
}