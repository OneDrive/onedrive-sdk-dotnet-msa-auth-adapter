// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using Android.App;
    using Android.Content;
    using Android.OS;
    using Android.Content.PM;
    using Android.Webkit;
    using Graph;
    using Android.Views;

    [Activity(Label = "OneDrive", Theme = "@android:style/Theme.NoTitleBar", ScreenOrientation = ScreenOrientation.Portrait)]
    public class AndroidWebAuthenticationActivity : Activity
    {
        private WebView webView;

        protected override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);
            base.SetContentView(Resource.Layout.webform);
            this.webView = base.FindViewById<WebView>(Resource.Id.webView);
            this.WebAuthenticationUi = this.GetWebAuthenticationUi();
            this.RequestUri = this.GetRequestUri();
            this.CallbackUri = this.GetCallbackUri();
            this.BeginLoadAuthorizationUrl();
        }

        public AndroidWebAuthenticationUi WebAuthenticationUi { get; private set; }

        private AndroidWebAuthenticationUi GetWebAuthenticationUi()
        {
            if (!base.Intent.HasExtra(AndroidConstants.AuthenticationStateKey))
            {
                return null;
            }

            string stateKey = base.Intent.GetStringExtra(AndroidConstants.AuthenticationStateKey);
            return AndroidAuthenticationState.Default.Remove<AndroidWebAuthenticationUi>(stateKey);
        }

        public Uri RequestUri { get; private set; }

        private Uri GetRequestUri()
        {
            if (!base.Intent.HasExtra(AndroidConstants.RequestUriKey))
            {
                return null;
            }

            return new Uri(base.Intent.GetStringExtra(AndroidConstants.RequestUriKey));
        }

        public Uri CallbackUri { get; private set; }

        private Uri GetCallbackUri()
        {
            if (!base.Intent.HasExtra(AndroidConstants.CallbackUriKey))
            {
                return null;
            }

            return new Uri(base.Intent.GetStringExtra(AndroidConstants.CallbackUriKey));
        }

        private void BeginLoadAuthorizationUrl()
        {
            Client client = new Client(this);
            this.webView.Settings.JavaScriptEnabled = true;
            this.webView.SetWebViewClient(client);
            this.webView.LoadUrl(this.RequestUri.ToString());
        }

        private void OnPageFinished(WebView view, string url)
        {
            Uri source = new Uri(url);
            if (source.AbsoluteUri.StartsWith(this.CallbackUri.ToString()))
            {
                var parameters = UrlHelper.GetQueryOptions(source);
                this.WebAuthenticationUi.OnCompleted(new AuthCompletedEventArgs(parameters));
                base.Finish();
            }
        }

        public override void OnBackPressed()
        {
            this.WebAuthenticationUi.OnFailed(
                new AuthFailedEventArgs(
                    new ServiceException(
                        new Error
                        {
                            Code = "authenticationCanceled",
                            Message = "User canceled authentication."
                        })));

            base.OnBackPressed();
        }

        private class Client : WebViewClient
        {
            private AndroidWebAuthenticationActivity activity;

            public Client(AndroidWebAuthenticationActivity activity)
            {
                this.activity = activity;
            }

            public override bool ShouldOverrideUrlLoading(WebView view, IWebResourceRequest request)
            {
                return false;
            }

            public override void OnPageFinished(WebView view, string url)
            {
                this.activity.OnPageFinished(view, url);
                base.OnPageFinished(view, url);
            }
        }
    }
}