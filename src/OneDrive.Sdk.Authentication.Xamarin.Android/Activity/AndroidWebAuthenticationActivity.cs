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
            this.webView = FindViewById<WebView>(Resource.Id.webView);
            this.WebAuthenticationUi = GetWebAuthenticationUi();
            this.RequestUri = GetRequestUri();
            this.CallbackUri = GetCallbackUri();
            this.BeginLoadAuthorizationUrl();
        }

        public AndroidWebAuthenticationUi WebAuthenticationUi { get; private set; }

        private AndroidWebAuthenticationUi GetWebAuthenticationUi()
        {
            if (!Intent.HasExtra(AndroidConstants.AuthenticationStateKey))
                return null;
            string stateKey = Intent.GetStringExtra(AndroidConstants.AuthenticationStateKey);
            return AndroidAuthenticationState.Default.Remove<AndroidWebAuthenticationUi>(stateKey);
        }

        public Uri RequestUri { get; private set; }

        private Uri GetRequestUri()
        {
            if (!Intent.HasExtra(AndroidConstants.RequestUriKey))
                return null;
            return new Uri(Intent.GetStringExtra(AndroidConstants.RequestUriKey));
        }

        public Uri CallbackUri { get; private set; }

        private Uri GetCallbackUri()
        {
            if (!Intent.HasExtra(AndroidConstants.CallbackUriKey))
                return null;
            return new Uri(Intent.GetStringExtra(AndroidConstants.CallbackUriKey));
        }

        private void BeginLoadAuthorizationUrl()
        {
            Client client = new Client(this);
            this.webView.Settings.JavaScriptEnabled = true;
            this.webView.SetWebViewClient(client);
            this.webView.LoadUrl(RequestUri.ToString());
        }

        private void OnPageFinished(WebView view, string url)
        {
            Uri source = new Uri(url);
            if (source.AbsoluteUri.StartsWith(CallbackUri.ToString()))
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