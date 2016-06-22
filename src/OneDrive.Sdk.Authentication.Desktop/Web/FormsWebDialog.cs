// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.Drawing;
    using System.Threading.Tasks;
    using System.Windows.Forms;

    using Microsoft.Graph;

    public class FormsWebDialog : Form
    {
        private WebBrowser webBrowser;
        private IDictionary<string, string> authenticationResponseValues = null;

        public Uri RequestUri { get; private set; }

        public Uri CallbackUri { get; private set; }

        public Point UIWidth { get; private set; }

        public FormsWebDialog()
        {
            this.InitializeComponent();
        }

        public async Task<IDictionary<string, string>> GetAuthenticationResponseValues(Uri requestUri, Uri callbackUri)
        {
            if (this.webBrowser.IsDisposed)
            {
                // Fail out gracefully if browser is disposed
                return null;
            }

            bool isSignOutRequest =
                requestUri.AbsoluteUri.StartsWith(OAuthConstants.MicrosoftAccountSignOutUrl,
                    StringComparison.OrdinalIgnoreCase);

            this.ShowInTaskbar = !isSignOutRequest;
            this.WindowState = isSignOutRequest ? FormWindowState.Minimized : FormWindowState.Normal;

            this.RequestUri = requestUri;
            this.CallbackUri = callbackUri;

            this.webBrowser.Navigate(requestUri);
            await this.ShowDialogAsync();

            if (this.authenticationResponseValues == null)
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = "authenticationCanceled",
                        Message = "User canceled authentication."
                    });
            }

            return this.authenticationResponseValues;
        }

        private void InitializeComponent()
        {
            this.webBrowser = new System.Windows.Forms.WebBrowser();
            this.SuspendLayout();
            // 
            // webBrowser
            // 
            this.webBrowser.Dock = System.Windows.Forms.DockStyle.Fill;
            this.webBrowser.Location = new System.Drawing.Point(0, 0);
            this.webBrowser.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.webBrowser.MinimumSize = new System.Drawing.Size(13, 13);
            this.webBrowser.Name = "webBrowser";
            this.webBrowser.Size = new System.Drawing.Size(484, 511);
            this.webBrowser.TabIndex = 0;
            this.webBrowser.Navigated += new System.Windows.Forms.WebBrowserNavigatedEventHandler(this.OnNavigated);
            this.webBrowser.Navigating += new System.Windows.Forms.WebBrowserNavigatingEventHandler(this.OnNavigating);
            // 
            // FormsWebDialog
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(484, 511);
            this.Controls.Add(this.webBrowser);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "FormsWebDialog";
            this.ShowIcon = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.ResumeLayout(false);

        }

        public void OnNavigated(object sender, WebBrowserNavigatedEventArgs e)
        {
            if (this.webBrowser.IsDisposed)
            {
                // If the browser is disposed, just cancel out gracefully
                return;
            }

            if (this.NavigatedToCallbackUri(e.Url))
            {
                this.authenticationResponseValues = UrlHelper.GetQueryOptions(e.Url);
                this.Close();
            }
        }

        public void OnNavigating(object sender, WebBrowserNavigatingEventArgs e)
        {
            if (this.webBrowser.IsDisposed)
            {
                // If the browser is disposed, just cancel out gracefully
                return;
            }

            if (this.NavigatedToCallbackUri(e.Url))
            {
                e.Cancel = true;
                this.authenticationResponseValues = UrlHelper.GetQueryOptions(e.Url);
                this.Close();
            }
        }

        private bool NavigatedToCallbackUri(Uri url)
        {
            return url.Authority.Equals(
                this.CallbackUri.Authority, StringComparison.OrdinalIgnoreCase)
                    && url.AbsolutePath.Equals(this.CallbackUri.AbsolutePath);
        }

        public Task<DialogResult> ShowDialogAsync()
        {
            TaskCompletionSource<DialogResult> tcs = new TaskCompletionSource<DialogResult>();
            this.FormClosed += (s, e) =>
            {
                tcs.SetResult(this.DialogResult);
            };

            this.Show();
            
            return tcs.Task;
        }
    }
}
