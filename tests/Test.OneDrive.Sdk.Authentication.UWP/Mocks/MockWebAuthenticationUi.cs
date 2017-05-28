﻿// ------------------------------------------------------------------------------
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

namespace Test.OneDrive.Sdk.Authentication.UWP.Mocks
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Microsoft.OneDrive.Sdk.Authentication;

    public delegate void AuthenticateCallback(Uri requestUri, Uri callbackUri);

    public class MockWebAuthenticationUi : IWebAuthenticationUi
    {
        public IDictionary<string, string> responseValues = new Dictionary<string, string>();

        public AuthenticateCallback OnAuthenticateAsync { get; set; }

        public Task<IDictionary<string, string>> AuthenticateAsync(Uri requestUri, Uri callbackUri)
        {
            if (this.OnAuthenticateAsync != null)
            {
                this.OnAuthenticateAsync(requestUri, callbackUri);
            }

            return Task.FromResult(this.responseValues);
        }
    }
}
