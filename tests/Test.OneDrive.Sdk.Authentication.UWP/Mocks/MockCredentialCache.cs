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
    using Microsoft.OneDrive.Sdk.Authentication;

    public class MockCredentialCache : CredentialCache
    {
        public bool AddToCacheCalled { get; set; }

        public bool DeleteFromCacheCalled { get; set; }

        public bool GetResultFromCacheCalled { get; set; }

        internal override void AddToCache(AccountSession accountSession)
        {
            this.AddToCacheCalled = true;
            base.AddToCache(accountSession);
        }

        internal override void DeleteFromCache(AccountSession accountSession)
        {
            this.DeleteFromCacheCalled = true;
            base.DeleteFromCache(accountSession);
        }

        internal override AccountSession GetResultFromCache(string clientId, string userId)
        {
            this.GetResultFromCacheCalled = true;
            return base.GetResultFromCache(clientId, userId);
        }
    }
}
