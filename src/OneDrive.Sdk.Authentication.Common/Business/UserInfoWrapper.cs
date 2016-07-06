// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using System;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;

    public class UserInfoWrapper : IUserInfo
    {
        private UserInfo userInfo;

        public UserInfoWrapper(UserInfo userInfo)
        {
            this.userInfo = userInfo;
        }

        public string DisplayableId
        {
            get
            {
                return this.userInfo.DisplayableId;
            }
        }

        public string FamilyName
        {
            get
            {
                return this.userInfo.FamilyName;
            }
        }

        public string GivenName
        {
            get
            {
                return this.userInfo.GivenName;
            }
        }
        
        public string IdentityProvider
        {
            get
            {
                return this.userInfo.IdentityProvider;
            }
        }

        public Uri PasswordChangeUrl
        {
            get
            {
                return this.userInfo.PasswordChangeUrl;
            }
        }

        public DateTimeOffset? PasswordExpiresOn
        {
            get
            {
                return this.userInfo.PasswordExpiresOn;
            }
        }

        public string UniqueId
        {
            get
            {
                return this.userInfo.UniqueId;
            }
        }
    }
}
