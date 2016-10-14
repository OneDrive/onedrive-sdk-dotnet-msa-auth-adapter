# Authentication Adapter for the OneDrive SDK

This library makes it easy to to consume Microsoft account and Azure Active Directory authentication for the [OneDrive SDK](https://github.com/OneDrive/onedrive-sdk-csharp). It provides IAuthenticationProvider imlementations for Microsoft account OAuth and [ADAL](https://github.com/AzureAD/azure-activedirectory-library-for-dotnet) authentication.

The Authentication Adapter for the OneDrive SDK Library is built as a Portable Class Library. It targets the following frameworks:

* .NET 4.5+
* .NET for Windows Store apps
* Windows Phone 8.1 and higher

## Installation via NuGet

To install the client library via NuGet:

* Search for `Microsoft.OneDriveSdk.Authentication` in the NuGet Library, or
* Type `Install-Package Microsoft.OneDriveSdk.Authentication` into the Package Manager Console.

## Getting started

### 1. Register your application

Register your application to use Microsoft Graph API using one of the following
supported authentication portals:

* [Microsoft Application Registration Portal](https://apps.dev.microsoft.com):
  Register a new application that works with Microsoft Account and/or
  organizational accounts using the unified V2 Authentication Endpoint.
* [Microsoft Azure Active Directory](https://manage.windowsazure.com): Register
  a new application in your tenant's Active Directory to support work or school
  users for your tenant or multiple tenants.
  
### 2. Create a Microsoft account authentication provider

```csharp
var msaAuthenticationProvider = new MsaAuthenticationProvider(
        clientId,
        returnUrl,
        scopes);
```

The MsaAuthenticationProvider constructor has an overload that takes in client secret for platforms that support web clients.

If you are building a UWP app, you can leverage the user's signed-in account. Simply construct an `OnlineIdAuthenticationProvider`:

```csharp
var msaAuthenticationProvider = new OnlineIdAuthenticationProvider(scopes);
```

This type inherits from `MsaAuthenticationProvider` and behaves similarly. It will also refresh the user's token as needed.

#### Authenticate a user

```csharp
msaAuthenticationProvider.AuthenticateUserAsync();
```

AuthenticateUserAsync will perform the action of prompting the user with authentication UI.

### 2. Create an Azure Active Directory authentication provider

```csharp
var adalAuthenticationProvider = new AdalAuthenticationProvider(AccountSelection.AadClientId, AccountSelection.AadReturnUrl);
```

The AdalAuthenticationProvider constructor has an overload that takes in client secret or client certificate for platforms that support web clients.
The developer can also pass in an AuthenticationContext, in case the app is already using ADAL for authentication and would like to re-use their authentication context.

#### Look up service information for a user using Discovery Service

The DiscoveryServiceHelper is used to look up discovery service information for a user. It takes in an AdalAuthenticationProvider to authenticate the user for the discovery service endpoint.

```csharp
var discoveryServiceHelper = new DiscoveryServiceHelper(adalAuthenticationProvider);
var businessServiceInformation = await discoveryServiceHelper.DiscoverFilesEndpointInformationForUserAsync();
```

#### Authenticate a user, with possible UI prompt

```csharp
        await adalAuthenticationProvider.AuthenticateUserAsync(serviceResourceId);
```

#### Authenticate a user with refresh token

```csharp
        await adalAuthenticationProvider.AuthenticateUserWithRefreshTokenAsync(refreshToken, serviceResourceId);
```

serviceResourceId is optional when authenticating using a refresh token. If not provided, the access token will be granted for the resource that generated the refresh token.

#### Authenticate a user with an authorization code

```csharp
        await adalAuthenticationProvider.AuthenticateUserWithAuthorizationCodeAsync(authorizationCode, serviceResourceId);
```

serviceResourceId is optional when authenticating using an authorization code. If not provided, the access token will be granted for the resource that generated the code.

### 3. Create a Microsoft Graph client object with an authentication provider

```csharp
var client = new OneDriveClient(baseUrl, authenticationProvider);
```

### Cache sessions

MasAuthProvider can store sessions for re-use later. Make the following changes to take advantage of silent re-authentication:
1. When constructing `MsaAuthenticationProvider`, provide an instantiation of `ICredentialVault`. A default implementation is available in `CredentialVault`.
2. Instead of calling `AuthenticateAsync`, call `RestoreMostRecentFromCacheOrAuthenticateUserAsync` on the instance of `MsaAuthenticationProvider`.

```csharp
var msaAuthProvider = new MsaAuthenticationProvider(
    clientId,
    returnUrl,
    scopes,
    /*CredentialCache*/ null,
    new CredentialVault(clientId));
authTask = msaAuthProvider.RestoreMostRecentFromCacheOrAuthenticateUserAsync();
app.OneDriveClient = new OneDriveClient(this.oneDriveConsumerBaseUrl, msaAuthProvider);
```

This will store the session in a secure location (encrypted on disk with the user's context, so only the current user can decrypt), and also retrieve previous sessions.
If a previous session is found with a refresh token, then its redemption will be attempted before prompting the user to log in. If the refresh token is valid then the user
will not see authentication UI at all.

To clear out this cache, simply call `await MsaAuthenticationProvider.SignOutAsync()`. The contents of the cache will be deleted.

Note: CredentialVault is not necassary if you are using `OnlineIdAuthenticationProvider`.

## Documentation and resources


## Issues

To view or log issues, see [issues](https://github.com/OneDrive/onedrive-sdk-dotnet-msa-auth-adapter/issues).

## Other resources

* NuGet Package: [https://www.nuget.org/packages/Microsoft.OneDriveSdk.Authentication](https://www.nuget.org/packages/Microsoft.OneDriveSDK.Authentication/)


## License

Copyright (c) Microsoft Corporation. All Rights Reserved. Licensed under the MIT [license](LICENSE.txt)

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
