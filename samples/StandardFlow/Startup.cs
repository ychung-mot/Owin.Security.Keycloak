﻿using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Keycloak;
using System;

[assembly: OwinStartup(typeof(StandardFlow.Startup))]
namespace StandardFlow
{
	public class Startup
	{
		const string persistentAuthType = "keycloak_cookies"; // Or name it whatever you want
		public void Configuration(IAppBuilder app)
		{
			app.UseCookieAuthentication(new CookieAuthenticationOptions
			{
				AuthenticationType = persistentAuthType
			});

			// You may also use this method if you have multiple authentication methods below,
			// or if you just like it better:
			app.SetDefaultSignInAsAuthenticationType(persistentAuthType);

			app.UseJwtBearerAuthentication

			app.UseKeycloakAuthentication(new KeycloakAuthenticationOptions
			{
				Realm = "onestopauth-business",
				ClientId = "hets",
				//ClientSecret = "8eb92690-8c0c-42ba-b1ac-106dd2d06a22",
				KeycloakUrl = "http://localhost:9030/auth",
				AuthenticationType = persistentAuthType,
				SignInAsAuthenticationType = persistentAuthType,
				//Token validation options - these are all set to defaults
				AllowUnsignedTokens = false,
				DisableIssuerSigningKeyValidation = false,
				DisableIssuerValidation = false,
				DisableAudienceValidation = true,
				TokenClockSkew = TimeSpan.FromSeconds(2),				
			});
		}
	}
}