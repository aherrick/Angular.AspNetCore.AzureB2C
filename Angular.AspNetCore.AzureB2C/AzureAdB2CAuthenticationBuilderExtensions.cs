using AToMS.Data.Models.AzureB2C;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Threading.Tasks;

// TODO: XML doc throughout.
namespace Microsoft.AspNetCore.Authentication
{
	public static class AzureAdB2CAuthenticationBuilderExtensions
	{
		public static AuthenticationBuilder AddAzureAdB2C(this AuthenticationBuilder builder)
			=> builder.AddAzureAdB2C(_ => { });

		/// <summary>
		/// Add Azure Active Directory B2C to builder.
		/// </summary>
		/// <param name="builder">The authentication builder.</param>
		/// <param name="configureOptions">The Azure Active Directory B2C configure options.</param>
		/// <returns>The updated builder.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="builder"/> is <c>null</c>.</exception>
		public static AuthenticationBuilder AddAzureAdB2C(this AuthenticationBuilder builder, Action<AzureAdB2COptions> configureOptions)
		{
			if (builder == null)
			{
				throw new ArgumentNullException(nameof(builder));
			}

			builder.Services.Configure(configureOptions);
			builder.Services.AddSingleton<IConfigureOptions<OpenIdConnectOptions>, ConfigureAzureOptions>();
			builder.AddOpenIdConnect();

			return builder;
		}

		// TODO: Separate class into its own file
		private class ConfigureAzureOptions : IConfigureNamedOptions<OpenIdConnectOptions>
		{
			private readonly AzureAdB2COptions azureOptions;

			public ConfigureAzureOptions(IOptions<AzureAdB2COptions> azureOptions)
			{
				this.azureOptions = azureOptions.Value;
			}

			public void Configure(string name, OpenIdConnectOptions options)
			{
				options.ClientId = azureOptions.ClientId;
				options.Authority = $"{azureOptions.Instance}/{azureOptions.Domain}/{azureOptions.SignUpSignInPolicyId}/v2.0";
				options.UseTokenLifetime = true;
				options.CallbackPath = azureOptions.CallbackPath;
				options.TokenValidationParameters = new TokenValidationParameters { NameClaimType = "name" };

				options.Events = new OpenIdConnectEvents
				{
					OnRedirectToIdentityProvider = OnRedirectToIdentityProvider,
					OnRemoteFailure = OnRemoteFailure
				};
			}

			public void Configure(OpenIdConnectOptions options)
			{
				Configure(Options.DefaultName, options);
			}

			public Task OnRedirectToIdentityProvider(RedirectContext context)
			{
				var defaultPolicy = azureOptions.DefaultPolicy;

				if (context.Properties.Items.TryGetValue(AzureAdB2COptions.PolicyAuthenticationProperty, out var policy)
					&& !policy.Equals(defaultPolicy))
				{
					context.ProtocolMessage.Scope = OpenIdConnectScope.OpenIdProfile;
					context.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
					context.ProtocolMessage.IssuerAddress = context.ProtocolMessage.IssuerAddress.ToLower()
						.Replace($"/{defaultPolicy.ToLower()}/", $"/{policy.ToLower()}/");
					context.Properties.Items.Remove(AzureAdB2COptions.PolicyAuthenticationProperty);
				}

				return Task.CompletedTask;
			}

			public async Task<Task> OnRemoteFailure(RemoteFailureContext context)
			{
				context.HandleResponse();

				// Handle the error code that Azure AD B2C throws when trying to reset a password
				// from the login page because password reset is not supported by a "sign-up or
				// sign-in policy"
				if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("AADB2C90118"))
				{
					// If the user clicked the reset password link, redirect to the reset password route
					var authProp = new AuthenticationProperties() { RedirectUri = "/" };
					authProp.Items[AzureAdB2COptions.PolicyAuthenticationProperty] = azureOptions.ResetPasswordPolicyId;

					await context.HttpContext.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, authProp);
				}
				else if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("access_denied"))
				{
					context.Response.Redirect("/");
				}
				else
				{
					context.Response.Redirect("/Home/Error");
				}

				return Task.CompletedTask;
			}
		}
	}
}