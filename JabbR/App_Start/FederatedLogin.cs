﻿using System;
using System.Configuration;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Web;
using System.Web.Util;
using Microsoft.IdentityModel.Protocols.WSFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Web;
using Microsoft.Web.Infrastructure.DynamicModuleHelper;
using Ninject;
using JabbR.Services;

[assembly: WebActivator.PostApplicationStartMethod(typeof(JabbR.App_Start.FederatedLogin), "PostAppStart")]
[assembly: WebActivator.PreApplicationStartMethod(typeof(JabbR.App_Start.FederatedLogin), "PreAppStart", Order = 1)]

namespace JabbR.App_Start
{
    public static partial class FederatedLogin
    {
        public static void PreAppStart()
        {
            var settings = Bootstrapper.Kernel.Get<IApplicationSettings>();

            if (!string.IsNullOrEmpty(settings.FedAuthIdentityProviderUrl))
            {
                DynamicModuleUtility.RegisterModule(typeof(NoConfigWSFederationAuthenticationModule));
                DynamicModuleUtility.RegisterModule(typeof(NoConfigSessionAuthenticationModule));
            }
        }

        public static void PostAppStart()
        {
            var settings = Bootstrapper.Kernel.Get<IApplicationSettings>();

            if (!string.IsNullOrEmpty(settings.FedAuthIdentityProviderUrl))
            {
                FederatedAuthentication.ServiceConfiguration.AudienceRestriction.AllowedAudienceUris.Add(new Uri(settings.FedAuthRealm));
                FederatedAuthentication.ServiceConfiguration.SecurityTokenHandlers.Configuration.CertificateValidator = X509CertificateValidator.None;
                FederatedAuthentication.ServiceConfiguration.SecurityTokenHandlers.Configuration.IssuerNameRegistry = new SimpleIssuerNameRegistry(settings.FedAuthCertificateThumbprint);
            }
        }


        private partial class NoConfigWSFederationAuthenticationModule : WSFederationAuthenticationModule
        {
            protected override void InitializePropertiesFromConfiguration(string serviceName)
            {
                var settings = Bootstrapper.Kernel.Get<IApplicationSettings>();

                this.Realm = settings.FedAuthRealm;
                this.Issuer = settings.FedAuthIdentityProviderUrl;
                // if not using the idp selector, redirect straight to idp if not authenticated
                this.PassiveRedirectEnabled = !settings.FedAuthWindowsAzureActiveDirectorySelectorEnabled; 
                this.RequireHttps = settings.FedAuthRequiresSsl;
            }
        }

        private class NoConfigSessionAuthenticationModule : SessionAuthenticationModule
        {
            protected override void InitializePropertiesFromConfiguration(string serviceName)
            {
                var settings = Bootstrapper.Kernel.Get<IApplicationSettings>();

                this.CookieHandler.RequireSsl = settings.FedAuthRequiresSsl;
            }
        }

        private class SimpleIssuerNameRegistry : IssuerNameRegistry
        {
            private readonly string trustedThumbrpint;

            public SimpleIssuerNameRegistry(string trustedThumbprint)
            {
                this.trustedThumbrpint = trustedThumbprint;
            }

            public override string GetIssuerName(System.IdentityModel.Tokens.SecurityToken securityToken)
            {
                var x509 = securityToken as X509SecurityToken;
                if (x509 != null)
                {
                    if (x509.Certificate.Thumbprint.Equals(trustedThumbrpint, StringComparison.OrdinalIgnoreCase))
                    {
                        return x509.Certificate.Subject;
                    }
                }

                return null;
            }
        }

        public class AllowTokenPostRequestValidator : RequestValidator
        {
            protected override bool IsValidRequestString(HttpContext context, string value,
                                                         RequestValidationSource requestValidationSource,
                                                         string collectionKey, out int validationFailureIndex)
            {
                validationFailureIndex = 0;

                if (requestValidationSource == RequestValidationSource.Form &&
                    collectionKey.Equals(WSFederationConstants.Parameters.Result, StringComparison.Ordinal))
                {
                    SignInResponseMessage message =
                        WSFederationMessage.CreateFromFormPost(context.Request) as SignInResponseMessage;

                    if (message != null)
                    {
                        return true;
                    }
                }
                return base.IsValidRequestString(context, value, requestValidationSource, collectionKey,
                                                 out validationFailureIndex);
            }
        }
    }
}