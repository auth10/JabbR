using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Web;
using JabbR.Services;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Web;
using Microsoft.Web.Infrastructure.DynamicModuleHelper;
using Ninject;

[assembly: WebActivator.PreApplicationStartMethod(typeof(JabbR.App_Start.FederatedLogin), "PreAppStart", Order = 1)]
[assembly: WebActivator.PostApplicationStartMethod(typeof(JabbR.App_Start.FederatedLogin), "PostAppStart")]

namespace JabbR.App_Start
{
    public static partial class FederatedLogin
    {
        public static void PreAppStart()
        {
            DynamicModuleUtility.RegisterModule(typeof(NoConfigWSFederationAuthenticationModule));
            DynamicModuleUtility.RegisterModule(typeof(NoConfigSessionAuthenticationModule));
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
            protected override void InitializeModule(HttpApplication context)
            {
                // shortcircuit registration of the module WSFederationAuthenticationModule events if fed auth is not configured
                var settings = Bootstrapper.Kernel.Get<IApplicationSettings>();
                if (!string.IsNullOrEmpty(settings.FedAuthIdentityProviderUrl))
                {
                    base.InitializeModule(context);
                }
            }

            protected override void InitializePropertiesFromConfiguration(string serviceName)
            {
                var settings = Bootstrapper.Kernel.Get<IApplicationSettings>();

                this.Realm = settings.FedAuthRealm;
                this.Issuer = settings.FedAuthIdentityProviderUrl;
                this.Reply = settings.FedAuthReply;
                // if not using the idp selector, redirect straight to idp if not authenticated
                this.PassiveRedirectEnabled = !settings.FedAuthWindowsAzureActiveDirectorySelectorEnabled; 
                this.RequireHttps = settings.FedAuthRequiresSsl;
            }
        }

        private class NoConfigSessionAuthenticationModule : SessionAuthenticationModule
        {
            protected override void InitializeModule(HttpApplication context)
            {
                // shortcircuit registration of the module SessionAuthenticationModule events if fed auth is not configured
                var settings = Bootstrapper.Kernel.Get<IApplicationSettings>();
                if (!string.IsNullOrEmpty(settings.FedAuthIdentityProviderUrl))
                {
                    base.InitializeModule(context);
                }
            }

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
    }
}