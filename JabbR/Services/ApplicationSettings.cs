using System.Configuration;
using System;

namespace JabbR.Services
{
    public class ApplicationSettings : IApplicationSettings
    {
        public string AuthApiKey
        {
            get
            {
                return ConfigurationManager.AppSettings["auth.apiKey"];
            }
        }

        public string DefaultAdminUserName
        {
            get
            {
                return ConfigurationManager.AppSettings["defaultAdminUserName"];
            }
        }

        public string DefaultAdminPassword
        {
            get
            {
                return ConfigurationManager.AppSettings["defaultAdminPassword"];
            }
        }


        public string AuthAppId
        {
            get 
            {
                return ConfigurationManager.AppSettings["auth.appId"];
            }
        }


        public string FedAuthIdentityProviderUrl
        {
            get
            {
                return ConfigurationManager.AppSettings["fedauth.identityProviderUrl"];
            }
        }

        public string FedAuthRealm
        {
            get
            {
                return ConfigurationManager.AppSettings["fedauth.realm"];
            }
        }


        public string FedAuthCertificateThumbprint
        {
            get
            {
                return ConfigurationManager.AppSettings["fedauth.certThumbprint"];
            }
        }

        public bool FedAuthRequiresSsl
        {
            get
            {
                bool requireSsl = false;
                bool requireSslParsed = Boolean.TryParse(ConfigurationManager.AppSettings["fedauth.requireSsl"], out requireSsl);
                return requireSslParsed && requireSsl;
            }
        }

        public bool FedAuthWindowsAzureActiveDirectorySelectorEnabled
        {
            get
            {
                bool selectorEnabled = false;
                bool selectorEnabledParsed = Boolean.TryParse(ConfigurationManager.AppSettings["fedauth.waad.selectorEnabled"], out selectorEnabled);
                return selectorEnabledParsed && selectorEnabled;
            }
        }

        public string FedAuthReply
        {
            get
            {
                return ConfigurationManager.AppSettings["fedauth.waad.reply"];
            }
        }
    }
}