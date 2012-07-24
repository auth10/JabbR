
namespace JabbR.Services
{
    public interface IApplicationSettings
    {
        string AuthApiKey { get; }

        string DefaultAdminUserName { get; }

        string DefaultAdminPassword { get; }
        string AuthAppId { get; }

        string FedAuthIdentityProviderUrl { get; }
        string FedAuthRealm { get; }
        string FedAuthReply { get; }
        string FedAuthCertificateThumbprint { get; }
        bool FedAuthRequiresSsl { get; }
        bool FedAuthWindowsAzureActiveDirectorySelectorEnabled { get; }
    }
}
