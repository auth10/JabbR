using System;
using System.Linq;
using System.Web;
using JabbR.Services;
using Microsoft.IdentityModel.Claims;
using Ninject;

namespace JabbR.App_Start
{
    public static partial class FederatedLogin
    {

        

        private partial class NoConfigWSFederationAuthenticationModule 
        {
            protected override void OnSignedIn(EventArgs args)
            {
                this.ProcessRequest(HttpContext.Current);

                base.OnSignedIn(args);
            }

            public void ProcessRequest(HttpContext context)
            {
                IClaimsIdentity identity = context.User.Identity as IClaimsIdentity;
                string _domain = "", _email = "", _firstname="", _lastname="", _strClaimType;

                if (identity == null)
                {
                    throw new InvalidOperationException("IClaimsIdentity is null.");
                }

                Claim userIdentityClaim = identity.Claims.SingleOrDefault(c => c.ClaimType == ClaimTypes.NameIdentifier);
                if (userIdentityClaim == null)
                {
                    throw new InvalidOperationException("NameIdentifier claim not found.");
                }

                // This runs through and forms the data for the claim. Obviously this can be done with Linq
               foreach (var c in identity.Claims)
            {
                _strClaimType = c.ClaimType;
                if (_strClaimType.EndsWith("domain"))
                    _domain = c.Value;
                if (_strClaimType.EndsWith("EmailAddress"))
                    _email = c.Value;
                if (_strClaimType.EndsWith("FirstName"))
                      _firstname = c.Value;
                if (_strClaimType.EndsWith("LastName"))
                       _lastname = c.Value ;
            }

            // Name does not exist in the Claim coming from ACS at this point in time

             //   if (identity.Name == null)
             //   {
             //       throw new InvalidOperationException("Name claim not found.");
             //   }

                string userIdentity = userIdentityClaim.Value;
                string username = _firstname;
                string email = _email;
                Claim emailClaim = identity.Claims.SingleOrDefault(c => c.ClaimType == ClaimTypes.Email);
                if (emailClaim != null)
                {
                    email = emailClaim.Value.ToString();
                }

                var identityLinker = Bootstrapper.Kernel.Get<IIdentityLinker>();
                identityLinker.LinkIdentity(new HttpContextWrapper(context), userIdentity, username, email);

                string hash = context.Request.Form["wctx"];
                context.Response.Redirect(GetUrl(hash), false);
                context.ApplicationInstance.CompleteRequest();
            }

            private string GetUrl(string hash)
            {
                return HttpRuntime.AppDomainAppVirtualPath + hash;
            }
        }
    }
}