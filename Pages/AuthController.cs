using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.MvcCore;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Okta_SAML_Example.Identity;
using Microsoft.Extensions.Options;
using System.Security.Authentication;
using System;
using System.ServiceModel.Security;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Okta_SAML_Example.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "/foobar/";
        private readonly Saml2Configuration config;

        public AuthController(IOptions<Saml2Configuration> configAccessor)
        {
            config = configAccessor.Value;
        }

     
        [Route("Login")]
        public IActionResult Login(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });
            return binding.Bind(new Saml2AuthnRequest(config)).ToActionResult();
        }

      
        [Route("AssertionConsumerService")]
        [HttpPost]
        public IActionResult AssertionConsumerService(Object body)
        {       
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new NuclSaml2AuthnResponse(config);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }

            ITfoxtec.Identity.Saml2.Http.HttpRequest request = Request.ToGenericHttpRequest();

            saml2AuthnResponse.Read(Encoding.UTF8.GetString(Convert.FromBase64String(request.Form[Saml2Constants.Message.SamlResponse])));

            saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal));

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
        }

        [HttpPost("Logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = await new Saml2LogoutRequest(config, User).DeleteSession(HttpContext);
            return Redirect("~/");
        }
    }
}
