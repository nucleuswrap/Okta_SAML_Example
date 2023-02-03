using System;
using System.Text;
using ITfoxtec.Identity.Saml2.Schemas;

namespace ITfoxtec.Identity.Saml2
{
	public class NuclSaml2AuthnResponse : Saml2AuthnResponse
	{
        public NuclSaml2AuthnResponse(Saml2Configuration config) : base(config)
        {
         
        }

        public void Read(string xml)
        {
            this.Read(xml, false, false);

		}

	}
}

