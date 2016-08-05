using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace AadCore
{
    public class ClientAssertionCert : IClientAssertionCertificate
    {
        public ClientAssertionCert(string clientId, X509Certificate2 certificate)
        {
            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            ClientId = clientId;
            Certificate = certificate;
        }

        public string ClientId { get; }

        public static int MinKeySizeInBits => 2048;

        public X509Certificate2 Certificate { get; }

        public byte[] Sign(string message)
        {
            var x509Key = new System.IdentityModel.Tokens.X509SecurityKey(Certificate);
            var rsa = x509Key.GetSignatureProviderForSigning(SecurityAlgorithms.RsaSha256Signature);
            return rsa.Sign(Encoding.UTF8.GetBytes(message));
        }

        public string Thumbprint => Convert.ToBase64String(Certificate.GetCertHash());
    }
}