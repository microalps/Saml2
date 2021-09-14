using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Sustainsys.Saml2.Internal
{
    internal static class CryptographyExtensions
    {
		private const String RSA = "1.2.840.113549.1.1.1";
		private const String DSA = "1.2.840.10040.4.1";
		private const String ECC = "1.2.840.10045.2.1";
        
        internal static void Encrypt(this XmlElement elementToEncrypt, bool useOaep, X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            var encryptedData = new EncryptedData
            {
                Type = EncryptedXml.XmlEncElementUrl,
                EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
            };

            var algorithm = useOaep ? EncryptedXml.XmlEncRSAOAEPUrl : EncryptedXml.XmlEncRSA15Url;
            var encryptedKey = new EncryptedKey
            {
                EncryptionMethod = new EncryptionMethod(algorithm),
            };

            var encryptedXml = new EncryptedXml();
            byte[] encryptedElement;
            using (var symmetricAlgorithm = new RijndaelManaged())
            {
                symmetricAlgorithm.KeySize = 256;
                encryptedKey.CipherData = new CipherData(EncryptedXml.EncryptKey(symmetricAlgorithm.Key, (RSA)certificate.PublicKey.Key, useOaep));
                encryptedElement = encryptedXml.EncryptData(elementToEncrypt, symmetricAlgorithm, false);
            }
            encryptedData.CipherData.CipherValue = encryptedElement;

            encryptedData.KeyInfo = new KeyInfo();
            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
            EncryptedXml.ReplaceElement(elementToEncrypt, encryptedData, false);
        }

        internal static IEnumerable<XmlElement> Decrypt(this IEnumerable<XmlElement> elements, AsymmetricAlgorithm key)
        {
            foreach (var element in elements)
            {
                yield return element.Decrypt(key);
            }
        }

        internal static XmlElement Decrypt(this XmlElement element, AsymmetricAlgorithm key)
        {
            var xmlDoc = XmlHelpers.XmlDocumentFromString(element.OuterXml);

            var exml = new RSAEncryptedXml(xmlDoc, (RSA)key);

            exml.DecryptDocument();

            return xmlDoc.DocumentElement;
        }

        internal static AsymmetricAlgorithm GetPrivateKey(this X509Certificate2 cert)
        {
            switch (cert.PublicKey.Oid.Value)
            {
                case RSA:
                    return cert.GetRSAPrivateKey();
                case ECC:
                    return cert.GetECDsaPrivateKey();
                case DSA:
                    return cert.GetDSAPrivateKey();
                default:
                    return cert.PrivateKey;
            }
        }
    }
}
