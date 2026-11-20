using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

const string ServerAuth = "1.3.6.1.5.5.7.3.1";
const string ClientAuth = "1.3.6.1.5.5.7.3.2";

var now = DateTimeOffset.UtcNow;
using var rootKey = RSA.Create(2048);
using var root = MakeRoot("owned-root", rootKey, now);
using var otherRootKey = RSA.Create(2048);
using var otherRoot = MakeRoot("other-owned-root", otherRootKey, now);

var assembly = typeof(X509Chain).Assembly.Location;
Console.WriteLine($"runtime={Environment.Version};rid={RuntimeInformation.RuntimeIdentifier};cryptoSha256={Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assembly)))}");

Check("server-only", root, root, now, ServerAuth);
Check("client-only", root, root, now, ClientAuth);
Check("dual-purpose", root, root, now, ServerAuth, ClientAuth);
Check("no-eku", root, root, now);
Check("other-root-client", otherRoot, root, now, ClientAuth);

static X509Certificate2 MakeRoot(string name, RSA key, DateTimeOffset now)
{
    var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
    return request.CreateSelfSigned(now.AddDays(-1), now.AddDays(2));
}

static void Check(string name, X509Certificate2 issuer, X509Certificate2 trustedRoot, DateTimeOffset now, params string[] eku)
{
    using var leafKey = RSA.Create(2048);
    var request = new CertificateRequest($"CN={name}", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
    if (eku.Length > 0)
    {
        var oids = new OidCollection();
        foreach (var oid in eku)
        {
            oids.Add(new Oid(oid));
        }
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, true));
    }
    var serial = RandomNumberGenerator.GetBytes(16);
    serial[0] &= 0x7f;
    using var leaf = request.Create(issuer, now.AddHours(-1), now.AddDays(1), serial);
    using var chain = new X509Chain();
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(trustedRoot);
    chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    chain.ChainPolicy.DisableCertificateDownloads = true;
    var accepted = chain.Build(leaf);
    var statuses = string.Join(",", chain.ChainStatus.Select(s => s.Status.ToString()));
    Console.WriteLine($"case={name};accepted={accepted};elements={chain.ChainElements.Count};status={statuses}");
}
