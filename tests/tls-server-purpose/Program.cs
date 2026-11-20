using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

const string ServerAuth = "1.3.6.1.5.5.7.3.1";
const string ClientAuth = "1.3.6.1.5.5.7.3.2";
var now = DateTimeOffset.UtcNow;
using var rootKey = RSA.Create(2048);
using var root = MakeRoot("owned-root", rootKey, now);
using var otherKey = RSA.Create(2048);
using var otherRoot = MakeRoot("other-owned-root", otherKey, now);
Console.WriteLine($"runtime={Environment.Version};rid={RuntimeInformation.RuntimeIdentifier};netsecSha256={HashAssembly(typeof(SslStream))};cryptoSha256={HashAssembly(typeof(X509Chain))}");

await CheckAsync("server-purpose", root, root, ServerAuth, "purpose.invalid", now);
await CheckAsync("client-purpose", root, root, ClientAuth, "purpose.invalid", now);
await CheckAsync("other-root", root, otherRoot, ServerAuth, "purpose.invalid", now);
await CheckAsync("wrong-host", root, root, ServerAuth, "other.invalid", now);

static string HashAssembly(Type type) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(type.Assembly.Location)));

static X509Certificate2 MakeRoot(string name, RSA key, DateTimeOffset now)
{
    var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
    return request.CreateSelfSigned(now.AddDays(-1), now.AddDays(2));
}

static async Task CheckAsync(string name, X509Certificate2 issuer, X509Certificate2 trustedRoot, string eku, string targetHost, DateTimeOffset now)
{
    using var leafKey = RSA.Create(2048);
    var request = new CertificateRequest("CN=purpose.invalid", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(eku) }, true));
    var san = new SubjectAlternativeNameBuilder();
    san.AddDnsName("purpose.invalid");
    request.CertificateExtensions.Add(san.Build());
    var serial = RandomNumberGenerator.GetBytes(16);
    serial[0] &= 0x7f;
    using var publicLeaf = request.Create(issuer, now.AddHours(-1), now.AddDays(1), serial);
    using var leaf = publicLeaf.CopyWithPrivateKey(leafKey);

    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
    var serverTask = Task.Run(async () =>
    {
        try
        {
            using var serverTcp = await listener.AcceptTcpClientAsync(cts.Token);
            using var server = new SslStream(serverTcp.GetStream(), false);
            await server.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = leaf,
                EnabledSslProtocols = SslProtocols.Tls12,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, cts.Token);
            var buffer = new byte[1];
            return (await server.ReadAsync(buffer, cts.Token) == 1 && buffer[0] == 0x42, "none");
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or OperationCanceledException)
        {
            return (false, $"{ex.GetType().Name}:{ex.HResult:X8}:{ex.Message}");
        }
    });

    var policy = new X509ChainPolicy
    {
        TrustMode = X509ChainTrustMode.CustomRootTrust,
        RevocationMode = X509RevocationMode.NoCheck,
        DisableCertificateDownloads = true
    };
    policy.CustomTrustStore.Add(trustedRoot);
    var accepted = false;
    var failure = "none";
    try
    {
        using var clientTcp = new TcpClient();
        await clientTcp.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        using var client = new SslStream(clientTcp.GetStream(), false);
        await client.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = targetHost,
            CertificateChainPolicy = policy,
            EnabledSslProtocols = SslProtocols.Tls12
        }, cts.Token);
        accepted = true;
        await client.WriteAsync(new byte[] { 0x42 }, cts.Token);
        await client.FlushAsync(cts.Token);
    }
    catch (Exception ex) when (ex is AuthenticationException or IOException or OperationCanceledException)
    {
        failure = ex.GetType().Name;
    }
    var (marker, serverFailure) = await serverTask;
    listener.Stop();
    Console.WriteLine($"case={name};accepted={accepted};marker={marker};failure={failure};serverFailure={serverFailure}");
}
