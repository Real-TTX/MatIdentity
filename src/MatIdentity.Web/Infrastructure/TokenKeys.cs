using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace MatIdentity.Web.Infrastructure;

/// <summary>
/// The keys of the tokens, kept on the data volume (<c>token-keys/</c>) so that tokens stay valid across restarts and updates:
/// an RSA key that signs every token (its public half is published at <c>/.well-known/jwks</c>, the apps check signatures with it) and a
/// symmetric key that encrypts what only MatIdentity reads itself (authorization codes, refresh tokens). Created on the first start.
/// Whoever has these files can issue tokens for every app: back the volume up like a password safe.
/// </summary>
public sealed class TokenKeys
{
    private const string SigningFile = "signing-rsa.pem";
    private const string EncryptionFile = "encryption-aes.key";

    private TokenKeys(RsaSecurityKey signing, SymmetricSecurityKey encryption)
    {
        Signing = signing;
        Encryption = encryption;
    }

    public RsaSecurityKey Signing { get; }

    public SymmetricSecurityKey Encryption { get; }

    /// <summary>Reads the keys from <paramref name="folder"/>, creating them when they do not exist yet.</summary>
    public static TokenKeys LoadOrCreate(string folder)
    {
        Directory.CreateDirectory(folder);

        var signingPath = Path.Combine(folder, SigningFile);
        var rsa = RSA.Create();
        if (File.Exists(signingPath))
        {
            rsa.ImportFromPem(File.ReadAllText(signingPath));
        }
        else
        {
            rsa.KeySize = 2048;
            WriteSecret(signingPath, rsa.ExportRSAPrivateKeyPem());
        }

        var encryptionPath = Path.Combine(folder, EncryptionFile);
        byte[] aes;
        if (File.Exists(encryptionPath))
        {
            aes = Convert.FromBase64String(File.ReadAllText(encryptionPath).Trim());
        }
        else
        {
            aes = RandomNumberGenerator.GetBytes(32);
            WriteSecret(encryptionPath, Convert.ToBase64String(aes));
        }

        // The key id is a hash of the public key, so it stays the same across restarts and changes with a new key (the apps cache the key by it).
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var signing = new RsaSecurityKey(rsa) { KeyId = Convert.ToHexString(SHA256.HashData(publicKey))[..16].ToLowerInvariant() };
        return new TokenKeys(signing, new SymmetricSecurityKey(aes));
    }

    private static void WriteSecret(string path, string content)
    {
        var temp = path + ".tmp";
        File.WriteAllText(temp, content);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        File.Move(temp, path, overwrite: false);
    }
}
