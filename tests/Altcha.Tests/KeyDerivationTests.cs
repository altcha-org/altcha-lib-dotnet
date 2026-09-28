namespace Altcha.Tests;

public class KeyDerivationTests
{
    private const string Nonce = "39baf91a19d671f8231217f9e28342a6";
    private const string Salt = "5e00d5d152e1a5db7d44fb6404a40a5e";

    // Vectors from altcha-lib/tests/v2/algorithms/*.test.ts (password = nonce || uint32BE(123)).
    [Theory]
    [InlineData("PBKDF2/SHA-256", 1, 32, 0, 0, "722ede188d41e7a7c9fd5447dca6cbb84e09c15724dbaadfb5bfb37d2cd4effa")]
    [InlineData("PBKDF2/SHA-256", 2, 32, 0, 0, "cba117f9a790022a55589d5008c9f003e49c011ff7fe34fc838788a1825524f7")]
    [InlineData("PBKDF2/SHA-384", 1, 32, 0, 0, "16fa2f9d7433fd956d7bb82745148bd18f44b8e87f8a57b47d1387f589402851")]
    [InlineData("PBKDF2/SHA-512", 1, 32, 0, 0, "d1033a8a8ae79a03ed06bdcfd8ad361aaafc72701c5db9da40fdeecefe3ec41a")]
    [InlineData("SHA-256", 1, 32, 0, 0, "6deccc5eecdb14c99d57129ef8f2f7d3e71812d8bd022c1caaf9e56512ec186c")]
    [InlineData("SHA-256", 2, 32, 0, 0, "54129dc0097cb40d1c75bd8dc1e5f713839b285d72f9685a3d91ab76ca2746ad")]
    [InlineData("SHA-384", 1, 48, 0, 0, "ec783f5767a962569850411504cd657ecd2eeef3219fc36036268c2ee8dd56b7f36f6899a37268634054c7e1267087a4")]
    [InlineData("SHA-512", 1, 64, 0, 0, "ed80526e1213f18539b9898556519535bc08bcc7e4d867e88988f3f3050795f0f7f606a2215896bf1b9f0a20aa0864958899c537057ef3193788b7abefd8cd21")]
    [InlineData("SCRYPT", 16384, 32, 8, 1, "1cc78d75577b791a65ba2b27894aec3c6af99b64155e79f50f4725fd43341070")]
    [InlineData("ARGON2ID", 1, 32, 16384, 1, "e5231033e21615aae48d8bc9b8e5e6c8f6538756f99dbcd5666f6e20832f30de")]
    [InlineData("ARGON2ID", 2, 32, 16384, 1, "e2e86adb59f793f14f7a9d38a52d531fa7ae6ca77d39b8448e4ebc2e724b094f")]
    public void DerivesJsReferenceKeys(string algorithm, int cost, int keyLength, int memoryCost, int parallelism, string expected)
    {
        var parameters = new ChallengeParameters
        {
            Algorithm = algorithm,
            Cost = cost,
            KeyLength = keyLength,
            MemoryCost = memoryCost > 0 ? memoryCost : null,
            Parallelism = parallelism > 0 ? parallelism : null,
            Nonce = Nonce,
            Salt = Salt,
        };
        var password = AltchaCrypto.PasswordWithCounter(Convert.FromHexString(Nonce), 123);

        var key = KeyDerivation.Resolve(algorithm)(parameters, Convert.FromHexString(Salt), password);

        Assert.Equal(expected, AltchaCrypto.ToHex(key));
    }

    [Theory]
    [InlineData("pbkdf2/sha-256")]
    [InlineData("Scrypt")]
    [InlineData("argon2id")]
    [InlineData("sha-512")]
    public void ResolveIsCaseInsensitive(string algorithm) =>
        Assert.True(KeyDerivation.TryResolve(algorithm, out _));

    [Theory]
    [InlineData("MD5")]
    [InlineData("PBKDF2/SHA-1")]
    [InlineData("")]
    public void ResolveRejectsUnknownAlgorithms(string algorithm)
    {
        Assert.False(KeyDerivation.TryResolve(algorithm, out _));
        Assert.Throws<AltchaException>(() => KeyDerivation.Resolve(algorithm));
    }
}
