namespace Altcha.Tests;

public class PowTests
{
    private const string Secret = "test-secret";

    [Fact]
    public void JsSignatureVectorVerifies()
    {
        var challenge = new Challenge
        {
            Parameters = new ChallengeParameters
            {
                Algorithm = "PBKDF2/SHA-256",
                Nonce = "39baf91a19d671f8231217f9e28342a6",
                Salt = "5e00d5d152e1a5db7d44fb6404a40a5e",
                KeyPrefix = "00",
                Cost = 1000,
                KeyLength = 32,
            },
            Signature = "a10045ef3381d5516e0c3fd6bf0b90e02fab68d576ffe9e0e1c2d1cd1e404f2a",
        };

        var result = AltchaPow.VerifySolution(new VerifySolutionOptions
        {
            Challenge = challenge,
            Solution = new Solution { Counter = 0, DerivedKey = "00" },
            HmacSignatureSecret = "signature.secret",
        });

        Assert.False(result.InvalidSignature);
    }

    [Fact]
    public void DeterministicRoundTripVerifies()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "PBKDF2/SHA-256",
            Cost = 1000,
            Counter = 5,
            KeyLength = 16,
            HmacSignatureSecret = Secret,
        });

        var solution = AltchaPow.SolveChallenge(new SolveChallengeOptions { Challenge = challenge });
        var result = Verify(challenge, solution);

        Assert.Equal(5, solution.Counter);
        Assert.Equal(16, challenge.Parameters.KeyPrefix.Length);
        Assert.True(result.Verified);
        Assert.False(result.InvalidSignature);
        Assert.False(result.InvalidSolution);
    }

    [Fact]
    public void OddPrefixRoundTripVerifies()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "SHA-256",
            Cost = 1,
            KeyPrefix = "0",
            HmacSignatureSecret = Secret,
        });

        var solution = AltchaPow.SolveChallenge(new SolveChallengeOptions { Challenge = challenge });

        Assert.StartsWith("0", solution.DerivedKey, StringComparison.Ordinal);
        Assert.True(Verify(challenge, solution).Verified);
    }

    [Fact]
    public void ExpiredChallengeIsRejectedBeforeOtherChecks()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "PBKDF2/SHA-256",
            Cost = 1,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-10),
            HmacSignatureSecret = Secret,
        });

        var result = Verify(challenge, new Solution { Counter = 0, DerivedKey = "abc" });

        Assert.True(result.Expired);
        Assert.False(result.Verified);
        Assert.Null(result.InvalidSignature);
        Assert.Null(result.InvalidSolution);
    }

    [Fact]
    public void ExpiresAtCurrentSecondIsExpired()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "PBKDF2/SHA-256",
            Cost = 1,
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()),
            HmacSignatureSecret = Secret,
        });
        Thread.Sleep(1);

        Assert.True(Verify(challenge, new Solution()).Expired);
    }

    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, false)]
    public void NonPositiveExpiresAt(long expiresAt, bool expired)
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "SHA-256",
            Cost = 1,
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(expiresAt),
            HmacSignatureSecret = Secret,
        });
        var solution = AltchaPow.SolveChallenge(new SolveChallengeOptions { Challenge = challenge });

        var result = Verify(challenge, solution);

        Assert.Equal(expired, result.Expired);
        Assert.Equal(!expired, result.Verified);
    }

    [Fact]
    public void TamperedParametersInvalidateSignature()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "PBKDF2/SHA-256",
            Cost = 100,
            Counter = 3,
            HmacSignatureSecret = Secret,
        });
        var solution = AltchaPow.SolveChallenge(new SolveChallengeOptions { Challenge = challenge });
        challenge.Parameters.Cost = 1;

        var result = Verify(challenge, solution);

        Assert.True(result.InvalidSignature);
        Assert.Null(result.InvalidSolution);
        Assert.False(result.Verified);
    }

    [Fact]
    public void MissingSignatureIsInvalid()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions { Algorithm = "SHA-256", Cost = 1 });

        var result = Verify(challenge, new Solution());

        Assert.True(result.InvalidSignature);
        Assert.False(result.Verified);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void VerifyWithoutSignatureSecretThrows(string? secret)
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions { Algorithm = "SHA-256", Cost = 1 });
        var solution = AltchaPow.SolveChallenge(new SolveChallengeOptions { Challenge = challenge });

        Assert.ThrowsAny<ArgumentException>(() => AltchaPow.VerifySolution(new VerifySolutionOptions
        {
            Challenge = challenge,
            Solution = solution,
            HmacSignatureSecret = secret,
        }));
    }

    [Fact]
    public void WrongSolutionIsInvalid()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "PBKDF2/SHA-256",
            Cost = 100,
            Counter = 7,
            HmacSignatureSecret = Secret,
        });

        var result = Verify(challenge, new Solution { Counter = 8, DerivedKey = new string('0', 64) });

        Assert.False(result.InvalidSignature);
        Assert.True(result.InvalidSolution);
        Assert.False(result.Verified);
    }

    [Fact]
    public void KeySignatureFastPathVerifiesWithoutDerivation()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "PBKDF2/SHA-256",
            Cost = 100,
            Counter = 4,
            HmacSignatureSecret = Secret,
            HmacKeySignatureSecret = "key-secret",
        });
        var solution = AltchaPow.SolveChallenge(new SolveChallengeOptions { Challenge = challenge });

        var result = AltchaPow.VerifySolution(new VerifySolutionOptions
        {
            Challenge = challenge,
            Solution = solution,
            HmacSignatureSecret = Secret,
            HmacKeySignatureSecret = "key-secret",
            DeriveKey = (_, _, _) => throw new InvalidOperationException("Fast path must not derive."),
        });

        Assert.NotNull(challenge.Parameters.KeySignature);
        Assert.True(result.Verified);
    }

    [Fact]
    public void UnsignedChallengeHasNoKeySignature()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "SHA-256",
            Cost = 1,
            Counter = 5,
            HmacKeySignatureSecret = "key-secret",
        });

        Assert.Null(challenge.Signature);
        Assert.Null(challenge.Parameters.KeySignature);
    }

    [Fact]
    public void InvalidDerivedKeyHexOnFastPathIsInvalidSolution()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "PBKDF2/SHA-256",
            Cost = 100,
            Counter = 4,
            HmacSignatureSecret = Secret,
            HmacKeySignatureSecret = "key-secret",
        });

        var result = AltchaPow.VerifySolution(new VerifySolutionOptions
        {
            Challenge = challenge,
            Solution = new Solution { Counter = 4, DerivedKey = "not-hex" },
            HmacSignatureSecret = Secret,
            HmacKeySignatureSecret = "key-secret",
        });

        Assert.True(result.InvalidSolution);
        Assert.False(result.Verified);
    }

    [Fact]
    public void NegativeCounterIsInvalidSolution()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "PBKDF2/SHA-256",
            Cost = 100,
            HmacSignatureSecret = Secret,
        });

        var result = Verify(challenge, new Solution { Counter = -1, DerivedKey = "00" });

        Assert.True(result.InvalidSolution);
        Assert.False(result.Verified);
    }

    [Fact]
    public void SolveHonorsCancellation()
    {
        var challenge = new Challenge
        {
            Parameters = new ChallengeParameters
            {
                Algorithm = "SHA-256",
                Cost = 1,
                KeyLength = 32,
                KeyPrefix = "ffffffffffffffff",
                Nonce = "00",
                Salt = "00",
            },
        };
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        Assert.ThrowsAny<OperationCanceledException>(() =>
            AltchaPow.SolveChallenge(new SolveChallengeOptions { Challenge = challenge }, cts.Token));
    }

    [Fact]
    public void CreateChallengeValidatesInput()
    {
        Assert.Throws<ArgumentException>(() => AltchaPow.CreateChallenge(new CreateChallengeOptions { Cost = 1 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => AltchaPow.CreateChallenge(new CreateChallengeOptions { Algorithm = "SHA-256" }));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            AltchaPow.CreateChallenge(new CreateChallengeOptions { Algorithm = "SHA-256", Cost = 1, Counter = -1 }));
        Assert.Throws<AltchaException>(() =>
            AltchaPow.CreateChallenge(new CreateChallengeOptions { Algorithm = "SHA-256", Cost = 1, KeyPrefix = "zz" }));
    }

    [Theory]
    [InlineData("A", "a")]
    [InlineData("0AB", "0ab")]
    public void CreateChallengeIssuesLowercaseKeyPrefix(string keyPrefix, string expected)
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "SHA-256",
            Cost = 1,
            KeyPrefix = keyPrefix,
            HmacSignatureSecret = Secret,
        });

        Assert.Equal(expected, challenge.Parameters.KeyPrefix);
    }

    [Fact]
    public void UppercaseOddKeyPrefixMatchesLowercaseKey()
    {
        // A signed challenge from another issuer with prefix "F2E": the prefix is normalized to lowercase for matching.
        var lowercase = SignedChallenge("f2e");
        var uppercase = SignedChallenge("F2E");
        var solution = AltchaPow.SolveChallenge(new SolveChallengeOptions { Challenge = uppercase });

        Assert.StartsWith("f2e", solution.DerivedKey, StringComparison.Ordinal);
        Assert.True(Verify(uppercase, solution).Verified);
        Assert.True(Verify(lowercase, solution).Verified);
    }

    [Theory]
    [InlineData("SHA-256", "zz", "1011", "0001")]
    [InlineData("SHA-256", "0g", "1011", "0001")]
    [InlineData("SHA-256", "00", "zz", "0001")]
    [InlineData("SHA-256", "00", "abc", "0001")]
    [InlineData("SHA-256", "00", "1011", "xyz")]
    [InlineData("MD5", "00", "1011", "0001")]
    public void MalformedSignedParametersAreInvalidSolution(string algorithm, string keyPrefix, string salt, string nonce)
    {
        var challenge = SignedChallenge(keyPrefix, salt, nonce, algorithm);

        var result = Verify(challenge, new Solution { Counter = 1, DerivedKey = "00" });

        Assert.False(result.InvalidSignature);
        Assert.True(result.InvalidSolution);
        Assert.False(result.Verified);
    }

    private static Challenge SignedChallenge(
        string keyPrefix,
        string salt = "101112131415161718191a1b1c1d1e1f",
        string nonce = "000102030405060708090a0b0c0d0e0f",
        string algorithm = "SHA-256")
    {
        var parameters = new ChallengeParameters
        {
            Algorithm = algorithm,
            Nonce = nonce,
            Salt = salt,
            KeyPrefix = keyPrefix,
            Cost = 1,
            KeyLength = 32,
        };
        return new Challenge
        {
            Parameters = parameters,
            Signature = AltchaCrypto.HmacHex(AltchaHashAlgorithm.Sha256, System.Text.Encoding.UTF8.GetBytes(CanonicalJson.Serialize(parameters)), Secret),
        };
    }

    [Fact]
    public void SignedDataRoundTripsThroughWireJson()
    {
        var challenge = AltchaPow.CreateChallenge(new CreateChallengeOptions
        {
            Algorithm = "SHA-256",
            Cost = 1,
            Counter = 2,
            HmacSignatureSecret = Secret,
            Data = new Dictionary<string, object?> { ["challengeId"] = "x<&>", ["n"] = 1.5, ["nested"] = new { b = 1, a = new[] { 1, 2 } } },
        });
        var json = System.Text.Json.JsonSerializer.Serialize(challenge, AltchaJson.SerializerOptions);
        var roundTripped = System.Text.Json.JsonSerializer.Deserialize<Challenge>(json, AltchaJson.SerializerOptions)!;
        var solution = AltchaPow.SolveChallenge(new SolveChallengeOptions { Challenge = roundTripped });

        Assert.True(Verify(roundTripped, solution).Verified);
    }

    [Fact]
    public void DeriveHmacKeySecretMatchesHmacOfMasterSecret()
    {
        var expected = AltchaCrypto.HmacHex(AltchaHashAlgorithm.Sha256, "master"u8.ToArray(), "derived-secret");

        Assert.Equal(expected, AltchaSecrets.DeriveHmacKeySecret("master"));
    }

    [Fact]
    public void KeyPrefixMatchesOddNibbles()
    {
        byte[] key = [0x00, 0xaa, 0xbb, 0xcc];

        Assert.True(KeyPrefix.Parse("").Matches(key));
        Assert.True(KeyPrefix.Parse("00a").Matches(key));
        Assert.False(KeyPrefix.Parse("00b").Matches(key));
        Assert.True(KeyPrefix.Parse("00aabbcc").Matches(key));
        Assert.False(KeyPrefix.Parse("00aabbcc0").Matches(key));
        Assert.True(KeyPrefix.Parse("00AABBCC").Matches(key));
        Assert.True(KeyPrefix.Parse("00A").Matches(key));
        Assert.False(KeyPrefix.Parse("00B").Matches(key));
        Assert.Throws<AltchaException>(() => KeyPrefix.Parse("0g"));
    }

    private static VerifySolutionResult Verify(Challenge challenge, Solution solution) =>
        AltchaPow.VerifySolution(new VerifySolutionOptions
        {
            Challenge = challenge,
            Solution = solution,
            HmacSignatureSecret = Secret,
        });
}
