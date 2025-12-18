using FluentAssertions;
using GitSecretGuard.Core.Models;
using GitSecretGuard.Core.Patterns;
using GitSecretGuard.Core.Scanners;
using Xunit;

namespace GitSecretGuard.Core.Tests;

// Unit tests for the RegexScanner
public class RegexScannerTests
{
    private readonly RegexScanner _scanner;
    
    public RegexScannerTests()
    {
        _scanner = new RegexScanner(DefaultPatterns.GetAll());
    }
    
    // AWS ACCESS KEY DETECTION
    [Fact]
    public async Task ScanContent_WithAwsAccessKeyId_DetectsSecret()
    {
        var content = """
            const config = {
                accessKeyId: "AKIAIOSFODNN7REALKEY"
            };
            """;
        
        var findings = await _scanner.ScanContentAsync(content, "test.js").ToListAsync();
        
        findings.Should().ContainSingle();
        findings[0].Pattern.Id.Should().Be("aws-access-key-id");
        findings[0].LineNumber.Should().Be(2);
    }
    
    [Fact]
    public async Task ScanContent_WithAsiaTemporaryKey_DetectsSecret()
    {
        var content = "aws_key = 'ASIAIOSFODNN7REALKEY'";
        
        var findings = await _scanner.ScanContentAsync(content, "test.py").ToListAsync();
        
        findings.Should().ContainSingle();
        findings[0].Pattern.Id.Should().Be("aws-access-key-id");
    }
    
    [Fact]
    public async Task ScanContent_WithAwsPlaceholder_SkipsAsPlaceholder()
    {
        var content = "key = 'AKIAEXAMPLEKEY1234567'";
        
        var findings = await _scanner.ScanContentAsync(content, "test.js").ToListAsync();
        
        findings.Should().BeEmpty();
    }
    
    // GITHUB TOKEN DETECTION  
    [Fact]
    public async Task ScanContent_WithGitHubPat_DetectsSecret()
    {
        var content = """
            # Configuration
            GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789
            """;
        
        var findings = await _scanner.ScanContentAsync(content, ".env").ToListAsync();
        
        findings.Should().ContainSingle();
        findings[0].Pattern.Id.Should().Be("github-pat");
    }
    
    [Fact]
    public async Task ScanContent_WithGitHubOAuth_DetectsSecret()
    {
        var content = "token: gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
        
        var findings = await _scanner.ScanContentAsync(content, "config.yml").ToListAsync();
        
        findings.Should().ContainSingle();
        findings[0].Pattern.Id.Should().Be("github-oauth");
    }
    
    // STRIPE KEY DETECTION
    [Fact]
    public async Task ScanContent_WithStripeLiveKey_DetectsCriticalSecret()
    {
        var content = """
            const stripe = require('stripe')('sk_live_abcdefghijklmnopqrstuvwxyz');
            """;
        
        var findings = await _scanner.ScanContentAsync(content, "payment.js").ToListAsync();
        
        findings.Should().ContainSingle();
        findings[0].Pattern.Id.Should().Be("stripe-secret-key");
        findings[0].Pattern.Severity.Should().Be(Severity.Critical);
    }
    
    [Fact]
    public async Task ScanContent_WithStripeTestKey_DoesNotDetect()
    {
        var content = "stripe_key = 'sk_test_abcdefghijklmnopqrstuvwxyz'";
        
        var findings = await _scanner.ScanContentAsync(content, "test.js").ToListAsync();
        
        findings.Where(f => f.Pattern.Id == "stripe-secret-key").Should().BeEmpty();
    }
    
    // PRIVATE KEY DETECTION
    [Fact]
    public async Task ScanContent_WithRsaPrivateKey_DetectsCriticalSecret()
    {
        var content = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
            -----END RSA PRIVATE KEY-----
            """;
        
        var findings = await _scanner.ScanContentAsync(content, "key.pem").ToListAsync();
        
        findings.Should().ContainSingle();
        findings[0].Pattern.Id.Should().Be("private-key");
        findings[0].Pattern.Severity.Should().Be(Severity.Critical);
    }
    
    [Fact]
    public async Task ScanContent_WithPublicKey_DoesNotDetect()
    {
        var content = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
            -----END PUBLIC KEY-----
            """;
        
        var findings = await _scanner.ScanContentAsync(content, "key.pub").ToListAsync();
        
        findings.Should().BeEmpty();
    }
    
    // DATABASE CONNECTION STRING DETECTION
    [Fact]
    public async Task ScanContent_WithMongoConnectionString_DetectsSecret()
    {
        var content = """
            DATABASE_URL=mongodb://admin:secretpassword123@cluster.mongodb.net:27017/mydb
            """;
        
        var findings = await _scanner.ScanContentAsync(content, ".env").ToListAsync();
        
        findings.Should().Contain(f => f.Pattern.Id == "connection-string");
    }
    
    [Fact]
    public async Task ScanContent_WithPostgresConnectionString_DetectsSecret()
    {
        var content = "conn = 'postgresql://user:pass@localhost:5432/db'";
        
        var findings = await _scanner.ScanContentAsync(content, "config.py").ToListAsync();
        
        findings.Should().Contain(f => f.Pattern.Id == "connection-string");
    }
    
    // FALSE POSITIVE HANDLING
    [Fact]
    public async Task ScanContent_WithPlaceholderText_SkipsAsPlaceholder()
    {
        var content = """
            // Configuration - replace with your actual values
            API_KEY=your-api-key-here
            AWS_KEY=AKIAXXXXXXXXXXXXXXXX
            PASSWORD=changeme
            """;
        
        var findings = await _scanner.ScanContentAsync(content, "config.example").ToListAsync();
        
        findings.Should().BeEmpty();
    }
    
    [Fact]
    public async Task ScanContent_WithTestIndicator_SkipsAsPlaceholder()
    {
        var content = "test_key = 'AKIA1234567890TESTKEY'";
        
        var findings = await _scanner.ScanContentAsync(content, "test.js").ToListAsync();
        
        findings.Should().BeEmpty();
    }
    
    // EDGE CASES
    [Fact]
    public async Task ScanContent_WithEmptyContent_ReturnsNoFindings()
    {
        var findings = await _scanner.ScanContentAsync("", "empty.txt").ToListAsync();
        
        findings.Should().BeEmpty();
    }
    
    [Fact]
    public async Task ScanContent_WithWhitespaceOnly_ReturnsNoFindings()
    {
        var content = "   \n\n\t\t\n   ";
        
        var findings = await _scanner.ScanContentAsync(content, "whitespace.txt").ToListAsync();
        
        findings.Should().BeEmpty();
    }
    
    [Fact]
    public async Task ScanContent_TracksCorrectLineNumbers()
    {
        var content = """
            // Line 1: Comment
            // Line 2: Another comment
            // Line 3: Yet another
            const key = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"; // Line 4
            // Line 5: More comments
            """;
        
        var findings = await _scanner.ScanContentAsync(content, "test.js").ToListAsync();
        
        findings.Should().ContainSingle();
        findings[0].LineNumber.Should().Be(4);
    }
    
    // FINDING MODEL TESTS
    [Fact]
    public async Task SecretFinding_GetRedactedMatch_RedactsMiddle()
    {
        var content = "key = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'";
        
        var findings = await _scanner.ScanContentAsync(content, "test.js").ToListAsync();
        
        var redacted = findings[0].GetRedactedMatch();
        
        redacted.Should().StartWith("ghp_");
        redacted.Should().EndWith("6789");
        redacted.Should().Contain("*");
    }
}

// Helper extension to convert IAsyncEnumerable to List for easier testing
public static class AsyncEnumerableExtensions
{
    public static async Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> source)
    {
        var list = new List<T>();
        await foreach (var item in source)
        {
            list.Add(item);
        }
        return list;
    }
}