namespace GitSecretGuard.Core.Models;

public class SecretPattern
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Pattern { get; init; }
    public required string Description { get; init; }
    public Severity Severity { get; init; } = Severity.High; // default "high"
    public string? Remediation { get; init; }
    public List<string> FileExtensions { get; init; } = [];
}

// severity levels for detected secrets
public enum Severity
{
    Low,
    Medium,
    High,
    Critical
}