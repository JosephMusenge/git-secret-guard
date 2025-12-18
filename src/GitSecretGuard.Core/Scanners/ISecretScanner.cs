using GitSecretGuard.Core.Models;
namespace GitSecretGuard.Core.Scanners;

public interface ISecretScanner
{
    // Scan single line for secrets
    IAsyncEnumerable<SecretFinding> ScanFileAsync(string filePath, CancellationToken cancellationToken = default);
    // scan dir recursively for secrets
    IAsyncEnumerable<SecretFinding> ScanDirectoryAsync(string directoryPath, CancellationToken cancellationToken = default);
    // scan provided content string directly
    IAsyncEnumerable<SecretFinding> ScanContentAsync(
        string content,
        string sourceName,
        CancellationToken cancellationToken = default);
    
}