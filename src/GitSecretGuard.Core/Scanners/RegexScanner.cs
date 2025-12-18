using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using GitSecretGuard.Core.Models;

namespace GitSecretGuard.Core.Scanners;

// scans files for secrets using regex
public class RegexScanner : ISecretScanner
{
    private readonly List<SecretPattern> _patterns;
    private readonly Dictionary<string, Regex> _compiledPatterns;
    
    // creates new scanner with the specified patterns
    public RegexScanner(IEnumerable<SecretPattern> patterns)
    {
        _patterns = patterns.ToList();
        _compiledPatterns = new Dictionary<string, Regex>();
        
        foreach (var pattern in _patterns)
        {
            _compiledPatterns[pattern.Id] = new Regex(
                pattern.Pattern, 
                RegexOptions.Compiled,
                TimeSpan.FromSeconds(5)
            );
        }
    }
    
    // scan a file for secrets
    public async IAsyncEnumerable<SecretFinding> ScanFileAsync(
        string filePath,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath))
        {
            yield break;
        }
        
        if (IsBinaryFile(filePath))
        {
            yield break;
        }
        
        var lines = await File.ReadAllLinesAsync(filePath, cancellationToken);
        
        for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            var line = lines[lineIndex];
            var lineNumber = lineIndex + 1;
            
            foreach (var pattern in _patterns)
            {
                if (pattern.FileExtensions.Count > 0)
                {
                    var extension = Path.GetExtension(filePath).TrimStart('.');
                    if (!pattern.FileExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                }
                
                var regex = _compiledPatterns[pattern.Id];
                var matches = regex.Matches(line);
                
                foreach (Match match in matches)
                {
                    if (IsLikelyPlaceholder(match.Value))
                    {
                        continue;
                    }
                    
                    yield return new SecretFinding
                    {
                        Pattern = pattern,
                        FilePath = filePath,
                        LineNumber = lineNumber,
                        Column = match.Index + 1,
                        MatchedText = match.Value,
                        LineContent = line
                    };
                }
            }
        }
    }
    
    // scan a directory recursively
    public async IAsyncEnumerable<SecretFinding> ScanDirectoryAsync(
        string directoryPath,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(directoryPath))
        {
            yield break;
        }
        
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.Hidden | FileAttributes.System
        };
        
        var files = Directory.EnumerateFiles(directoryPath, "*", options);
        
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            if (ShouldSkipPath(file))
            {
                continue;
            }
            
            await foreach (var finding in ScanFileAsync(file, cancellationToken))
            {
                yield return finding;
            }
        }
    }
    
    // scan content directly without reading from a file
    public async IAsyncEnumerable<SecretFinding> ScanContentAsync(
        string content,
        string sourceName,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var lines = content.Split('\n');
        
        for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            var line = lines[lineIndex];
            var lineNumber = lineIndex + 1;
            
            foreach (var pattern in _patterns)
            {
                var regex = _compiledPatterns[pattern.Id];
                var matches = regex.Matches(line);
                
                foreach (Match match in matches)
                {
                    if (IsLikelyPlaceholder(match.Value))
                    {
                        continue;
                    }
                    
                    yield return new SecretFinding
                    {
                        Pattern = pattern,
                        FilePath = sourceName,
                        LineNumber = lineNumber,
                        Column = match.Index + 1,
                        MatchedText = match.Value,
                        LineContent = line
                    };
                }
            }
        }
        
        await Task.CompletedTask;
    }
    
    // check if a file is likely binary (not text)
    private static bool IsBinaryFile(string filePath)
    {
        try
        {
            using var stream = File.OpenRead(filePath);
            var buffer = new byte[8192];
            var bytesRead = stream.Read(buffer, 0, buffer.Length);
            
            for (int i = 0; i < bytesRead; i++)
            {
                if (buffer[i] == 0)
                {
                    return true;
                }
            }
            
            return false;
        }
        catch
        {
            return true;
        }
    }
    
    // checks if a matched string looks like a placeholder instead of a real secret
    private static bool IsLikelyPlaceholder(string value)
    {
        var lower = value.ToLowerInvariant();
        
        string[] placeholderIndicators = 
        [
            "example",
            "sample",
            "your",
            "xxx",
            "test",
            "fake",
            "dummy",
            "placeholder",
            "changeme",
            "todo",
            "fixme",
            "insert",
            "<",
            ">"
        ];
        
        foreach (var indicator in placeholderIndicators)
        {
            if (lower.Contains(indicator))
            {
                return true;
            }
        }
        
        if (IsRepetitive(value))
        {
            return true;
        }
        
        return false;
    }
    
    // check if a string consists of repetitive patterns
    private static bool IsRepetitive(string value)
    {
        if (value.Length < 6) return false;
        
        if (value.Distinct().Count() <= 2)
        {
            return true;
        }
        
        return false;
    }
    
    // check if a path should be skipped
    private static bool ShouldSkipPath(string filePath)
    {
        string[] skipPatterns =
        [
            "node_modules",
            ".git",
            "bin",
            "obj",
            ".vs",
            ".idea",
            "__pycache__",
            "venv",
            ".venv",
            "dist",
            "build",
            ".next",
            "coverage"
        ];
        
        foreach (var pattern in skipPatterns)
        {
            if (filePath.Contains(Path.DirectorySeparatorChar + pattern + Path.DirectorySeparatorChar) ||
                filePath.Contains(Path.AltDirectorySeparatorChar + pattern + Path.AltDirectorySeparatorChar))
            {
                return true;
            }
        }
        
        return false;
    }
}