namespace GitSecretGuard.Core.Models;

public class SecretFinding
{
    public required SecretPattern Pattern { get; init; }
    public required string FilePath { get; init; }
    public required int LineNumber { get; init; }
    public required int Column { get; init; }
    public required string MatchedText { get; init; }
    public required string LineContent { get; init; }

    // class to create redacted version of matched text
    public string GetRedactedMatch()
    {
        if (MatchedText.Length <= 8)
        {
            return new string('*', MatchedText.Length);
        }

        var firstPart = MatchedText[..4];
        var lastPart = MatchedText[^4..];
        var middleLength = MatchedText.Length - 8;
        return $"{firstPart}{new string('*', middleLength)}{lastPart}";
    }

    // format finding into human-readable string
    public string ToDispalyString()
    {
         return $"""
            ⚠️  {Pattern.Name} detected
               File: {FilePath}
               Line: {LineNumber}, Column: {Column}
               Match: {GetRedactedMatch()}
               
               {LineContent.Trim()}
               {new string(' ', Column - 1)}{"^".PadRight(MatchedText.Length, '^')}
               
               Severity: {Pattern.Severity}
               
               How to fix:
               {Pattern.Remediation ?? "Remove this secret and use environment variables instead."}
            """;
    }
}