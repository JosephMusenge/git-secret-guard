using System.CommandLine;
using GitSecretGuard.Core.Models;
using GitSecretGuard.Core.Patterns;
using GitSecretGuard.Core.Scanners;
using Spectre.Console;
using Spectre.Console.Rendering;


// COMMAND LINE SETUP
var rootCommand = new RootCommand("Git-Secret-Guard - Pre-commit secret detection for developers")
{
};

// SCAN COMMAND: git-secret-guard scan <path>
var pathArgument = new Argument<string>(
    name: "path",
    description: "Path to file or directory to scan",
    getDefaultValue: () => "."
);

var configOption = new Option<string?>(
    aliases: ["--config", "-c"],
    description: "Path to custom patterns configuration file"
);

var verboseOption = new Option<bool>(
    aliases: ["--verbose", "-v"],
    description: "Show detailed output including scanned files"
);

var jsonOption = new Option<bool>(
    aliases: ["--json"],
    description: "Output results as JSON (useful for CI/CD integration)"
);

var scanCommand = new Command("scan", "Scan files or directories for secrets")
{
    pathArgument,
    configOption,
    verboseOption,
    jsonOption
};

scanCommand.SetHandler(async (path, config, verbose, json) =>
{
    await RunScanAsync(path, config, verbose, json);
}, pathArgument, configOption, verboseOption, jsonOption);

rootCommand.AddCommand(scanCommand);

// INIT COMMAND: git-secret-guard init
var initCommand = new Command("init", "Initialize Git-Secret-Guard in the current repository");

initCommand.SetHandler(async () =>
{
    await RunInitAsync();
});

rootCommand.AddCommand(initCommand);

// PATTERNS COMMAND: git-secret-guard patterns
var patternsCommand = new Command("patterns", "List all detection patterns");

patternsCommand.SetHandler(() =>
{
    ListPatterns();
});

rootCommand.AddCommand(patternsCommand);

// RUN THE CLI
return await rootCommand.InvokeAsync(args);
// command implementations
async Task RunScanAsync(string path, string? configPath, bool verbose, bool json)
{
    if (!json)
    {
        AnsiConsole.Write(
            new FigletText("Git-Secret-Guard")
                .LeftJustified()
                .Color(Color.Blue));
        
        AnsiConsole.MarkupLine("[grey]Scanning for secrets...[/]");
        AnsiConsole.WriteLine();
    }
    
    var fullPath = Path.GetFullPath(path);
    
    if (!File.Exists(fullPath) && !Directory.Exists(fullPath))
    {
        AnsiConsole.MarkupLine($"[red]Error:[/] Path not found: {fullPath}");
        Environment.ExitCode = 1;
        return;
    }
    
    var patterns = DefaultPatterns.GetAll();
    var scanner = new RegexScanner(patterns);
    
    var findings = new List<SecretFinding>();
    var filesScanned = 0;
    
    await AnsiConsole.Status()
        .StartAsync("Scanning...", async ctx =>
        {
            IAsyncEnumerable<SecretFinding> scanResults;
            
            if (File.Exists(fullPath))
            {
                scanResults = scanner.ScanFileAsync(fullPath);
                filesScanned = 1;
            }
            else
            {
                scanResults = scanner.ScanDirectoryAsync(fullPath);
                filesScanned = Directory.EnumerateFiles(fullPath, "*", SearchOption.AllDirectories)
                    .Count();
            }
            
            await foreach (var finding in scanResults)
            {
                findings.Add(finding);
                ctx.Status($"Found {findings.Count} potential secret(s)...");
            }
        });
    
    if (json)
    {
        OutputJson(findings);
    }
    else
    {
        OutputPretty(findings, filesScanned, verbose);
    }
    
    Environment.ExitCode = findings.Count > 0 ? 1 : 0;
}

void OutputPretty(List<SecretFinding> findings, int filesScanned, bool verbose)
{
    if (findings.Count == 0)
    {
        AnsiConsole.MarkupLine("[green]✓ No secrets detected![/]");
        AnsiConsole.MarkupLine($"[grey]Scanned {filesScanned} file(s)[/]");
        return;
    }
    
    AnsiConsole.MarkupLine($"[red]⚠ Found {findings.Count} potential secret(s)![/]");
    AnsiConsole.WriteLine();
    
    var byFile = findings.GroupBy(f => f.FilePath);
    
    foreach (var fileGroup in byFile)
    {
        var panel = new Panel(BuildFileFindings(fileGroup.ToList()))
        {
            Header = new PanelHeader($"[yellow]{fileGroup.Key}[/]"),
            Border = BoxBorder.Rounded,
            Padding = new Padding(1, 0, 1, 0)
        };
        
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }
    
    AnsiConsole.Write(new Rule("[red]What to do next[/]").LeftJustified());
    AnsiConsole.MarkupLine("1. [bold]Remove[/] the secrets from your code");
    AnsiConsole.MarkupLine("2. [bold]Add[/] sensitive files to .gitignore");
    AnsiConsole.MarkupLine("3. [bold]Use[/] environment variables or a secrets manager");
    AnsiConsole.MarkupLine("4. [bold]Rotate[/] any secrets that may have been exposed");
    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[grey]Run 'git-secret-guard patterns' to see all detection patterns[/]");
}

IRenderable BuildFileFindings(List<SecretFinding> findings)
{
    var rows = new List<IRenderable>();
    
    foreach (var finding in findings)
    {
        var severityColor = finding.Pattern.Severity switch
        {
            Severity.Critical => "red",
            Severity.High => "orange1",
            Severity.Medium => "yellow",
            Severity.Low => "grey",
            _ => "white"
        };
        
        rows.Add(new Markup($"[bold]Line {finding.LineNumber}:[/] [{severityColor}]{finding.Pattern.Name}[/]"));
        rows.Add(new Markup($"[grey]Match:[/] {finding.GetRedactedMatch()}"));
        
        var lineContent = finding.LineContent.Trim();
        rows.Add(new Markup($"[grey]{Markup.Escape(lineContent)}[/]"));
        rows.Add(new Text(""));
    }
    
    return new Rows(rows);
}

void OutputJson(List<SecretFinding> findings)
{
    Console.WriteLine("{");
    Console.WriteLine($"  \"count\": {findings.Count},");
    Console.WriteLine("  \"findings\": [");
    
    for (int i = 0; i < findings.Count; i++)
    {
        var f = findings[i];
        var comma = i < findings.Count - 1 ? "," : "";
        Console.WriteLine("    {");
        Console.WriteLine($"      \"type\": \"{f.Pattern.Id}\",");
        Console.WriteLine($"      \"name\": \"{f.Pattern.Name}\",");
        Console.WriteLine($"      \"file\": \"{f.FilePath.Replace("\\", "\\\\")}\",");
        Console.WriteLine($"      \"line\": {f.LineNumber},");
        Console.WriteLine($"      \"column\": {f.Column},");
        Console.WriteLine($"      \"severity\": \"{f.Pattern.Severity}\",");
        Console.WriteLine($"      \"match\": \"{f.GetRedactedMatch()}\"");
        Console.WriteLine($"    }}{comma}");
    }
    
    Console.WriteLine("  ]");
    Console.WriteLine("}");
}

async Task RunInitAsync()
{
    AnsiConsole.MarkupLine("[blue]Initializing Git-Secret-Guard...[/]");
    
    var gitDir = Path.Combine(Directory.GetCurrentDirectory(), ".git");
    if (!Directory.Exists(gitDir))
    {
        AnsiConsole.MarkupLine("[red]Error:[/] Not a git repository. Run 'git init' first.");
        Environment.ExitCode = 1;
        return;
    }
    
    var hooksDir = Path.Combine(gitDir, "hooks");
    Directory.CreateDirectory(hooksDir);
    
    var preCommitPath = Path.Combine(hooksDir, "pre-commit");
    var hookScript = """
        #!/bin/sh
        # Git-Secret-Guard pre-commit hook
        # Scans staged changes for secrets before allowing commit
        
        echo "🔍 Git-Secret-Guard: Scanning for secrets..."
        
        if command -v git-secret-guard &> /dev/null; then
            git-secret-guard scan .
            exit_code=$?
            
            if [ $exit_code -ne 0 ]; then
                echo ""
                echo "❌ Commit blocked: secrets detected!"
                echo "Please remove the secrets and try again."
                exit 1
            fi
            
            echo "✅ No secrets detected"
            exit 0
        else
            echo "⚠️  git-secret-guard not found in PATH"
            echo "Install it or remove this hook to continue"
            exit 1
        fi
        """;
    
    await File.WriteAllTextAsync(preCommitPath, hookScript);
    
    if (!OperatingSystem.IsWindows())
    {
        File.SetUnixFileMode(preCommitPath, 
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
            UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
    }
    
    AnsiConsole.MarkupLine("[green]✓[/] Created pre-commit hook");
    
    var configPath = Path.Combine(Directory.GetCurrentDirectory(), ".gitsecretguard.yml");
    if (!File.Exists(configPath))
    {
        var configContent = """
            # Git-Secret-Guard Configuration
            # See https://github.com/yourusername/git-secret-guard for documentation
            
            # Paths to ignore (in addition to .gitignore)
            ignore:
              - "**/*.test.js"
              - "**/*.spec.ts"
              - "**/fixtures/**"
            
            # Custom patterns (in addition to built-in patterns)
            # patterns:
            #   - id: my-company-token
            #     name: "My Company API Token"
            #     pattern: "myco_[a-zA-Z0-9]{32}"
            #     severity: high
            #     description: "Internal API token for My Company services"
            
            # Allowlist specific findings (use with caution!)
            # allowlist:
            #   - pattern: aws-access-key-id
            #     path: "**/test/**"
            #     reason: "Test fixtures use fake AWS keys"
            """;
        
        await File.WriteAllTextAsync(configPath, configContent);
        AnsiConsole.MarkupLine("[green]✓[/] Created .gitsecretguard.yml configuration file");
    }
    else
    {
        AnsiConsole.MarkupLine("[grey]→[/] .gitsecretguard.yml already exists, skipping");
    }
    
    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[green]Git-Secret-Guard initialized![/]");
    AnsiConsole.MarkupLine("Your commits will now be scanned for secrets.");
    AnsiConsole.MarkupLine("[grey]Run 'git-secret-guard scan .' to test the scanner[/]");
}

void ListPatterns()
{
    var patterns = DefaultPatterns.GetAll();
    
    AnsiConsole.Write(
        new FigletText("Patterns")
            .LeftJustified()
            .Color(Color.Blue));
    
    var table = new Table()
        .Border(TableBorder.Rounded)
        .AddColumn("[bold]ID[/]")
        .AddColumn("[bold]Name[/]")
        .AddColumn("[bold]Severity[/]")
        .AddColumn("[bold]Description[/]");
    
    foreach (var pattern in patterns.OrderBy(p => p.Id))
    {
        var severityColor = pattern.Severity switch
        {
            Severity.Critical => "red",
            Severity.High => "orange1",
            Severity.Medium => "yellow",
            Severity.Low => "grey",
            _ => "white"
        };
        
        table.AddRow(
            pattern.Id,
            pattern.Name,
            $"[{severityColor}]{pattern.Severity}[/]",
            pattern.Description.Length > 50 
                ? pattern.Description[..47] + "..." 
                : pattern.Description
        );
    }
    
    AnsiConsole.Write(table);
    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine($"[grey]{patterns.Count} patterns loaded[/]");
}