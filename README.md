# Git-Secret-Guard 

This is a side project idea that came to mind after scrolling too much 😭. I saw this post on X and remembered I was just in this position recently. So I created this simple CLI tool to help stop leaking secrets before they become public disasters and memes.

<p align="center">
  <img src="docs/images/X-github-api-meme.png" alt="Tweet: just search OPENAI_API_KEY on github. thank me later." width="500">
  <br>
  <em>The tweet that started it all - 1.7M views and mass API key rotations 😅</em>
</p>

Git-Secret-Guard scans your code for API keys, passwords, and tokens *before* they enter git history. Unlike current scanners like GitLeaks and detect-secrets—which are great, but assume you're a security engineer who already knows what you're doing—Git-Secret-Guard is built for:

- 🎓 Those who just learned what an API key is
- 🚀 Self-taught developers still building security instincts  
- 💻 Anyone who's ever accidentally committed a `.env` file (we've all been there)

Of course, seasoned developers can use it too—secrets get leaked by mistake all the time, regardless of experience.

## How It Works

You try to commit code with a secret → Git-Secret-Guard blocks it → You fix it → Crisis averted.
```
🔍 Git-Secret-Guard: Scanning for secrets...

⚠ Found 1 potential secret(s)!

╭─────────────────────────────────────────────────────────────╮
│ ./src/config.js                                             │
├─────────────────────────────────────────────────────────────┤
│ Line 3: AWS Access Key ID                                   │
│ Match: AKIA************MPLE                                 │
│                                                             │
│ accessKeyId: "AKIAIOSFODNN7EXAMPLE"                         │
╰─────────────────────────────────────────────────────────────╯

❌ Commit blocked!

How to fix:
1. Remove the secret from your code
2. Store it in a .env file instead
3. Add .env to your .gitignore
4. Use environment variables in your code
```

**The secret never enters git history. You don't end up on that GitHub search.**

## Quick Start

**1. Clone and build:**
```bash
git clone https://github.com/yourusername/git-secret-guard.git
cd git-secret-guard
dotnet build
```

**2. Scan your project:**
```bash
dotnet run --project src/GitSecretGuard.Cli -- scan /path/to/your/project
```

**3. Set up automatic protection (recommended):**
```bash
cd your-project
/path/to/git-secret-guard init
```

Now every commit gets scanned automatically. If there's a secret, the commit is blocked.

## What It Catches

17+ types of secrets, including:

- **AWS** – Access Keys, Secret Keys
- **GitHub** – Personal Access Tokens, OAuth Tokens
- **Stripe** – Secret Keys (the ones that actually charge cards)
- **OpenAI** – API Keys
- **Slack** – Bot Tokens, Webhooks
- **Google Cloud** – API Keys, Service Account Keys
- **Azure** – Connection Strings
- **Databases** – MongoDB, PostgreSQL, MySQL, Redis connection strings
- **Private Keys** – RSA, SSH, etc.
- **Generic** – Passwords and API keys in code

Run `git-secret-guard patterns` to see all of them.

## Commands
```bash
# Scan a directory
git-secret-guard scan .

# Scan a specific file
git-secret-guard scan ./config.js

# JSON output (for CI/CD)
git-secret-guard scan . --json

# See all patterns
git-secret-guard patterns

# Set up pre-commit hook
git-secret-guard init
```

## Use in CI/CD

Add this to your GitHub Actions workflow to catch secrets in pull requests:
```yaml
name: Secret Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '8.0.x'
      - name: Scan for secrets
        run: |
          git clone https://github.com/yourusername/git-secret-guard.git /tmp/gsg
          dotnet run --project /tmp/gsg/src/GitSecretGuard.Cli -- scan .
```

## FAQ

**Will this slow down my commits?**  
No. It's fast. Most projects scan in under a second.

**What if it flags a false positive?**  
You can add paths to ignore in a `.gitsecretguard.yml` config file.

**What if I already committed a secret?**  
Git-Secret-Guard prevents future leaks. For secrets already in your history, you need to [rotate the credential](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) and assume it's compromised.

**Does this replace GitLeaks?**  
It can! GitLeaks is great for security teams. This is friendlier for everyone else.

## Tech Stack

- **C#** / .NET 8
- **Spectre.Console** for the pretty terminal output
- **xUnit** for tests

## Contributing

Found a bug? Want to add a new pattern? PRs welcome.

## License

MIT

---

*Built because mass-rotating API keys at 2am is not fun and you seriously don't want to become a meme.* 