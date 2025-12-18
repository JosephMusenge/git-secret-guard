using GitSecretGuard.Core.Models;

namespace GitSecretGuard.Core.Patterns;

// provide the default set of patterns for detecting common secrets
public static class DefaultPatterns
{
    // get all default patterns
    public static List<SecretPattern> GetAll() =>
    [
        // AWS CREDENTIALS
        new SecretPattern
        {
            Id = "aws-access-key-id",
            Name = "AWS Access Key ID",
            Pattern = @"(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}",
            Description = "AWS Access Key IDs authenticate API requests to AWS services.",
            Severity = Severity.Critical,
            Remediation = """
                1. Immediately rotate this key in AWS IAM Console
                2. Check CloudTrail for unauthorized usage
                3. Remove the key from your code
                4. Use environment variables: Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")
                5. For production, use IAM roles instead of access keys
                
                AWS Documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
                """
        },
        
        new SecretPattern
        {
            Id = "aws-secret-access-key",
            Name = "AWS Secret Access Key",
            Pattern = @"(?i)(?:aws)?_?secret_?(?:access)?_?key['""]?\s*[:=]\s*['""]?([A-Za-z0-9/+=]{40})['""]?",
            Description = "AWS Secret Access Keys are the password component of AWS credentials.",
            Severity = Severity.Critical,
            Remediation = """
                1. Rotate BOTH the Access Key ID and Secret Access Key
                2. Use AWS Secrets Manager or Parameter Store for production
                3. Consider using aws-vault for local development
                """
        },
        
        // STRIPE
        new SecretPattern
        {
            Id = "stripe-secret-key",
            Name = "Stripe Secret Key",
            Pattern = @"sk_live_[a-zA-Z0-9]{24,}",
            Description = "Stripe secret keys can process payments and access sensitive customer data.",
            Severity = Severity.Critical,
            Remediation = """
                1. Roll this key immediately in Stripe Dashboard → Developers → API Keys
                2. Check Stripe logs for unauthorized transactions
                3. Store in environment variable: STRIPE_SECRET_KEY
                """
        },
        
        new SecretPattern
        {
            Id = "stripe-restricted-key",
            Name = "Stripe Restricted Key",
            Pattern = @"rk_live_[a-zA-Z0-9]{24,}",
            Description = "Stripe restricted keys have limited permissions but can still access production data.",
            Severity = Severity.High,
            Remediation = "Roll this key in Stripe Dashboard and store in environment variable."
        },
        
        // GITHUB
        new SecretPattern
        {
            Id = "github-pat",
            Name = "GitHub Personal Access Token",
            Pattern = @"ghp_[a-zA-Z0-9]{36}",
            Description = "GitHub Personal Access Tokens can access repositories and perform actions as you.",
            Severity = Severity.Critical,
            Remediation = """
                1. Revoke immediately: GitHub → Settings → Developer settings → Personal access tokens
                2. Check your GitHub security log for unauthorized access
                3. Create a new token with minimal required scopes
                """
        },
        
        new SecretPattern
        {
            Id = "github-oauth",
            Name = "GitHub OAuth Access Token",
            Pattern = @"gho_[a-zA-Z0-9]{36}",
            Description = "GitHub OAuth tokens are used for OAuth app authentication.",
            Severity = Severity.High,
            Remediation = "Revoke the OAuth token and investigate the OAuth app that created it."
        },
        
        new SecretPattern
        {
            Id = "github-app-token",
            Name = "GitHub App Token",
            Pattern = @"(?:ghu|ghs)_[a-zA-Z0-9]{36}",
            Description = "GitHub App installation or user-to-server tokens.",
            Severity = Severity.High,
            Remediation = "These tokens are typically short-lived. Investigate how it was exposed."
        },
        
        // OPENAI
        new SecretPattern
        {
            Id = "openai-api-key",
            Name = "OpenAI API Key",
            Pattern = @"sk-[a-zA-Z0-9]{48}",
            Description = "OpenAI API keys grant access to GPT models and can incur usage charges.",
            Severity = Severity.High,
            Remediation = """
                1. Rotate the key in OpenAI dashboard
                2. Check usage history for unauthorized calls
                3. Set usage limits in your OpenAI account
                """
        },
        
        // SLACK
        new SecretPattern
        {
            Id = "slack-bot-token",
            Name = "Slack Bot Token",
            Pattern = @"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
            Description = "Slack bot tokens allow applications to act as a bot in Slack workspaces.",
            Severity = Severity.High,
            Remediation = """
                1. Regenerate the token in your Slack app settings
                2. Review bot permissions - use minimal scopes
                """
        },
        
        new SecretPattern
        {
            Id = "slack-webhook",
            Name = "Slack Webhook URL",
            Pattern = @"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}",
            Description = "Slack webhook URLs can post messages to channels.",
            Severity = Severity.Medium,
            Remediation = "Regenerate the webhook in Slack app settings."
        },
        
        // GENERIC PATTERNS
        new SecretPattern
        {
            Id = "private-key",
            Name = "Private Key",
            Pattern = @"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            Description = "Private keys are used for authentication and encryption.",
            Severity = Severity.Critical,
            Remediation = """
                1. Consider this key compromised - generate a new key pair
                2. Remove the old public key from all authorized_keys files
                3. Use ssh-agent for SSH keys instead of storing them in project directories
                """
        },
        
        new SecretPattern
        {
            Id = "generic-api-key",
            Name = "Generic API Key Assignment",
            Pattern = @"(?i)(?:api[_-]?key|apikey)['""]?\s*[:=]\s*['""]([a-zA-Z0-9_\-]{20,})['""]?",
            Description = "A value assigned to a variable that looks like an API key.",
            Severity = Severity.Medium,
            Remediation = """
                1. Identify what service this key belongs to
                2. Rotate the key with that service
                3. Use environment variables or a secrets manager
                """
        },
        
        new SecretPattern
        {
            Id = "generic-password",
            Name = "Password Assignment",
            Pattern = @"(?i)(?:password|passwd|pwd)['""]?\s*[:=]\s*['""]([^'""]{8,})['""]",
            Description = "A value assigned to a password variable.",
            Severity = Severity.High,
            Remediation = """
                1. Change this password immediately
                2. Check if this password was reused anywhere else
                3. Use environment variables or a secrets manager
                """
        },
        
        new SecretPattern
        {
            Id = "connection-string",
            Name = "Database Connection String",
            Pattern = @"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'""<>]+:[^\s'""<>]+@[^\s'""<>]+",
            Description = "Database connection strings often contain credentials.",
            Severity = Severity.Critical,
            Remediation = """
                1. Change the database password immediately
                2. Check database logs for unauthorized access
                3. Use environment variables for connection strings
                """
        },
        
        // CLOUD PROVIDERS
        new SecretPattern
        {
            Id = "gcp-api-key",
            Name = "Google Cloud API Key",
            Pattern = @"AIza[0-9A-Za-z\-_]{35}",
            Description = "Google Cloud API keys can access various Google services.",
            Severity = Severity.High,
            Remediation = """
                1. Delete and recreate the key in Google Cloud Console
                2. Add API restrictions to limit which APIs the key can access
                """
        },
        
        new SecretPattern
        {
            Id = "gcp-service-account",
            Name = "Google Cloud Service Account Key",
            Pattern = @"""private_key"":\s*""-----BEGIN [A-Z]+ PRIVATE KEY-----",
            Description = "Google Cloud service account private keys provide full access to GCP resources.",
            Severity = Severity.Critical,
            Remediation = """
                1. Delete this service account key in GCP Console
                2. Use Workload Identity Federation instead of key files
                """
        },
        
        new SecretPattern
        {
            Id = "azure-connection-string",
            Name = "Azure Storage Connection String",
            Pattern = @"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};",
            Description = "Azure Storage connection strings provide full access to storage accounts.",
            Severity = Severity.Critical,
            Remediation = """
                1. Rotate the storage account keys in Azure Portal
                2. Use Managed Identity instead of connection strings
                """
        }
    ];
}