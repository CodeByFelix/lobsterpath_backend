RULE_BANK = {
    "ingress": {
        "block_prompt_injection": {
            "name": "block_prompt_injection",
            "description": "Detected prompt injection attempt",
            "priority": 100,
            "action": "DENY",
            "deny_message": "Request Blocked: prompt injection detected.",
            "conditions": [{"field": "contains_injection_patterns", "match_type": "boolean", "value": True}]
        },
        "block_sensitive_paths": {
            "name": "block_sensitive_paths",
            "description": "Prompt targets sensitive system paths",
            "priority": 85,
            "action": "DENY",
            "deny_message": "Request Blocked: sensitive path access denied.",
            "conditions": [{"field": "contains_sensitive_paths", "match_type": "boolean", "value": True}]
        },
        "block_harm_violence": {
            "name": "block_harm_violence",
            "description": "Prompt requests instructions for violence or weapons",
            "priority": 98,
            "action": "DENY",
            "deny_message": "Request Blocked: request for harmful content detected.",
            "conditions": [{"field": "contains_harm_patterns", "match_type": "boolean", "value": True}]
        },
        "block_malware_request": {
            "name": "block_malware_request",
            "description": "Prompt requests creation of malware or exploits",
            "priority": 96,
            "action": "DENY",
            "deny_message": "Request Blocked: malware/exploit generation request detected.",
            "conditions": [{"field": "contains_malware_request", "match_type": "boolean", "value": True}]
        },
        "block_phishing_fraud": {
            "name": "block_phishing_fraud",
            "description": "Prompt requests creation of phishing or fraudulent materials",
            "priority": 94,
            "action": "DENY",
            "deny_message": "Request Blocked: phishing/fraud content request detected.",
            "conditions": [{"field": "contains_phishing_patterns", "match_type": "boolean", "value": True}]
        },
        "block_data_exfiltration": {
            "name": "block_data_exfiltration",
            "description": "Prompt contains data exfiltration patterns",
            "priority": 92,
            "action": "DENY",
            "deny_message": "Request Blocked: data exfiltration attempt detected.",
            "conditions": [{"field": "contains_exfiltration", "match_type": "boolean", "value": True}]
        },
        "block_obfuscation_evasion": {
            "name": "block_obfuscation_evasion",
            "description": "Prompt uses encoding or obfuscation to evade detection",
            "priority": 90,
            "action": "DENY",
            "deny_message": "Request Blocked: obfuscation/evasion technique detected.",
            "conditions": [{"field": "contains_obfuscation", "match_type": "boolean", "value": True}]
        },
        "review_role_impersonation": {
            "name": "review_role_impersonation",
            "description": "Prompt attempts to assign a privileged role identity",
            "priority": 86,
            "action": "HUMAN_REVIEW",
            "conditions": [{"field": "contains_role_impersonation", "match_type": "boolean", "value": True}]
        },
        "block_pii_request": {
            "name": "block_pii_request",
            "description": "Prompt is requesting personal/sensitive information",
            "priority": 82,
            "action": "DENY",
            "deny_message": "Request Blocked: request for personal/sensitive information detected.",
            "conditions": [{"field": "contains_pii_request", "match_type": "boolean", "value": True}]
        },
        "block_dangerous_commands": {
            "name": "block_dangerous_commands",
            "description": "Dangerous system commands detected",
            "priority": 80,
            "action": "DENY",
            "deny_message": "Request Blocked: dangerous command detected.",
            "conditions": [
                {"field": "contains_system_commands", "match_type": "boolean", "value": True},
                {"field": "risk_score", "match_type": "threshold", "value": 0.3}
            ]
        },
        "review_high_risk": {
            "name": "review_high_risk",
            "description": "High risk score requires human review",
            "priority": 70,
            "action": "HUMAN_REVIEW",
            "conditions": [{"field": "risk_score", "match_type": "threshold", "value": 0.6}]
        },
        "log_code_execution": {
            "name": "log_code_execution",
            "description": "Log code execution requests",
            "priority": 30,
            "action": "LOG",
            "conditions": [{"field": "intent_category", "match_type": "exact", "value": "code_execution"}]
        }
    },
    "egress": {
        "block_credential_leak": {
            "name": "block_credential_leak",
            "description": "Model output contains credentials",
            "priority": 100,
            "action": "DENY",
            "deny_message": "Output Blocked: contains credentials.",
            "conditions": [{"field": "contains_credentials", "match_type": "boolean", "value": True}]
        },
        "block_pii_leak": {
            "name": "block_pii_leak",
            "description": "Model output contains PII",
            "priority": 90,
            "action": "DENY",
            "deny_message": "Output blocked: contains PII.",
            "conditions": [{"field": "contains_pii", "match_type": "boolean", "value": True}]
        }
    },
    "defaults": {
        "rate_limits": {
            "requests_per_minute": 120,
            "requests_per_hour": 2000,
            "burst_threshold": 30
        },
        "network": {
            "egress_policy": "allowlist",
            "allowed_domains": ["api.openai.com", "api.anthropic.com"],
            "denied_domains": ["*.onion", "pastebin.com"]
        },
        "filesystem": {
            "denied_paths": ["/etc/**", "/root/**", "**/.ssh/**", "**/.env", "**/*secret*", "**/*password*"],
            "allowed_read_paths": ["/home/*/documents/**", "/tmp/agent_workspace/**"],
            "allowed_write_paths": ["/home/*/documents/agent_output/**", "/tmp/agent_workspace/**"]
        }
    }
}

# Master list of OpenAI-compatible LLM providers
PROVIDER_LIST = [
    {"name": "OpenAI", "base_url": "https://api.openai.com/v1"},
    {"name": "Groq", "base_url": "https://api.groq.com/openai/v1"},
    {"name": "Together AI", "base_url": "https://api.together.xyz/v1"},
    {"name": "Perplexity", "base_url": "https://api.perplexity.ai"},
    {"name": "Mistral AI", "base_url": "https://api.mistral.ai/v1"},
    {"name": "DeepSeek", "base_url": "https://api.deepseek.com"},
    {"name": "OpenRouter", "base_url": "https://openrouter.ai/api/v1"},
    #{"name": "Ollama (Local)", "base_url": "http://localhost:11434/v1"},
    #{"name": "LM Studio (Local)", "base_url": "http://localhost:1234/v1"}
]

# Curated stable models for each provider
MODEL_BANK = {
    "OpenAI": [
        "gpt-5.2",
        "gpt-5.2-mini",
        "gpt-5.2-nano",
        "gpt-5.1",
        "gpt-5.1-mini",
        "gpt-5.1-nano",
        "gpt-4.1",
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo"
    ],
    "Groq": [
        "openai/gpt-oss-120b",
        "openai/gpt-oss-20b",
        "llama-3.1-70b-versatile",
        "llama-3.1-8b-instant",
        "llama3-70b-8192",
        "mixtral-8x7b-32768",
        "gemma2-9b-it"
    ],
    "Together AI": [
        "meta-llama/Llama-3-70b-chat-hf",
        "mistralai/Mixtral-8x7B-Instruct-v0.1",
        "databricks/dbrx-instruct",
        "google/gemma-7b-it",
        "Qwen/Qwen2-72B-Instruct"
    ],
    "Perplexity": [
        "llama-3.1-sonar-small-128k-online",
        "llama-3.1-sonar-large-128k-online",
        "llama-3.1-sonar-huge-128k-online",
        "llama-3.1-sonar-small-128k-chat",
        "llama-3.1-sonar-large-128k-chat"
    ],
    "Mistral AI": [
        "mistral-large-latest",
        "open-mistral-nemo",
        "codestral-latest",
        "mistral-medium-latest",
        "mistral-small-latest"
    ],
    "DeepSeek": [
        "deepseek-chat",
        "deepseek-coder"
    ],
    "OpenRouter": [
        "openai/gpt-5.2",
        "anthropic/claude-sonnet-4"
    ]
}
