import re

TENANT_NAMES = [
    "Mescalero Gas Co.",
    "Wallis Oil Co.",
    "Brown's Oil Service",
    "Lonewolf Petroleum",
    "Fronk Oil Co, Inc.",
    "Mobile Fuel Services",
    "Hutchens Petroleum",
    "Paul Murray Oil",
    "Hunt & Sons, Inc.",
    "G Cooper Oil Co Inc",
    "Ricochet Fuel Distributors",
    "Delta Fuel Company",
    "Lucky's Energy Service",
    "Melzers Fuel Service",
    "ABS / Haffner",
    "Tri Star Energy",
    "FuelSource, Inc AKA (Behnke Investments)",
    "Blu Petroleum",
    "Heritage Petroleum",
    "Dogpatch Biofuels",
    "Foster Fuels",
    "Sprague Operating Resources",
    "Rossee Oil",
    "MTI",
    "United SW fuels",
    "Rock Canyon",
    "Whitener Enterprises",
    "On Site Fuels",
    "Arnold Oil",
    "Pacific States Petroleum",
    "Moffitt",
    "Coleman Oil",
    "3L",
    "Monument",
    "McNeece Bros",
    "Seminole",
    "Robco",
    "FleetFuels",
    "California fuels",
]

# Pricing matches within 150 chars of any of these phrases are treated as
# feature-documentation references and suppressed from Internal Pricing findings.
FEATURE_PRICING_EXCLUSION_RE = re.compile(
    r'(?i)\b('
    r'bol\s+pricing|vendor\s+pricing|temporary\s+pricing|fleet\s+pricing|'
    r'rack\s+pricing|site\s+pricing|card\s+pricing|contract\s+pricing|'
    r'cost\s*\+\s*pricing|cost\s*plus\s+pricing|'
    r'pricing\s+feature|pricing\s+module|pricing\s+configuration|'
    r'pricing\s+settings?|pricing\s+page|pricing\s+tab|pricing\s+screen|'
    r'pricing\s+workflow|pricing\s+overview|pricing\s+guide|pricing\s+type|'
    r'pricing\s+model|pricing\s+option|pricing\s+rule|pricing\s+logic|'
    r'pricing\s+engine|pricing\s+setup|pricing\s+functionality|'
    r'pricing\s+document|pricing\s+spec|'
    r'price\s+type|price\s+code|price\s+book|price\s+group|price\s+level|'
    r'price\s+schedule|price\s+rule|price\s+list|'
    r'navigate\s+to\s+pricing|go\s+to\s+pricing|open\s+pricing|'
    r'pricing\s+section|pricing\s+field|pricing\s+form'
    r')\b'
)

# Security scanning regex patterns grouped by category
SECURITY_PATTERNS = {
    "api_keys_tokens": {
        "severity": "High",
        "patterns": [
            (re.compile(r'(?i)(api[_\-\s]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{16,})["\']?'), "API Key"),
            (re.compile(r'(?i)(secret[_\-\s]?key|secret[_\-\s]?token)\s*[=:]\s*["\']?([A-Za-z0-9\-_/+]{16,})["\']?'), "Secret Key/Token"),
            (re.compile(r'(?i)(access[_\-\s]?token|bearer[_\-\s]?token)\s*[=:]\s*["\']?([A-Za-z0-9\-_.+/]{20,})["\']?'), "Access/Bearer Token"),
            (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{6,})["\']?'), "Password"),
            (re.compile(r'(?i)(private[_\-\s]?key)\s*[=:]\s*["\']?([A-Za-z0-9\-_/+=]{20,})["\']?'), "Private Key"),
            (re.compile(r'(?i)(connection[_\-\s]?string|conn[_\-\s]?str)\s*[=:]\s*["\']?([^\s"\']{10,})["\']?'), "Connection String"),
            (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID"),
            (re.compile(r'(?i)(client[_\-\s]?secret)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{16,})["\']?'), "Client Secret"),
            (re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'), "PEM Private Key Block"),
        ],
    },
    "internal_pricing": {
        "severity": "Medium",
        "patterns": [
            (re.compile(r'(?i)(unit[_\s]?cost|cost[_\s]?per[_\s]?unit)\s*[=:$]?\s*\$?\d+[\.,]\d*'), "Unit Cost"),
            (re.compile(r'(?i)(margin|gross[_\s]?margin|net[_\s]?margin)\s*[=:]\s*\d+[\.,]?\d*\s*%?'), "Margin"),
            (re.compile(r'(?i)(discount[_\s]?structure|discount[_\s]?tier|pricing[_\s]?tier)\s*[=:\-]'), "Discount/Pricing Tier"),
            (re.compile(r'(?i)(internal[_\s]?price|cost[_\s]?breakdown|price[_\s]?breakdown)\s*[=:\-]'), "Internal Price/Cost Breakdown"),
            (re.compile(r'(?i)(markup|mark[_\-]?up)\s*[=:]\s*\d+[\.,]?\d*\s*%?'), "Markup"),
            (re.compile(r'(?i)wholesale\s+price\s*[=:$]?\s*\$?\d+'), "Wholesale Price"),
            (re.compile(r'(?i)(cost[_\s]?basis|landed[_\s]?cost)\s*[=:$]?\s*\$?\d+'), "Cost Basis/Landed Cost"),
        ],
    },
    "customer_pii": {
        "severity": "High",
        "patterns": [
            (re.compile(r'(?i)(account[_\s]?number|acct[_\s]?no|acct[_\s]?#)\s*[=:#]?\s*([A-Z0-9\-]{4,})'), "Account Number"),
            # @fleetpanda.com excluded — internal company addresses
            (re.compile(r'\b[A-Za-z0-9._%+\-]+@(?!fleetpanda\.com\b)[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), "Email Address"),
            (re.compile(r'(?i)(ssn|social[_\s]?security)\s*[=:#]?\s*\d{3}[-\s]?\d{2}[-\s]?\d{4}'), "SSN"),
            (re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'), "Phone Number"),
            (re.compile(r'(?i)(contract[_\s]?value|deal[_\s]?value|contract[_\s]?amount)\s*[=:$]?\s*\$?\d[\d,]*'), "Contract Value"),
            (re.compile(r'(?i)(contract[_\s]?term|contract[_\s]?expir|agreement[_\s]?expir)\s*[=:\-]'), "Contract Term/Expiry"),
            (re.compile(r'(?i)(contact[_\s]?info|billing[_\s]?address|ship[_\s]?to)\s*[=:\-]'), "Contact/Billing Info"),
        ],
    },
    "competitor_intel": {
        "severity": "Medium",
        "patterns": [
            (re.compile(r'(?i)(competitor|competition|rival)\s+(price|pricing|cost|rate|quote)'), "Competitor Pricing"),
            (re.compile(r'(?i)(win[_\s]?loss|lost[_\s]?deal|lost[_\s]?to)\s*[=:\-]'), "Win/Loss Data"),
            (re.compile(r'(?i)(competitive[_\s]?intel|market[_\s]?intel|competitive[_\s]?analysis)\s*[=:\-]'), "Competitive Analysis"),
            (re.compile(r'(?i)(beat|undercut|outbid)\s+[A-Z][a-z]+\s+(oil|fuel|petroleum|energy)'), "Competitor Strategy"),
            (re.compile(r'(?i)(strategic[_\s]?assessment|swot|market[_\s]?position)\s*[=:\-]'), "Strategic Assessment"),
        ],
    },
}

GOOGLE_DRIVE_FOLDER_PATH = ["Documentation", "102 Documents"]
TOKEN_FILE = "token.json"
CREDENTIALS_FILE = "credentials.json"
SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]
