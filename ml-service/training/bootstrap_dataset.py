from __future__ import annotations

import csv
import random
import string
from pathlib import Path
from urllib.parse import quote

SEED = 20261002
OUT = Path(__file__).resolve().parents[1] / "data" / "bootstrap_urls.csv"

LEGIT_DOMAINS = [
    "google.com", "wikipedia.org", "microsoft.com", "apple.com", "github.com",
    "stackoverflow.com", "mozilla.org", "python.org", "npmjs.com", "pypi.org",
    "developer.mozilla.org", "openai.com", "cloudflare.com", "ubuntu.com",
    "debian.org", "kernel.org", "mit.edu", "stanford.edu", "iiit.ac.in",
    "who.int", "un.org", "postgresql.org", "docker.com",
    "vercel.com", "netlify.com", "aws.amazon.com", "azure.microsoft.com",
]

LEGIT_PATHS = [
    "", "about", "docs", "help", "products", "pricing", "blog", "news",
    "search?q={token}", "articles/{token}", "docs/{token}/guide", "account/settings", "login", "signin", "support", "verify-email",
]

PHISH_DOMAINS = [
    "secure-account-check", "verify-user-login", "account-security-alert", "wallet-verify",
    "billing-confirmation", "support-verification", "login-authentication", "payment-update",
    "microsoft-security", "apple-id-verify", "google-account-check", "paypal-resolution",
]

PHISH_TLDS = ["com", "net", "org", "co", "xyz", "top", "click", "site", "online", "live", "icu", "shop"]
PHISH_PATHS = [
    "login", "signin", "verify", "verification", "account/verify", "secure/login",
    "update/payment", "auth/session", "recover/password", "wallet/connect",
    "billing/confirm", "security/check", "identity/verify",
]


def token(rng: random.Random, n: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(n))


def legit_url(rng: random.Random, index: int) -> str:
    domain = LEGIT_DOMAINS[index % len(LEGIT_DOMAINS)]
    path_template = LEGIT_PATHS[(index // len(LEGIT_DOMAINS)) % len(LEGIT_PATHS)]
    if path_template.startswith("search?"):
        path = path_template.format(token=quote(f"docs-{index}-{token(rng, 8)}"))
    elif path_template:
        path = f"{path_template}/{token(rng, 10)}"
    else:
        path = f"page/{token(rng, 10)}"
    scheme = "https"
    return f"{scheme}://{domain}/{path}"


def phishing_url(rng: random.Random, index: int) -> str:
    # Explicit hard cases exercise URL features that are easy to miss in small synthetic corpora.
    if index % 17 == 0:
        octet = 2 + (index // 17) % 200
        return f"http://192.0.2.{octet}/account/verify/{index}-{token(rng, 10)}"

    brand = PHISH_DOMAINS[index % len(PHISH_DOMAINS)]
    subdomains = rng.choice(["", "secure.", "account.secure.", "login.verify.", f"{token(rng,4)}.secure."])
    domain = f"{brand}-{token(rng, 4)}.{rng.choice(PHISH_TLDS)}"
    path = rng.choice(PHISH_PATHS)
    if index % 19 == 0:
        path = f"portal//{path}"
    q = rng.choice([
        "", f"?session={token(rng,16)}", f"?redirect=https%3A%2F%2Fexample.com%2Flogin",
        f"?continue=%2Faccount%2Fverify&id={token(rng,10)}",
    ])
    q = f"?case={index}-{token(rng, 6)}" if not q else f"{q}&case={index}"
    scheme = rng.choice(["http", "https"])
    extra = rng.choice(["", "@trusted.example", "-secure"])
    return f"{scheme}://{subdomains}{brand}{extra}.{domain.split('.',1)[1]}/{path}{q}" if extra == "@trusted.example" else f"{scheme}://{subdomains}{domain}/{path}{q}"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)
    rows: list[tuple[str, int]] = []
    n_per_class = 1800
    for i in range(n_per_class):
        rows.append((legit_url(rng, i), 0))
        rows.append((phishing_url(rng, i), 1))
    rng.shuffle(rows)
    canonical_urls = [url.split("#", 1)[0] for url, _ in rows]
    if len(set(canonical_urls)) != len(canonical_urls):
        raise RuntimeError("Bootstrap generator produced duplicate canonical URLs.")
    with OUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["url", "label", "source"])
        for url, label in rows:
            writer.writerow([url, label, "bootstrap-template"])
    print(f"Wrote {len(rows):,} rows to {OUT}")
    print("NOTE: This corpus is an executable bootstrap dataset, not a substitute for an external real-world benchmark.")


if __name__ == "__main__":
    main()
