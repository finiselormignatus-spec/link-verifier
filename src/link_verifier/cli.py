import argparse

from link_verifier.core import validate_link


def main():
    parser = argparse.ArgumentParser(description="Check if a URL is legitimate and reachable.")
    parser.add_argument("url", help="The URL to verify")
    parser.add_argument(
        "allowed_domains",
        nargs="*",
        help="Optional allowlist of allowed domains (for example: github.com example.com)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    result = validate_link(args.url, timeout=args.timeout, allowed_domains=args.allowed_domains)

    print(f"URL: {args.url}")
    print(f"Status: {result['status']}")
    print(f"Legit: {result['legit']}")
    print(f"Message: {result['message']}")
    if result.get("final_url"):
        print(f"Final URL: {result['final_url']}")
    if result.get("status_code") is not None:
        print(f"HTTP Status: {result['status_code']}")


if __name__ == "__main__":
    main()
