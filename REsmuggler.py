#!/usr/bin/env python3
from argparse import ArgumentParser
from sys import exit as sys_exit, stdin, version_info
from urllib.parse import urlparse

from lib.colors import Colors
from lib.mutations import MUTATION_PROFILES
from lib.scanner import ScanConfig, SmugglerScanner
from lib.ui import print_banner, print_info
from lib.output_formatter import BatchOutputFormatter


MINIMUM_PYTHON = (3, 8)


def parse_target(url: str):
    if not url or not url.strip():
        raise ValueError("empty target URL")
    url = url.strip()
    if "://" in url:
        scheme = url.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme: {scheme}")
    else:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("missing host")
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    endpoint = parsed.path or "/"
    if parsed.query:
        endpoint = f"{endpoint}?{parsed.query}"
    return parsed.hostname, port, endpoint, use_tls


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="smuggler",
        description="HTTP Request Smuggling scanner with canary-based desync verification.",
    )
    parser.add_argument("-u", "--url", help="Target URL, e.g. https://host/path")
    parser.add_argument("--vhost", default="", help="Override Host header value")
    parser.add_argument("-m", "--method", default="POST", help="HTTP method (default: POST)")
    parser.add_argument("-c", "--config", default="default",
                        choices=list(MUTATION_PROFILES.keys()),
                        help="Mutation profile (default: default)")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Socket timeout in seconds")
    parser.add_argument("-r", "--rate", type=float, default=0.0,
                        help="Minimum delay between probes in seconds")
    parser.add_argument("-x", "--exit-early", action="store_true", help="Stop on first finding")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only print findings")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show progress for every step")
    parser.add_argument("-l", "--log", help="Write a plaintext log to this file")
    parser.add_argument("-j", "--json", action="store_true", help="Output findings as JSON")
    parser.add_argument("--csv", action="store_true", help="Output findings as CSV")
    parser.add_argument("--mutations", action="store_true",
                        help="Enable legacy mutation-loop testing")
    parser.add_argument("--no-canary", action="store_true",
                        help="Skip canary probes (TE.CL / CL.TE / CL.0 / 0.CL)")
    parser.add_argument("--no-cl0", action="store_true",
                        help="Skip only CL.0 / 0.CL canary probes")
    parser.add_argument("--no-single-packet", action="store_true", help="Skip single-packet probes")
    parser.add_argument("--no-parser", action="store_true", help="Skip parser discrepancy probes")
    parser.add_argument("--no-funky", action="store_true", help="Skip funky chunk probes")
    parser.add_argument("--no-timing", action="store_true", help="Skip timing-based probes")
    parser.add_argument("--no-h2c", action="store_true", help="Skip H2C probes")
    parser.add_argument("--no-te0", action="store_true", help="Skip TE.0 probes")
    parser.add_argument("--no-h2", action="store_true", help="Skip HTTP/2 downgrade probes")
    color_group = parser.add_mutually_exclusive_group()
    color_group.add_argument("--color", action="store_true", help="Force ANSI colors")
    color_group.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    return parser


def collect_targets(args) -> list:
    if args.url is not None:
        return [args.url]
    if stdin.isatty():
        return []
    return [line.strip() for line in stdin.read().splitlines() if line.strip()]


def main() -> int:
    if version_info < MINIMUM_PYTHON:
        print(f"Python {MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]}+ is required")
        return 1

    parser = build_parser()
    args = parser.parse_args()

    Colors.autodetect(force=args.color, disabled=args.no_color)

    targets = collect_targets(args)
    if not targets:
        parser.print_help()
        return 1

    print_banner()

    log_handle = open(args.log, "w", encoding="utf-8") if args.log else None
    batch = BatchOutputFormatter(args.config, args.method.upper())

    try:
        try:
            for target in targets:
                try:
                    host, port, endpoint, use_tls = parse_target(target)
                except ValueError as error:
                    print_info("!", f"invalid target: {error}", log_handle, Colors.RED)
                    continue

                print_info("target", f"{host}:{port}{endpoint}", log_handle, Colors.CYAN)
                print_info("method", args.method.upper(), log_handle)
                print_info("timeout", f"{args.timeout}s", log_handle)

                config = ScanConfig(
                    host=host, port=port, endpoint=endpoint,
                    method=args.method.upper(), vhost=args.vhost,
                    use_tls=use_tls, timeout=args.timeout,
                    quiet=args.quiet, verbose=args.verbose,
                    exit_early=args.exit_early,
                    rate_limit=args.rate, log_handle=log_handle,
                    json_output=args.json,
                    test_canary=not args.no_canary,
                    test_cl0=not args.no_cl0,
                    test_single_packet=not args.no_single_packet,
                    test_parser=not args.no_parser,
                    test_funky=not args.no_funky,
                    test_timing=not args.no_timing,
                    test_h2c=not args.no_h2c,
                    test_te0=not args.no_te0,
                    test_h2=not args.no_h2,
                    test_mutations=args.mutations,
                )
                scanner = SmugglerScanner(config)
                if not scanner.prepare():
                    continue
                findings = scanner.scan(MUTATION_PROFILES[args.config]())
                print_info("result", f"{findings} finding(s)", log_handle,
                           Colors.GREEN if findings == 0 else Colors.RED)

                target_name = f"{'https' if use_tls else 'http'}://{host}:{port}{endpoint}"
                batch.add_target(target_name, scanner.get_findings())
        except KeyboardInterrupt:
            print()
            print_info("!", "interrupted by user", log_handle, Colors.YELLOW)
            return 130
    finally:
        if log_handle is not None:
            log_handle.close()

    if args.json:
        print(batch.to_json())
    elif args.csv:
        print(batch.to_csv())

    total = sum(t["findings_count"] for t in batch.targets)
    print_info("total", f"{total} finding(s)", None,
               Colors.GREEN if total == 0 else Colors.RED)
    return batch.exit_code()


if __name__ == "__main__":
    sys_exit(main())
