#!/usr/bin/env python3
"""
Command-line interface for iAnonymiser.

Works directly against the anonymization engine (core.Anonymizer) — no
running server required.

Once installed (`pip install .`), use the standalone commands:
    anonymize app.log
    anonymize app.log -o app.anon.log --preset kubernetes
    cat app.log | anonymize - > app.anon.log
    deanonymize llm_response.txt --mapping app.log.mapping.json

Without installing, run this file directly instead:
    python cli.py anonymize app.log
    python cli.py deanonymize llm_response.txt --mapping app.log.mapping.json
"""

import argparse
import sys
from pathlib import Path

from core import Anonymizer


def _read_input(path: str) -> str:
    if path == '-':
        return sys.stdin.read()
    return Path(path).read_text(encoding='utf-8')


def _write_output(path: str, content: str) -> None:
    if path:
        Path(path).write_text(content, encoding='utf-8')
    else:
        sys.stdout.write(content)


def _add_anonymize_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('input', help="Input file, or '-' for stdin")
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('--preset', help='Preset to load (e.g. kubernetes, ansible, aws, security, minimal)')
    parser.add_argument('--preserve', action='append', default=[], help='Value to never anonymize (repeatable)')
    parser.add_argument('--mapping-out', help='Where to save the mapping file (default: <input>.mapping.json)')


def _add_deanonymize_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('input', help="Input file (e.g. an LLM response), or '-' for stdin")
    parser.add_argument('--mapping', required=True, help="Mapping file produced by 'anonymize'")
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')


def cmd_anonymize(args: argparse.Namespace) -> None:
    anon = Anonymizer()
    if args.preset:
        if not anon.load_preset(args.preset):
            print(f"error: unknown preset '{args.preset}'", file=sys.stderr)
            sys.exit(1)
    for value in args.preserve:
        anon.add_preserve_value(value)

    text = _read_input(args.input)
    result = anon.anonymize(text)

    mapping_path = args.mapping_out or ('mapping.json' if args.input == '-' else f'{args.input}.mapping.json')
    Path(mapping_path).write_text(anon.export_mappings(format='json'), encoding='utf-8')

    _write_output(args.output, result.anonymized_text)

    total = sum(result.stats.values())
    print(f"iAnonymiser: {total} value(s) replaced. Mapping saved to {mapping_path}", file=sys.stderr)


def cmd_deanonymize(args: argparse.Namespace) -> None:
    anon = Anonymizer()
    mapping_data = Path(args.mapping).read_text(encoding='utf-8')
    if not anon.import_mappings(mapping_data, format='json'):
        print(f"error: could not read mapping file '{args.mapping}'", file=sys.stderr)
        sys.exit(1)

    text = _read_input(args.input)
    _write_output(args.output, anon.deanonymize(text))


def anonymize_main() -> None:
    """Entry point for the standalone `anonymize` command."""
    parser = argparse.ArgumentParser(
        prog='anonymize',
        description='Replace sensitive data with placeholders (iAnonymiser).',
    )
    _add_anonymize_args(parser)
    cmd_anonymize(parser.parse_args())


def deanonymize_main() -> None:
    """Entry point for the standalone `deanonymize` command."""
    parser = argparse.ArgumentParser(
        prog='deanonymize',
        description='Restore original values using a mapping file (iAnonymiser).',
    )
    _add_deanonymize_args(parser)
    cmd_deanonymize(parser.parse_args())


def main() -> None:
    """Entry point for `python cli.py <anonymize|deanonymize> ...` (no install required)."""
    parser = argparse.ArgumentParser(
        prog='ianonymiser',
        description='Sanitize logs/configs locally before sharing them with an LLM.',
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    p_anon = subparsers.add_parser('anonymize', help='Replace sensitive data with placeholders')
    _add_anonymize_args(p_anon)
    p_anon.set_defaults(func=cmd_anonymize)

    p_dean = subparsers.add_parser('deanonymize', help='Restore original values using a mapping file')
    _add_deanonymize_args(p_dean)
    p_dean.set_defaults(func=cmd_deanonymize)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
