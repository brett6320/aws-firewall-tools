"""
Local AWS profiles by account id, and account selection for multi-account scans.

Intent: tools that look inside member accounts must use the right local
profile for each account, never a personal/privileged one, and must prove the
profile really belongs to that account before reading anything. This module
holds that logic once, so every tool selects and verifies accounts the same way.

Profiles are read from the local AWS config (AWS_CONFIG_FILE is honoured). A
profile's account is its sso_account_id, aws_account_id, or the account in
its role_arn. Profiles ending in an excluded suffix (default -priv, -cpar) are
never used.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass

import boto3
import botocore.session
from botocore.exceptions import BotoCoreError, ClientError

from lib.aws_common import get_client

log = logging.getLogger("accounts")

DEFAULT_EXCLUDE_SUFFIXES = "-priv,-cpar"
_ACCOUNT_RE = re.compile(r"arn:aws[\w-]*:iam::(\d{12}):")


def profile_account_map(exclude_suffixes: list[str]) -> dict[str, list[str]]:
    """{account_id: [profile, ...]} from the local AWS config, skipping excluded suffixes.
    Account id comes from sso_account_id, aws_account_id, or the role_arn's account."""
    profiles = botocore.session.Session().full_config.get("profiles", {})
    out: dict[str, list[str]] = {}
    for name, cfg in sorted(profiles.items()):
        if any(name.lower().endswith(s.lower()) for s in exclude_suffixes if s):
            continue
        acct = cfg.get("sso_account_id") or cfg.get("aws_account_id")
        if not acct and cfg.get("role_arn"):
            m = _ACCOUNT_RE.match(cfg["role_arn"])
            acct = m.group(1) if m else None
        if acct:
            out.setdefault(str(acct).strip(), []).append(name)
    return out


def profile_lookup(args) -> tuple[dict[str, list[str]], dict[str, str]]:
    """(account -> profiles map, --account-profile overrides) from CLI args."""
    pmap = profile_account_map([s.strip() for s in args.exclude_profile_suffix.split(",")])
    return pmap, dict(x.split("=", 1) for x in args.account_profile or [])


def pick_profile(account: str, pmap: dict[str, list[str]], overrides: dict[str, str]) -> tuple[str | None, str]:
    """Return (profile, note) for an account: an override, else the first matching profile."""
    if account in overrides:
        return overrides[account], "override"
    cands = pmap.get(account, [])
    if not cands:
        return None, "no local profile"
    note = "" if len(cands) == 1 else f"multiple profiles {cands}; using first (override with --account-profile)"
    return cands[0], note


def caller_account(profile: str | None) -> str:
    """Account id the profile's credentials belong to (sts:GetCallerIdentity)."""
    return get_client("sts", boto3.Session(profile_name=profile)).get_caller_identity()["Account"]


def resolve_admin_profile(args) -> str | None:
    """Profile for the FMS administrator account.

    --profile wins; else the profile for --admin-account / FMM_ADMIN_ACCOUNT; else AWS_PROFILE.
    A profile chosen by admin account is verified against that account before use.
    """
    if args.profile:
        return args.profile
    if not args.admin_account:
        return os.getenv("AWS_PROFILE") or None
    profile, note = pick_profile(args.admin_account, *profile_lookup(args))
    if not profile:
        raise ValueError(f"no local AWS profile for FMS admin account {args.admin_account}")
    if note and note != "override":
        log.warning("Admin account %s: %s", args.admin_account, note)
    actual = caller_account(profile)
    if actual != args.admin_account:
        raise ValueError(f"admin profile {profile} resolves to {actual}, expected {args.admin_account}")
    log.info("FMS admin account %s via profile %s", args.admin_account, profile)
    return profile


def add_profile_args(p, admin: bool = False) -> None:
    """Add the profile-mapping flags (and, with admin=True, --admin-account) to a parser."""
    if admin:
        p.add_argument("--admin-account", default=os.getenv("FMM_ADMIN_ACCOUNT") or None, metavar="ACCOUNT_ID",
                       help="FMS administrator (security) account; its local profile is found by account id "
                            "(env FMM_ADMIN_ACCOUNT)")
    p.add_argument("--account-profile", action="append", metavar="ACCOUNT=PROFILE",
                   help="Force the local profile used for an account (repeatable)")
    p.add_argument("--exclude-profile-suffix", default=DEFAULT_EXCLUDE_SUFFIXES,
                   help=f"Comma-separated profile name suffixes never used (default {DEFAULT_EXCLUDE_SUFFIXES})")


def check_profile_args(p, args) -> None:
    """Reject malformed --account-profile values (argparse error)."""
    for x in args.account_profile or []:
        if "=" not in x:
            p.error(f"--account-profile expects ACCOUNT=PROFILE, got {x!r}")


def add_account_args(p) -> None:
    """Add account selection flags for tools that scan member accounts directly."""
    p.add_argument("--profile", default=os.getenv("AWS_PROFILE") or None,
                   help="Scan only this profile's account (default AWS_PROFILE) unless --account/--all-accounts")
    p.add_argument("--account", action="append",
                   help="Account id(s) to scan via their local profiles; repeatable / comma-separated")
    p.add_argument("--all-accounts", action="store_true",
                   help="Scan every account that has a usable local profile")
    add_profile_args(p)


@dataclass
class Target:
    """An account to scan and the verified profile to scan it with.

    `ok` False means the account cannot be scanned; `note` says why. `profile` None with
    ok=True means the default credential chain (no --profile given).
    """
    account: str
    profile: str | None
    ok: bool = True
    note: str = ""        # why it cannot be scanned, or a note about the profile choice

    @property
    def label(self) -> str:
        """Profile name for reports ('default' for the default credential chain)."""
        return self.profile or "default"


def select_accounts(args) -> list[Target]:
    """Accounts to scan, each with a profile verified by sts:GetCallerIdentity.

    --account / --all-accounts pick accounts from the local profile map; otherwise the
    single --profile (or default credentials) account is scanned. Accounts with no profile,
    or whose profile resolves to another account, come back with ok=False and a note.
    """
    pmap, overrides = profile_lookup(args)
    if args.account or args.all_accounts:
        wanted = sorted({a.strip() for item in args.account or [] for a in item.split(",") if a.strip()}
                        | (set(pmap) | set(overrides) if args.all_accounts else set()))
        picked = [(a, *pick_profile(a, pmap, overrides)) for a in wanted]
    else:
        return [Target(caller_account(args.profile), args.profile)]
    out = []
    for account, profile, note in picked:
        if not profile:
            out.append(Target(account, None, False, note))
            continue
        try:
            actual = caller_account(profile)
        except (ClientError, BotoCoreError) as e:
            out.append(Target(account, profile, False, f"profile {profile}: {e}"))
            continue
        if actual != account:
            out.append(Target(account, profile, False, f"profile {profile} resolves to {actual}"))
            continue
        if note and note != "override":
            log.warning("Account %s: %s", account, note)
        out.append(Target(account, profile, True, note if note == "override" else ""))
    return out
