#!/usr/bin/env python3
import shutil
import subprocess
import sys
import warnings
from pathlib import Path

import rich_click as click
from rich.console import Console
from cryptography import x509
from cryptography.x509.base import Certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.utils import CryptographyDeprecationWarning

console = Console()


def configure_warnings(verbose: bool):
    if not verbose:
        warnings.filterwarnings(
            "ignore",
            message=r"Attribute's length must be >= 1 and <= 64, but it was \d+",
            category=UserWarning,
            module="cryptography.*",
        )
        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


def load_system_trust() -> list[Certificate]:
    """
    Load trusted CA certificates using p11-kit or fallback paths.
    """
    candidates = [
        "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL/Fedora/CentOS
        "/etc/ssl/cert.pem",  # macOS (older versions)
    ]

    # Try using p11-kit if available
    if shutil.which("p11-kit"):
        try:
            result = subprocess.run(
                ["p11-kit", "extract", "--format=pem-bundle", "--filter=ca-anchors"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            return load_certificates_from_bytes(result.stdout)
        except Exception:
            pass

    # Fallback to common files
    for path in candidates:
        p = Path(path)
        if p.exists():
            return load_certificates(p)

    return []


def load_certificates_from_bytes(data: bytes) -> list[Certificate]:
    certs = []
    for block in data.split(b"-----END CERTIFICATE-----"):
        if b"-----BEGIN CERTIFICATE-----" in block:
            cert_pem = block + b"-----END CERTIFICATE-----\n"
            try:
                cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                certs.append(cert)
            except Exception:
                continue
    return certs


def load_certificates(path: Path) -> list[Certificate]:
    """Load one or more certificates from a PEM file."""
    certs = []
    try:
        data = path.read_bytes()
        for block in data.split(b"-----END CERTIFICATE-----"):
            if b"-----BEGIN CERTIFICATE-----" in block:
                cert_pem = block + b"-----END CERTIFICATE-----\n"
                try:
                    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                    certs.append(cert)
                except Exception:
                    continue
    except Exception as e:
        console.print(f"[red]Error reading {path}:[/red] {e}")
    return certs


def load_all_target_certs(target: Path) -> dict[Path, list[Certificate]]:
    """Load certs from a file or directory."""
    results = {}
    if target.is_file():
        certs = load_certificates(target)
        if certs:
            results[target] = certs
    elif target.is_dir():
        for file in target.rglob("*.pem"):
            certs = load_certificates(file)
            if certs:
                results[file] = certs
    else:
        console.print(f"[red]Invalid path:[/red] {target}")
    return results


def cert_fingerprint(cert: Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def is_cert_trusted(
    cert: x509.Certificate, ca_bundle: list[x509.Certificate], verbose: bool = False
) -> bool:
    for ca in ca_bundle:
        try:
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")

                if cert.issuer == ca.subject:
                    # Optional: implement signature verification here if needed

                    if verbose:
                        for warn in w:
                            console.print(
                                "[yellow]⚠ Warning during issuer/subject comparison:[/yellow]"
                            )
                            console.print(
                                f"  Cert subject: {cert.subject.rfc4514_string()}"
                            )
                            console.print(
                                f"  CA subject:   {ca.subject.rfc4514_string()}"
                            )
                            console.print(f"  Message: [dim]{warn.message}[/dim]")

                    return True

        except Exception as e:
            if verbose:
                console.print(f"[red]Error during issuer comparison:[/red] {e}")
    return False


def load_certificates_from_p11kit_file(
    path: Path, verbose: bool = False
) -> list[x509.Certificate]:
    certs = []
    current_lines = []
    in_cert_block = False

    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()

                if stripped.startswith("-----BEGIN CERTIFICATE-----"):
                    in_cert_block = True
                    current_lines = [stripped]
                    continue

                if in_cert_block:
                    current_lines.append(stripped)
                    if stripped.startswith("-----END CERTIFICATE-----"):
                        # Try loading the PEM block
                        try:
                            pem_data = "\n".join(current_lines).encode("utf-8")
                            with warnings.catch_warnings(record=True) as w:
                                warnings.simplefilter("always")
                                cert = x509.load_pem_x509_certificate(
                                    pem_data, default_backend()
                                )
                                if verbose:
                                    for warn in w:
                                        console.print(
                                            "[yellow]⚠ Warning while loading certificate:[/yellow]"
                                        )
                                        console.print(
                                            f"  Cert subject: {cert.subject.rfc4514_string()}"
                                        )
                                        console.print(
                                            f"  Message: [dim]{warn.message}[/dim]"
                                        )
                            certs.append(cert)
                        except Exception as e:
                            if verbose:
                                console.print(
                                    f"[red]Failed to parse PEM cert:[/red] {e}"
                                )
                        in_cert_block = False
                        current_lines = []

        if verbose:
            console.print(
                f"[green]Loaded {len(certs)} certificates from {path}[/green]"
            )

        return certs

    except Exception as e:
        console.print(f"[red]Failed to read {path}:[/red] {e}")
        return []


def load_pristine_redhat_bundle(verbose: bool = False) -> list[x509.Certificate]:
    """
    Loads the pristine Red Hat trust anchors from /usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit.
    This file contains full PEM certs in [p11-kit-object-v1] format.
    """
    path = Path("/usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit")
    if not path.exists():
        console.print(f"[red]File not found:[/red] {path}")
        return []

    return load_certificates_from_p11kit_file(path, verbose=verbose)


@click.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--ca-bundle",
    type=click.Path(exists=True, path_type=Path),
    help="Explicit CA bundle to compare against.",
)
@click.option(
    "--trust",
    is_flag=True,
    help="Use the system trust store (via p11-kit or fallback paths).",
)
@click.option(
    "--pristine",
    is_flag=True,
    help="Use only the pristine system trust bundle (Red Hat only).",
)
@click.option("--verbose", is_flag=True, help="Emit non-fatal warnings.")
def main(
    target: Path, ca_bundle: Path | None, trust: bool, pristine: bool, verbose: bool
):
    """
    Check if certificates in TARGET (file or directory) are included in or trusted by the CA_BUNDLE.
    """

    if sum(map(bool, [trust, pristine, ca_bundle])) != 1:
        console.print(
            "[red]Please specify exactly one of --ca-bundle, --trust, or --pristine[/red]"
        )
        sys.exit(1)

    configure_warnings(verbose)

    # Load CA bundle certs
    if pristine:
        ca_certs = load_pristine_redhat_bundle(verbose=verbose)
    elif trust:
        ca_certs = load_system_trust()
    elif ca_bundle:
        ca_certs = load_certificates(ca_bundle)
    if not ca_certs:
        console.print("[red]No CA certificates loaded.[/red]")
        sys.exit(1)

    ca_fingerprints = {cert_fingerprint(cert) for cert in ca_certs}
    results = load_all_target_certs(target)

    if not results:
        console.print(f"[red]No certificates found in {target}[/red]")
        sys.exit(1)

    overall_success = True

    for path, certs in results.items():
        for idx, cert in enumerate(certs):
            fp = cert_fingerprint(cert)
            subject = cert.subject.rfc4514_string()

            # Check for exact match in CA bundle
            match_found = fp in ca_fingerprints
            trusted = is_cert_trusted(cert, ca_certs)

            if match_found:
                console.print(
                    f"[green]✓ {path} (cert #{idx + 1}): Exact match found in CA bundle[/green]"
                )
            elif trusted:
                console.print(
                    f"[green]✓ {path} (cert #{idx + 1}): Trusted by CA bundle[/green]"
                )
            else:
                console.print(
                    f"[yellow]⚠ {path} (cert #{idx + 1}): No match or trust found[/yellow]"
                )
                overall_success = False
            if verbose:
                console.print(f"  Subject: {subject}")

    if overall_success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
