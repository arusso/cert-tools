import re
import hashlib
from pathlib import Path
import rich_click as click
from cryptography import x509
from cryptography.hazmat.backends import default_backend

@click.command(name="explode-certs")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("output_dir", required=False, type=click.Path(file_okay=False, path_type=Path), default=Path("./output"))
def main(input_file: Path, output_dir: Path):
    """
    Extract individual certificates from a PEM chain and write each to a separate file
    named by its SHA-256 fingerprint.
    """
    if not output_dir.exists():
        output_dir.mkdir(parents=True)

    with input_file.open("rb") as f:
        data = f.read()

    cert_blocks = re.findall(
        b"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        data,
        flags=re.DOTALL,
    )

    if not cert_blocks:
        click.echo(f"[red]No certificates found in {input_file}[/red]")
        raise SystemExit(1)

    for index, block in enumerate(cert_blocks):
        pem = b"-----BEGIN CERTIFICATE-----" + block + b"-----END CERTIFICATE-----\n"

        try:
            cert = x509.load_pem_x509_certificate(pem, default_backend())
            der = cert.public_bytes(encoding=x509.Encoding.DER)
            fingerprint = hashlib.sha256(der).hexdigest().upper()
            output_file = output_dir / f"{fingerprint}.pem"

            with output_file.open("wb") as out:
                out.write(pem)

            click.echo(f"Extracted: {output_file}")

        except Exception as e:
            tmp_file = output_dir / f"cert_{index:03d}.pem"
            with tmp_file.open("wb") as out:
                out.write(pem)
            click.echo(f"[yellow]Failed to parse cert #{index}, written as {tmp_file}[/yellow]")
            if isinstance(e, ValueError):
                click.echo(f"[dim]{e}[/dim]")


if __name__ == '__main__':
    main()
