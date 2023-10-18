import logging
from base64 import b64encode
from pathlib import Path

import typer

from app_scan.common.downloader import DockerDownloader

app = typer.Typer()


def get_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    logger.setLevel(logging.DEBUG)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    return logger


@app.command()
def main(
    manifest_url: str,
    output_dir: Path,
    username: str = typer.Option("admin", "--username", "-u"),
    password: str = typer.Option("password", "--password", "-p"),
):
    if output_dir.is_dir() and any(output_dir.iterdir()):
        typer.secho("Output dir already exists!")
        raise typer.Exit(1)
    output_dir.mkdir(exist_ok=True)

    if not manifest_url.startswith(("http://", "https://")):
        typer.secho("Schema is missing in manifest url! Append http/https to your url")
        raise typer.Exit(1)

    if not manifest_url.endswith("/manifest.json"):
        typer.secho("Url is not ending with manifest.json, appending one.")
        manifest_url = manifest_url.strip("/")
        manifest_url = f"{manifest_url}/manifest.json"

    logger = get_logger()
    docker_downloader = DockerDownloader(logger, "", "3.99", manifest_url)

    auth = (
        "Basic "
        + b64encode(b":".join((username.encode(), password.encode()))).strip().decode()
    )
    docker_downloader.headers["Authorization"] = auth

    docker_downloader.download(str(output_dir))


if __name__ == "__main__":
    app()
