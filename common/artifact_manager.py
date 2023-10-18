from typing import Dict
from urllib.parse import urlparse

import requests
import os
from aiohttp import ClientSession

from app_scan.common.log import LoggerType

CHUNK_SIZE = 256 * 1024


class ArtifactManager:
    def __init__(
        self,
        logger: LoggerType,
        artifactory_token: str,
        xray_version: str,
        artifact_url: str,
    ):
        self.artifact_url = artifact_url
        self.xray_version = xray_version
        self.artifactory_token = artifactory_token
        self.logger = logger
        self.headers = {
            "Authorization": f"Bearer {self.artifactory_token}",
            "User-Agent": "Xray/" + self.xray_version,
        }
        parsed_uri = urlparse(self.artifact_url)
        self.artifactory_host = f"{parsed_uri.scheme}://{parsed_uri.netloc}"

    def get_jfrog_artifact_type(self, artifact_path: str) -> int:
        ...

    def download(self, download_path: str) -> str:
        ...

    @staticmethod
    def download_file(url: str, headers: Dict[str, str], local_filepath: str):
        with requests.get(url, stream=True, headers=headers) as r:
            r.raise_for_status()
            local_filepath = os.path.relpath(os.path.join("/", local_filepath), "/")
            with open(local_filepath, "wb") as f:
                for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                    f.write(chunk)

    async def async_download_file(self, url: str, headers: Dict[str, str], download_path: str):
        download_path = os.path.relpath(os.path.join("/", download_path), "/")
        with open(download_path, "wb") as fd:
            async with ClientSession() as session:
                self.logger.info(f"Going to download from {url}")
                async with session.get(url, headers=headers) as resp:
                    resp.raise_for_status()
                    async for chunk in resp.content.iter_chunked(CHUNK_SIZE):
                        fd.write(chunk)
