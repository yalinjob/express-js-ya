import asyncio
import os
import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests
import uvloop

from app_scan.common.artifact_manager import ArtifactManager
from app_scan.common.defs import JfrogArtifactTypes
from app_scan.common.log import LoggerType

DOCKER_V1_FILES = ["layer.tar", "VERSION", "json"]
SHA256_REGEX = re.compile(r"[0-9a-f]{64}")
uvloop.install()


class DockerDownloader(ArtifactManager):
    def __init__(
        self,
        logger: LoggerType,
        artifactory_token: str,
        xray_version: str,
        artifact_url: str,
    ):
        super().__init__(logger, artifactory_token, xray_version, artifact_url)
        parsed_uri = urlparse(self.artifact_url)
        self.artifact_repo_name = self.get_repository_name(parsed_uri)
        self.docker_api_url = f"{self.artifactory_host}/v2/{self.artifact_repo_name}"
        # artifactory manifest url template: https://<host>/artifactory/<repo_name>/<path>/<tag>/manifest.json
        # parsed_uri.path == /artifactory/<repo_name>/<path>/<tag>/manifest.json
        self.image_path = "/".join(parsed_uri.path.split("/")[3:-2])
        self.image_tag = parsed_uri.path.split("/")[-2]

    def get_repository_name(self, uri) -> str:
        data = uri.path.split('/')
        if len(data) > 3:
            return data[2]
        return ""

    def validate_digest(self, digest: str):
        if not SHA256_REGEX.fullmatch(digest):
            raise Exception("Not a sha256 hash!")

    def download(self, download_path: str) -> str:
        manifest_data = self.load_manifest_data(download_path)
        if isinstance(manifest_data, list):
            layers_url = self.artifact_url.removesuffix("manifest.json")
            for manifest_json in manifest_data:
                for layer in manifest_json["Layers"]:
                    layer_url = f"{layers_url}{layer}"
                    digest = layer.removesuffix("/layer.tar")
                    self.validate_digest(digest)
                    digest_path = os.path.join(download_path, digest)
                    os.mkdir(digest_path)
                    for file in DOCKER_V1_FILES:
                        self.download_file(
                            layer_url,
                            self.headers,
                            os.path.join(digest_path, file),
                        )
                self.download_config(download_path, layers_url, manifest_json)
        else:
            layers = manifest_data["layers"]
            self.logger.info("starting to download layers")
            files_to_download = []
            for layer in layers:
                layers_digest = layer["digest"].removeprefix("sha256:")
                self.validate_digest(layers_digest)
                layer_url = f"{self.docker_api_url}/{self.image_path}/blobs/{layer['digest']}"
                files_to_download.append(
                    (layer_url, os.path.join(download_path, layers_digest))
                )
            config_digest = manifest_data["config"]["digest"].removeprefix("sha256:")
            self.validate_digest(config_digest)
            config_url = f"{self.docker_api_url}/{self.image_path}/blobs/{manifest_data['config']['digest']}"
            files_to_download.append((config_url, os.path.join(download_path, config_digest)))
            asyncio.run(self.download_files(files_to_download))
        if os.environ.get("DEBUG_MODE"):
            self.logger.info(f"Downloaded: {os.listdir(download_path)}")
        self.logger.info("download_image finished")
        return download_path

    def get_config_url(self, layers_url, manifest_data):
        if "Config" in manifest_data:
            config_digest = manifest_data["Config"]
            config_url = f"{layers_url}{config_digest}"
        else:
            config_algo, config_digest = manifest_data["config"]["digest"].split(":")
            config_identifier = f"{config_algo}__{config_digest}"
            config_url = f"{layers_url}{config_identifier}"
        return config_url, config_digest

    async def download_files(self, downloads: List[Tuple[str, str]]):
        await asyncio.gather(
            *(
                self.async_download_file(url, self.headers, download_path)
                for url, download_path in downloads
            )
        )

    def download_config(self, download_path: str, layers_url: str, manifest_data: Dict):
        self.logger.info("downloaded layers, downloading config")
        config_url, config_digest = self.get_config_url(layers_url, manifest_data)
        config_r = requests.get(config_url, headers=self.headers)
        config_r.raise_for_status()
        config_path = os.path.join(
            download_path,
            f'{config_digest}{".json" if not config_digest.endswith(".json") else "" }',
        )
        
        with open(config_path, "w") as f:
            f.write(config_r.text)
        self.logger.info("downloaded config")

    def load_manifest_data(self, download_path: str) -> Dict:
        self.logger.info("starting to download manifest.json")
        headers = self.headers.copy()
        headers['Accept'] = "application/vnd.docker.distribution.manifest.v1+json," \
                            "application/vnd.docker.distribution.manifest.v1+prettyjws," \
                            "application/vnd.docker.distribution.manifest.v2+json," \
                            "application/vnd.oci.image.manifest.v1+json," \
                            "application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json"
        r = requests.get(f"{self.docker_api_url}/{self.image_path}/manifests/{self.image_tag}", headers=headers)
        r.raise_for_status()
        manifest_file_name = os.path.join(download_path, "manifest.json")
        with open(manifest_file_name, "wb") as f:
            f.write(r.content)
        manifest_data = r.json()
        return manifest_data

    def get_jfrog_artifact_type(self, artifact_path: str) -> int:
        return JfrogArtifactTypes.DOCKER
    
    def sanitize_path(user_path):
        return os.path.relpath(os.path.join("/", user_path), "/")
