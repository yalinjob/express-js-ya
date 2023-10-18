import os
import urllib.parse
from typing import Optional, Type

from app_scan.common.artifact_manager import ArtifactManager
from app_scan.common.defs import VdooArtifactTypes
from app_scan.common.downloader import DockerDownloader
from app_scan.common.software_package_downloader import SoftwarePackageDownloader

DOWNLOADERS = {
    VdooArtifactTypes.CONTAINER: DockerDownloader,
    VdooArtifactTypes.SOFTWARE_PACKAGE: SoftwarePackageDownloader,
    VdooArtifactTypes.JAR: SoftwarePackageDownloader,
}


def get_vdoo_artifact_type(docker_artifact_manifest_url: str, artifact_url: str) -> int:
    """
    docker_artifact_manifest_url, artifact_url cannot be both None
    """
    if docker_artifact_manifest_url:
        return VdooArtifactTypes.CONTAINER

    path = urllib.parse.urlparse(artifact_url).path
    ext = os.path.splitext(path)[1]
    if ext.lower() in [".jar", ".war"]:
        return VdooArtifactTypes.JAR

    return VdooArtifactTypes.SOFTWARE_PACKAGE


def get_artifact_downloader(vdoo_artifact: int) -> Optional[Type[ArtifactManager]]:
    return DOWNLOADERS.get(vdoo_artifact, None)
