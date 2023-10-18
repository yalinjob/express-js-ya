import logging
import os
import uuid

from app_scan.common.artifact_manager import ArtifactManager
from app_scan.common.defs import JfrogArtifactTypes


class SoftwarePackageDownloader(ArtifactManager):
    def __init__(self,
                 logger: logging.Logger,
                 artifactory_token: str,
                 xray_version: str,
                 artifact_url: str):
        super().__init__(logger, artifactory_token, xray_version, artifact_url)

    def download(self, download_path: str):
        self.logger.info(f'download_path={download_path} self.artifact_url={self.artifact_url}')
        local_filename = self.artifact_url.split('/')[-1]
        if not local_filename:
            local_filename = str(uuid.uuid4())
        local_filepath = os.path.join(download_path, local_filename)

        if local_filename == 'state.latest.json':
            # Artifactory API for getting the decrypt JSON file
            # http://router:8046/artifactory/tf-backend/workspaces/jfrog-ws0/state.latest.json
            # http://127.0.0.1:8083/artifactory/api/terraform/remote/v2/workspaces/tf-backend__jfrog-test1/state.latest/state-download
            url_parts = self.artifact_url.split('/')
            if len(url_parts) < 8:
                raise ValueError(f'Insufficient parts in {self.artifact_url}')
            backend = url_parts[4]
            workspace = url_parts[6]
            new_url = f'{url_parts[0]}//{url_parts[2]}/artifactory/api/terraform/remote/v2/workspaces/'
            new_url += f'{backend}__{workspace}/state.latest/state-download'
            self.logger.info(f'Download path for state file: {new_url}')
            self.download_file(new_url, self.headers, local_filepath)
        else:
            self.download_file(self.artifact_url, self.headers, local_filepath)

        return local_filepath

    def get_jfrog_artifact_type(self, artifact_path: str) -> int:
        if 'state.latest.json' in artifact_path:
            return JfrogArtifactTypes.TERRAFORM

        return JfrogArtifactTypes.OTHER
