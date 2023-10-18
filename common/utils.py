from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app_scan.common.downloaders import VdooArtifactTypes, get_vdoo_artifact_type, get_artifact_downloader
from app_scan.common.log import LoggerType


def decrypt(key: str, cipher: str) -> str:
    _NONCE_LEN = 12
    cipher_bytes = bytes.fromhex(cipher)
    if len(key) == 32:
        # key is plain text
        key_bytes = key.encode()
    else:
        # key is hex encoded
        key_bytes = bytes.fromhex(key)
    nonce, ciphertext = cipher_bytes[:_NONCE_LEN], cipher_bytes[_NONCE_LEN:]
    aesgcm = AESGCM(key_bytes)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


def download_artifact(artifact_url: str,
                      image_manifest_url: str,
                      download_path: str,
                      artifactory_token: str,
                      xray_version: str,
                      g_logger: LoggerType):
    vdoo_artifact_type = get_vdoo_artifact_type(docker_artifact_manifest_url=image_manifest_url,
                                                artifact_url=artifact_url)
    _artifact_url = artifact_url
    if vdoo_artifact_type == VdooArtifactTypes.CONTAINER:
        _artifact_url = image_manifest_url

    g_logger.info(f'vdoo_artifact_type={vdoo_artifact_type}')
    downloader_class = get_artifact_downloader(vdoo_artifact_type)
    if not downloader_class:
        raise RuntimeError(f"Downloader was not found for {_artifact_url}")

    download_manager = downloader_class(artifact_url=_artifact_url,
                                        logger=g_logger,
                                        artifactory_token=artifactory_token,
                                        xray_version=xray_version)
    local_file_path = download_manager.download(download_path)

    return local_file_path, vdoo_artifact_type, download_manager.get_jfrog_artifact_type(local_file_path)
