import os
import subprocess
import sys
import time
import uuid

from app_scan.common.defs import JfrogArtifactTypes
from app_scan.common.log import configure_logging
from app_scan.common.utils import decrypt, download_artifact

g_logger = configure_logging("expscan")


def run_extractor(artifact_path, extracted_dir_path, vdoo_artifact_type):
    extractor_args = [
        "/extractor_venv/bin/vdoo_extractor",
        artifact_path,
        extracted_dir_path,
        "-t",
        str(vdoo_artifact_type),
    ]
    g_logger.info("going to run extractor: %s", extractor_args)
    process = subprocess.run(extractor_args)
    g_logger.info("extractor return code: %s", process.returncode)
    process.check_returncode()
    if os.environ.get("DEBUG_MODE"):
        g_logger.info("Extracted:")
        for root, dirs, files in os.walk(extracted_dir_path):
            for file in files:
                g_logger.info(os.path.join(root, file))


def run_analyzers(extracted_dir_path, scanners_types, jfrog_artifact_type):
    analyzers_args = ["/analyzers_venv/bin/exposure", "-f", extracted_dir_path]
    if scanners_types:
        scanners_types_list = (
            scanners_types.split(" ")
            if " " in scanners_types
            else scanners_types.split(",")
        )
        analyzers_args += [
            item
            for sublist in (["-t", x] for x in scanners_types_list)
            for item in sublist
        ]
    else:
        if jfrog_artifact_type == JfrogArtifactTypes.TERRAFORM:
            analyzers_args += ["-t", "IAC"]
        else:
            analyzers_args += [
                item
                for sublist in (
                    ["-t", x]
                    for x in ["MALICIOUS-CODE", "SERVICES", "SECRETS", "APPLICATIONS"]
                )
                for item in sublist
            ]
    g_logger.info("going to run analyzers: %s", analyzers_args)
    process = subprocess.run(analyzers_args)
    g_logger.info("analyzers return code: %s", process.returncode)
    process.check_returncode()


def main():
    (
        xray_version,
        artifactory_token,
        xray_token,
        image_manifest_url,
        artifact_url,
        scanners_types,
    ) = handle_input()
    dir_path = f"/var/firmware_store/{uuid.uuid4()}/"
    os.makedirs(dir_path, exist_ok=True)
    download_path = os.path.join(dir_path, "downloaded")
    os.makedirs(download_path, exist_ok=True)
    scan_start_time = time.time()
    artifact_path, vdoo_artifact_type, jfrog_artifact_type = download_artifact(
        artifact_url,
        image_manifest_url,
        download_path,
        artifactory_token,
        xray_version,
        g_logger,
    )
    g_logger.info(
        "Total download time", extra={"total_time": time.time() - scan_start_time}
    )
    extracted_dir_path = os.path.join(dir_path, "extracted")

    start_time = time.time()
    run_extractor(artifact_path, extracted_dir_path, vdoo_artifact_type)
    g_logger.info(
        "Total run time of extractor", extra={"total_time": time.time() - start_time}
    )

    start_time = time.time()
    run_analyzers(extracted_dir_path, scanners_types, jfrog_artifact_type)
    g_logger.info(
        "Total run time of analyzers", extra={"total_time": time.time() - start_time}
    )
    g_logger.info(
        "Done with exposures scanner container",
        extra={"total_time": time.time() - scan_start_time},
    )


def handle_input():
    if (xray_version := os.environ.get("XRAY_VERSION")) is None:
        raise ValueError("missing XRAY_VERSION")
    if (artifactory_token := os.environ.get("ARTIFACTORY_TOKEN")) is None:
        raise ValueError("missing ARTIFACTORY_TOKEN")
    if (xray_token := os.environ.get("XRAY_TOKEN")) is None:
        raise ValueError("missing XRAY_TOKEN")

    if artifactory_token.startswith("ey") or artifactory_token.startswith(
        "cm"
    ):  # JWT tokens start with ey
        g_logger.info("assuming input is not encrypted")
    else:  # assume encrypted
        g_logger.info("got encrypted tokens, decrypting...")
        if (aes_key := os.environ.get("SECRET_AES_KEY")) is None:
            raise ValueError("input encrypted without AES key")
        artifactory_token = decrypt(aes_key, artifactory_token)
        os.environ["XRAY_TOKEN"] = f"Bearer {decrypt(aes_key, xray_token)}"
        g_logger.info("tokens decrypted")

    image_manifest_url = os.environ.get("IMAGE_MANIFEST_URL", "")
    artifact_url = os.environ.get("ARTIFACT_URL", "")
    if os.environ.get("DEBUG_MODE"):
        image_manifest_url = image_manifest_url.replace("localhost", "router")
    if not image_manifest_url and not artifact_url:
        raise ValueError(
            "IMAGE_MANIFEST_URL, ARTIFACT_URL - Definition of one of them is needed"
        )
    if image_manifest_url and artifact_url:
        raise ValueError(
            "IMAGE_MANIFEST_URL, ARTIFACT_URL - Only one of them needs to be defined"
        )

    if "SCAN_ID" not in os.environ:
        raise ValueError("missing SCAN_ID")
    if (exp_runs_tbl_id := os.environ.get("EXPOSURES_RUNS_TBL_ID")) is None:
        raise ValueError("missing EXPOSURES_RUNS_TBL_ID")
    if (exp_results_url := os.environ.get("EXPOSURES_RESULTS_URL")) is None:
        raise ValueError("missing EXPOSURES_RESULTS_URL")

    scanners_types = os.environ.get("SCANNERS_TYPES", None)

    g_logger.info("IMAGE_MANIFEST_URL", extra={"image_manifest_url": image_manifest_url})
    g_logger.info("ARTIFACT_URL", extra={"artifact_url": artifact_url})
    g_logger.info("EXPOSURES_RUNS_TBL_ID", extra={"exp_runs_tbl_id": exp_runs_tbl_id})
    g_logger.info("EXPOSURES_RESULTS_URL", extra={"exp_results_url": exp_results_url})
    return (
        xray_version,
        artifactory_token,
        xray_token,
        image_manifest_url,
        artifact_url,
        scanners_types,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        g_logger.exception(f"Exposures scanner got exception {repr(e)}")
        sys.exit(1)
