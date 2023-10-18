import json
import os
import subprocess
import sys
import time
import uuid

import requests

from app_scan.common.log import UBER_TRACE_ID, configure_logging
from app_scan.common.utils import decrypt, download_artifact

g_logger = configure_logging("appscan")


def handle_input():
    xray_version = os.environ.get("XRAY_VERSION")
    if xray_version is None:
        raise ValueError("missing XRAY_VERSION")

    artifactory_token = os.environ.get("ARTIFACTORY_TOKEN")
    if artifactory_token is None:
        raise ValueError("missing ARTIFACTORY_TOKEN")
    xray_token = os.environ.get("XRAY_TOKEN")
    if xray_token is None:
        raise ValueError("missing XRAY_TOKEN")

    if artifactory_token.startswith("ey") or artifactory_token.startswith("cm"):
        # JWT tokens start with ey
        g_logger.info("assuming input is not encrypted")
    else:  # assume encrypted
        g_logger.info("got encrypted tokens, decrypting...")
        aes_key = os.environ.get("SECRET_AES_KEY")
        if aes_key is None:
            raise ValueError("input encrypted without AES key")
        artifactory_token = decrypt(aes_key, artifactory_token)
        xray_token = decrypt(aes_key, xray_token)
        os.environ["XRAY_TOKEN"] = f"Bearer {xray_token}"
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

    result_url = os.environ.get("RESULTS_URL", "")
    if os.environ.get("DEBUG_MODE"):
        result_url = result_url.replace("localhost", "router")
        # Analyzers re-reads RESULT_URL from env. It must be updated to take effect
        os.environ["RESULTS_URL"] = result_url
        g_logger.info(f"Updated env with RESULTS_URL={os.environ.get('RESULTS_URL')}")

    if not result_url:
        raise ValueError("missing RESULTS_URL")

    g_logger.info("IMAGE_MANIFEST_URL", extra={"image_manifest_url": image_manifest_url})
    g_logger.info("RESULT_URL", extra={"result_url": result_url})

    return (
        xray_version,
        artifactory_token,
        image_manifest_url,
        artifact_url,
    )


def run_extractor(dir_path, extracted_dir_path, vdoo_artifact_type):
    extractor_args = [
        "/extractor_venv/bin/vdoo_extractor",
        dir_path,
        extracted_dir_path,
        "-t",
        str(vdoo_artifact_type),
    ]
    g_logger.info("going to run extractor: %s", extractor_args)
    process = subprocess.run(extractor_args)
    g_logger.info("extractor return code: %s", process.returncode)
    process.check_returncode()


def run_analyzers(extracted_dir_path):
    analyzers_args = [
        "/analyzers_venv/bin/applicable",
        "-f",
        extracted_dir_path,
    ]
    g_logger.info("going to run analyzers: %s", analyzers_args)
    process = subprocess.run(analyzers_args)
    g_logger.info("analyzers return code: %s", process.returncode)
    process.check_returncode()


def submit_result(result, result_url, xray_token):
    requests_session = requests.Session()
    headers = {"Authorization": f"Bearer {xray_token}", "uber-trace-id": UBER_TRACE_ID}
    for item_to_submit in result.get("data", []):
        g_logger.info(json.dumps(item_to_submit))
        response = requests_session.put(
            result_url, headers=headers, json=item_to_submit
        )
        g_logger.info(
            "Applicability update response",
            extra={
                "method": response.request.method,
                "url": response.request.url,
                "status_code": response.status_code,
            },
        )


def print_result(image_manifest_url, artifact_url, result):
    url = image_manifest_url or artifact_url
    for item_to_submit in result.get("data", []):
        g_logger.info(
            "artifact: %s component_id: %s vulnerability_id: %s applicable: %s",
            url,
            item_to_submit.get("vulnerable_component_id"),
            item_to_submit.get("vulnerability_id"),
            item_to_submit.get("applicable"),
        )


def main():
    (
        xray_version,
        artifactory_token,
        image_manifest_url,
        artifact_url,
    ) = handle_input()
    dir_path = f"/var/firmware_store/{uuid.uuid4()}/"
    os.makedirs(dir_path, exist_ok=True)
    download_path = os.path.join(dir_path, "downloaded")
    os.makedirs(download_path, exist_ok=True)

    scan_start_time = time.time()
    artifact_path, vdoo_artifact_type, _ = download_artifact(
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
    run_analyzers(extracted_dir_path)
    g_logger.info(
        "Total run time of analyzers", extra={"total_time": time.time() - start_time}
    )
    g_logger.info(
        "Done with applicability scanner container",
        extra={"total_time": time.time() - scan_start_time},
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        g_logger.exception(f"Applicability scanner got exception: {repr(e)}")
        sys.exit(1)
