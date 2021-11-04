import json
import os
import tempfile

import pytest
from pytest_httpserver import HTTPServer

from action import main


def test_action__got_valid_secrets_exception(httpserver: HTTPServer, monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "11")
    monkeypatch.setenv("GITHUB_RUN_NUMBER", "22")
    monkeypatch.setenv("GITHUB_HEAD_REF", "my-branch"),
    monkeypatch.setenv("GITHUB_BASE_REF", "master"),
    monkeypatch.setenv("INPUT_TOKEN", os.environ["GITHUB_TOKEN"]),
    monkeypatch.setenv("INPUT_WEBHOOK_URL", httpserver.url_for("/secret_scanning")),

    event = tempfile.NamedTemporaryFile(suffix=".json")
    event.write(
        json.dumps({"repository": {"full_name": "my/repository"}, "pull_request": {"head": {"sha": "my_sha"}}}).encode()
    )
    event.flush()
    monkeypatch.setenv("GITHUB_EVENT_PATH", event.name)

    httpserver.expect_request("/secret_scanning").respond_with_json(
        {
            "status": "failed",
            "error": "",
            "details": [
                {
                    "is_valid": "IS_SECRET_VALID_YES",
                    "file_path": "bla.json",
                    "secret_value": "***",
                    "secret_type": "regular",
                }
            ],
        }
    )

    ###
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        main()
    ###

    assert pytest_wrapped_exception.value.code == 1


def test_action__got_valid(httpserver: HTTPServer, monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "11")
    monkeypatch.setenv("GITHUB_RUN_NUMBER", "22")
    monkeypatch.setenv("GITHUB_HEAD_REF", "my-branch"),
    monkeypatch.setenv("GITHUB_BASE_REF", "master"),
    monkeypatch.setenv("INPUT_TOKEN", os.environ["GITHUB_TOKEN"]),
    monkeypatch.setenv("INPUT_WEBHOOK_URL", httpserver.url_for("/secret_scanning")),

    event = tempfile.NamedTemporaryFile(suffix=".json")
    event.write(
        json.dumps({"repository": {"full_name": "my/repository"}, "pull_request": {"head": {"sha": "my_sha"}}}).encode()
    )
    event.flush()
    monkeypatch.setenv("GITHUB_EVENT_PATH", event.name)

    httpserver.expect_request("/secret_scanning").respond_with_json(
        {
            "status": "valid",
            "error": "",
            "details": [
                {
                    "is_valid": "IS_SECRET_VALID_NO",
                    "file_path": "bla.json",
                    "secret_value": "***",
                    "secret_type": "regular",
                }
            ],
        }
    )

    ###
    main()
    ###


def test_action__got_just_created(httpserver: HTTPServer, monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "11")
    monkeypatch.setenv("GITHUB_RUN_NUMBER", "22")
    monkeypatch.setenv("GITHUB_HEAD_REF", "my-branch"),
    monkeypatch.setenv("GITHUB_BASE_REF", "master"),
    monkeypatch.setenv("INPUT_TOKEN", os.environ["GITHUB_TOKEN"]),
    monkeypatch.setenv("INPUT_WEBHOOK_URL", httpserver.url_for("/secret_scanning")),

    event = tempfile.NamedTemporaryFile(suffix=".json")
    event.write(
        json.dumps({"repository": {"full_name": "my/repository"}, "pull_request": {"head": {"sha": "my_sha"}}}).encode()
    )
    event.flush()
    monkeypatch.setenv("GITHUB_EVENT_PATH", event.name)

    httpserver.expect_ordered_request("/secret_scanning").respond_with_json({"status": "just_created", "error": ""})
    httpserver.expect_ordered_request("/secret_scanning").respond_with_json({"status": "valid", "error": ""})

    ###
    main()
    ###
