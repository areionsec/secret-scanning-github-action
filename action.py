import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from functools import cached_property
from urllib.request import Request, urlopen

logger = logging.getLogger()

DEFAULT_DELAY_SECONDS = 2.0
DEFAULT_TIMEOUT_SECONDS = 120.0


class Delay(Exception):
    pass


class ValidSecretsException(Exception):
    pass


class Response:
    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self.json_data = json_data

    def json(self):
        return json.loads(self.json_data)


class Requests:
    JSON_MODULE = json

    # noinspection PyShadowingNames
    @classmethod
    def post(cls, url, json):
        request = Request(
            method="POST",
            data=cls.JSON_MODULE.dumps(json).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            url=url,
        )
        with urlopen(request) as req:
            return Response(req.status, req.read().decode("utf-8"))


requests = Requests


class Worker:
    def __init__(self, timeout_seconds: float, delay_seconds: float):
        self.timeout_seconds = timeout_seconds
        self.delay_seconds = delay_seconds

    def run(self):
        deadline = time.time() + self.timeout_seconds
        while time.time() < deadline:
            try:
                return self.execute()
            except Delay as delay:
                logger.debug(f"got {repr(delay)} sleeping for {self.delay_seconds} seconds")
                time.sleep(self.delay_seconds)
        raise TimeoutError()

    def execute(self):
        raise NotImplementedError()

    @classmethod
    def create(cls, timeout_seconds=DEFAULT_TIMEOUT_SECONDS, delay_seconds=DEFAULT_DELAY_SECONDS):
        return cls(timeout_seconds, delay_seconds)


class GitHubSecretScanner(Worker):
    def __init__(self, context, delay_seconds: float):
        super().__init__(context.input_timeout_seconds, delay_seconds)
        self.context = context

    @cached_property
    def github_details(self):
        return {
            "action_unique_id": self.context.action_unique_id,
            "github_run_id": self.context.github_run_id,
            "github_run_number": self.context.github_run_number,
            "github_head_ref": self.context.github_head_ref,
            "github_base_ref": self.context.github_base_ref,
            "github_token": self.context.github_token,
            "github_sha": self.context.github_sha,
            "github_repository": self.context.github_repository,
        }

    @classmethod
    def print_secrets(cls, details):
        for secret in details:
            if secret["is_valid"] in ["IS_SECRET_VALID_UNSPECIFIED", "IS_SECRET_VALID_NO"]:
                print(
                    f"::notice file={secret['file_path']}::found invalid secret {secret['secret_value']} of {secret['secret_type']}"
                )
            elif secret["is_valid"] in ["IS_SECRET_VALID_YES"]:
                print(
                    f"::error file={secret['file_path']}::found valid secret {secret['secret_value']} of {secret['secret_type']}"
                )
            else:
                print(
                    f"::warning file={secret['file_path']}::found unknown secret {secret['secret_value']} of {secret['secret_type']}"
                )

    def execute(self):
        response = requests.post(self.context.input_webhook_url, json=self.github_details)

        if response.status_code != 200:
            raise Exception(f"webhook returned invalid status code: {response.status_code}")

        result = response.json()

        if result["error"] != "":
            raise Exception(f"webhook failed with error: {result['error']}")

        if result["status"] == "failed":
            self.print_secrets(result.get("details", []))
            raise ValidSecretsException()

        if result["status"] != "just_created":
            self.print_secrets(result.get("details", []))
            return

        raise Delay()

    @classmethod
    def create(
        cls,
        context: "Context",
        delay_seconds=DEFAULT_DELAY_SECONDS,
    ):
        return cls(context, delay_seconds)


@dataclass
class Context:
    action_unique_id: str
    github_run_id: str
    github_run_number: str
    github_head_ref: str
    github_base_ref: str
    github_token: str
    github_sha: str
    github_repository: str
    input_webhook_url: str
    input_timeout_seconds: float

    @classmethod
    def create(cls):
        with open(os.getenv("GITHUB_EVENT_PATH"), "r") as event_file:
            event = json.load(event_file)

        return cls(
            action_unique_id=uuid.uuid4().hex,
            github_run_id=os.getenv("GITHUB_RUN_ID"),
            github_run_number=os.getenv("GITHUB_RUN_NUMBER"),
            github_head_ref=os.getenv("GITHUB_HEAD_REF"),
            github_base_ref=os.getenv("GITHUB_BASE_REF"),
            github_token=os.getenv("INPUT_TOKEN"),
            input_webhook_url=os.getenv("INPUT_WEBHOOK_URL"),
            github_repository=event["repository"]["full_name"],
            github_sha=event["pull_request"]["head"]["sha"],
            input_timeout_seconds=float(os.getenv("INPUT_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)),
        )


# noinspection PyBroadException
def main():
    try:
        context = Context.create()
        GitHubSecretScanner.create(context).run()
        print("::notice::no secrets found \U0001f44d")
    except TimeoutError:
        print("::error::action timeout!")
        sys.exit(1)
    except ValidSecretsException:
        print("::error::found valid secrets on code!")
        sys.exit(1)
    except Exception:
        logger.exception("action failed!")
        print("::error::action failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
