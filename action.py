import json
import logging
import os
import sys
import time
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
    def __init__(self, webhook_url, github_details, timeout_seconds: float, delay_seconds: float):
        super().__init__(timeout_seconds, delay_seconds)
        self.webhook_url = webhook_url
        self.github_details = github_details

    def execute(self):
        response = requests.post(self.webhook_url, json=self.github_details)

        if response.status_code != 200:
            raise Exception(f"webhook returned invalid status code: {response.status_code}")

        result = response.json()

        if result["error"] != "":
            raise Exception(f"webhook failed with error: {result['error']}")

        if result["status"] == "failed":
            raise ValidSecretsException()

        if result["status"] != "just_created":
            return

        raise Delay()

    @classmethod
    def create(
        cls, webhook_url, github_details, timeout_seconds=DEFAULT_TIMEOUT_SECONDS, delay_seconds=DEFAULT_DELAY_SECONDS
    ):
        return cls(webhook_url, github_details, timeout_seconds, delay_seconds)


def collect_details():
    with open("/github/workflow/event.json", "r") as event_file:
        event = json.load(event_file)

    return {
        "github_repository": event["repository"]["full_name"],
        "github_run_id": f'{os.getenv("GITHUB_RUN_ID")}-{os.getenv("GITHUB_RUN_NUMBER")}',
        "github_sha": event["pull_request"]["head"]["sha"],
        "github_head_ref": os.getenv("GITHUB_HEAD_REF"),
        "github_base_ref": os.getenv("GITHUB_BASE_REF"),
        "github_token": os.getenv("INPUT_TOKEN"),
    }


# noinspection PyBroadException
def main():
    details = collect_details()
    try:
        GitHubSecretScanner.create(
            os.getenv("INPUT_WEBHOOK_URL"), details, timeout_seconds=float(os.getenv("INPUT_TIMEOUT_SECONDS"))
        ).run()
        print("::notice::no secrets found \U0001f44d")
    except TimeoutError:
        print("::error::action timeout!")
        sys.exit(1)
    except ValidSecretsException:
        print("::error::found valid secrets on code!")
        sys.exit(1)
    except Exception:
        print("::error::action failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
