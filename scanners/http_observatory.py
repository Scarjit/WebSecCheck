import json
from enum import Enum
from time import sleep

import requests

from Bulletin import Bulletin, IssueLevel


class ScanState(Enum):
    ABORTED = 10
    FAILED = 281
    FINISHED = 46240
    PENDING = 122
    STARTING = 96
    RUNNING = 128

    @staticmethod
    def fromStr(state: str):
        if state == "ABORTED":
            return ScanState.ABORTED
        elif state == "FAILED":
            return ScanState.FAILED
        elif state == "FINISHED":
            return ScanState.FINISHED
        elif state == "STARTING":
            return ScanState.STARTING
        elif state == "RUNNING":
            return ScanState.RUNNING


class ScanObject:
    algorithm_version: int
    end_time: str
    grade: str
    hidden: bool
    likelihood_indicator: str
    response_headers: dict
    scan_id: int
    score: int
    start_time: str
    state: ScanState
    status_code: int
    tests_failed: int
    tests_passed: int
    tests_quantity: int

    def __init__(self, j: json):
        self.FromJSON(j)

    def FromJSON(self, j: json):
        self.algorithm_version = j["algorithm_version"]
        self.end_time = j["end_time"]
        self.grade = j["grade"]
        self.hidden = j["hidden"]
        self.likelihood_indicator = j["likelihood_indicator"]
        self.response_headers = j["response_headers"]
        self.scan_id = j["scan_id"]
        self.score = j["score"]
        self.start_time = j["start_time"]
        self.status_code = j["status_code"]
        self.tests_failed = j["tests_failed"]
        self.tests_passed = j["tests_passed"]
        self.tests_quantity = j["tests_quantity"]
        self.state = ScanState.fromStr(j["state"])
        return self


class TestResult:
    expectation: str
    name: str
    output: json
    passed: bool
    result: str
    score_description: str
    score_modifier: int

    def __init__(self, j: json):
        self.FromJSON(j)

    def FromJSON(self, j: json):
        self.expectation = j["expectation"]
        self.name = j["name"]
        self.output = j["output"]
        self.passed = j["pass"]
        self.result = j["result"]
        self.score_description = j["score_description"]
        self.score_modifier = j["score_modifier"]
        return self


class HTTPObservatory:
    base_url = "https://http-observatory.security.mozilla.org/api/v1"
    scan_object: ScanObject = None
    test_results: json = None
    url: str = None

    def __init__(self, url: str):
        self.url = url
        payload = {
            'hidden': True,
            'rescan': True,
        }
        self.scan_object = ScanObject(requests.post(self.base_url + "/analyze?host=" + self.url, data=payload).json())
        self.EnsureScanResult()

    def EnsureScanResult(self):
        while self.scan_object.state != ScanState.FINISHED:
            print("Scan not yet finished ...")
            sleep(5)
            self.scan_object = ScanObject(requests.get(self.base_url + "/analyze?host=" + self.url).json())

    def GetBulletin(self) -> list[Bulletin]:
        if self.scan_object is None:
            print("No scan object found, aborting")
            exit(-1)

        self.test_results = requests.get(
            self.base_url + "/getScanResults?scan=" + str(self.scan_object.scan_id)).json()

        bulletins = list()
        for test_name in self.test_results:
            test = TestResult(self.test_results[test_name])
            if not test.passed:
                bulletins.append(self.GenerateBulletin(test))
        return bulletins

    @staticmethod
    def GenerateBulletin(test: TestResult):
        return Bulletin(test.name, test.score_description, test.output, IssueLevel.ERR)
