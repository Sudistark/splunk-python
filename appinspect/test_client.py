import unittest
import requests
from . client import AppInspectClient, ERROR_MESSAGE
from . exceptions import AppInpsectException, AppInspectAuthenticateException, \
                         AppInspectValidateException
try:
    from unittest import mock
except ImportError:
    import mock

# Mock requests response
class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data

def mock_failed_request(*args, **kwargs):
    return MockResponse(None, 400)


class AppInspectClientAuthTest(unittest.TestCase):
    """Test AppInspect Client _authenticate method
    """

    def setUp(self):
        pass


    @mock.patch(
        'requests.get',
        return_value=MockResponse(
            {"data": {"token": "authenticated_token"}},
            200
        )
    )
    def testAuthenticateSuccess(self, mock_get):
        self.client = AppInspectClient("test_username", "test_password")
        self.assertTrue(self.client.authenticated)
        self.assertEqual(
            self.client.token,
            "bearer authenticated_token",
            "client token should match"
        )

    @mock.patch(
        'requests.get',
        return_value=MockResponse(
            {"msg": "Failed to authenticate user"},
            401
        )
    )
    def testAuthenticateFailed(self, mock_get):
        with self.assertRaisesRegexp(
            AppInspectAuthenticateException,
            ERROR_MESSAGE["UNAUTHORIZED"]
        ):
            self.client = AppInspectClient("incorrect_username", "incorrect_password")
            self.assertIsNone(self.client.authenticated)
            self.assertIsNone(self.client.token)

    @mock.patch(
        'requests.get',
        side_effect=mock_failed_request
    )
    def testAuthenticateFailedRequest(self, mock_get):
        with self.assertRaisesRegexp(
            AppInspectAuthenticateException,
            ERROR_MESSAGE["UNAUTHORIZED"]
        ):
            self.client = AppInspectClient("failed_username", "failed_password")
            self.assertIsNone(self.client.authenticated)
            self.assertIsNone(self.client.token)


class AppInspectClientAuthStub(AppInspectClient):
    def __init__(self, username, password, endpoint="default_endpoint"):
        self.token = None
        self.authenticated = self._authenticate(username, password)
        self.endpoint = endpoint

    def _authenticate(self, username, password):
        token = "{}:{}".format(username, password)
        self.token = "bearer {}".format(token)
        return True

class AppInspectClientValidateResultTest(unittest.TestCase):
    """Test AppInspect Client get_validation_result method
    """

    def setUp(self):
        self.client = AppInspectClientAuthStub(
            "test_username",
            "test_password",
            "test_endpoint"
        )
        self.sha = "test_sha"

        self.assertTrue(self.client.authenticated is True)
        self.assertEqual(
            self.client.token,
            "bearer test_username:test_password",
            "client token should match"
        )
        self.assertEqual(
            self.client.endpoint,
            "test_endpoint",
            "client endpoint should match with given value"
        )

    @mock.patch(
        'requests.get',
        return_value=MockResponse(
            {
                "status": "SUCCESS",
                "info": {
                    "failure": 0,
                    "error": 0
                }
            },
            200
        )
    )
    def testValidationResultSuccess(self, mock_get):
        self.assertTrue(self.client.get_validation_result(self.sha))

    @mock.patch(
        'requests.get',
        return_value=MockResponse(
            {
                "status": "SUCCESS",
                "info": {
                    "failure": 2,
                    "error": 0
                }
            },
            200
        )
    )
    def testValidationResultFailed(self, mock_get):
        with self.assertRaisesRegexp(
            AppInspectValidateException,
            ERROR_MESSAGE["VALIDATION_FAILED"]
        ):
            self.assertIsNone(self.client.get_validation_result(self.sha))

    @mock.patch(
        'requests.get',
        return_value=MockResponse("unrelated_message", 404)
    )
    def testValidationResultNotFound(self, mock_get):
        with self.assertRaisesRegexp(
            AppInspectValidateException,
            ERROR_MESSAGE["NOT_FOUND"]
        ):
            self.assertIsNone(self.client.get_validation_result(self.sha))

    @mock.patch(
        'requests.get',
        return_value=MockResponse("unrelated_message", 403)
    )
    def testValidationResultForbidden(self, mock_get):
        with self.assertRaisesRegexp(
            AppInspectValidateException,
            ERROR_MESSAGE["FORBIDDEN"]
        ):
            self.assertIsNone(self.client.get_validation_result(self.sha))

    @mock.patch(
        'requests.get',
        return_value=MockResponse({"status": "PROCESSING",}, 200)
    )
    def testValidationResultInProgress(self, mock_get):
        with self.assertRaisesRegexp(
            AppInspectValidateException,
            ERROR_MESSAGE["IN_PROGRESS"]
        ):
            self.assertIsNone(self.client.get_validation_result(self.sha))

    @mock.patch(
        'requests.get',
        side_effect=mock_failed_request
    )
    def testValidationRequestFailed(self, mock_get):
        with self.assertRaisesRegexp(
            AppInspectValidateException,
            ERROR_MESSAGE["GENERAL_ERROR"]
        ):
            self.assertIsNone(self.client.get_validation_result(self.sha))

    @mock.patch('requests.get', side_effect=requests.exceptions.Timeout())
    def testValidationRequestTimeout(self, mock_get):
        with self.assertRaisesRegexp(
            AppInspectValidateException,
            ERROR_MESSAGE["GENERAL_ERROR"]
        ):
            self.assertIsNone(self.client.get_validation_result(self.sha))

    @mock.patch('requests.get', side_effect=KeyError("test_error"))
    def testValidationRequestBroken(self, mock_get):
        with self.assertRaisesRegexp(AppInspectValidateException, "test_error"):
            self.assertIsNone(self.client.get_validation_result(self.sha))


if __name__ == '__main__':
    # exec all tests
    loader = unittest.TestLoader()
    suites = []
    suites.append(loader.loadTestsFromTestCase(AppInspectClientAuthTest))
    suites.append(loader.loadTestsFromTestCase(AppInspectClientValidateResultTest))
    unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(suites))
