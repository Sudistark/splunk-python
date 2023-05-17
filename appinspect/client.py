import logging
import requests
from requests.auth import HTTPBasicAuth

from . exceptions import AppInpsectException, AppInspectAuthenticateException, \
                         AppInspectValidateException

logger = logging.getLogger(__name__)

DEFAULT_ENDPOINT = "https://appinspect.splunk.com/v1"
DEFAULT_AUTH_ENDPOINT = "https://api.splunk.com/2.0/rest/login/splunk"
REQUEST_TIMEOUT = 20
ERROR_MESSAGE = {
    "UNAUTHORIZED": "Incorrect username or password for Splunk credentials.",
    "NOT_FOUND": ("This app has not been submitted to AppInspect. "
                  "Submit your app to AppInspect for validation."),
    "FORBIDDEN": ("You are not authorized to install this app. "
                  "You must submit the app to AppInspect, "
                  "and specify the same credentials as those "
                  "used for AppInspect."),
    "IN_PROGRESS": ("AppInspect validation is in progress. "
                    "Try again later"),
    "VALIDATION_FAILED": ("This app has failed AppInspect validation. "
                          "Fix the issues in the report, "
                          "and retry AppInspect validation."),
    "GENERAL_ERROR": ("Unable to retrieve AppInspect validation result. "
                      "Try again later.")
}


class AppInspectClient(object):

    def __init__(self, username, password, endpoint=DEFAULT_ENDPOINT):
        self.token = None
        self.authenticated = self._authenticate(username, password)
        self.endpoint = endpoint

    def _authenticate(self, username, password):
        """https://api.splunk.com/2.0/rest/login/splunk
        """
        url = DEFAULT_AUTH_ENDPOINT
        logger.info("Authenticating via url {}".format(url))

        try:
            response = requests.get(
                url=url,
                auth=HTTPBasicAuth(username=username, password=password)
            )

            if response.status_code == 200:
                token = response.json().get("data").get("token")
                self.token = "bearer {}".format(token)
                return True
            else:
                logger.exception("Received status code: {} from {}".format(response.status_code, url))
                raise AppInspectAuthenticateException(ERROR_MESSAGE["UNAUTHORIZED"])
        except AppInspectAuthenticateException:
            raise
        except Exception as e:
            logger.exception(str(e))
            raise AppInspectValidateException(message=str(e))

    def get_ping(self):
        """ GET /ping """
        if not self.authenticated:
            raise AppInspectAuthenticateException()
        url = "{}/ping".format(self.endpoint)
        headers = {'Authorization': self.token}
        response = requests.get(url=url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise AppInpsectException("Received status code {} from url: {}".format(response.status_code, url))

    def get_validation_result(self, sha):
        """
        Use generated SHA value to retrieve validation result of the app.

        :type sha: string
        :param sha: sha value of a given app

        :rtype: boolean
        :return: whether the app is validated
        """
        if not self.authenticated:
            raise AppInspectAuthenticateException()

        url = "{}/app/validate/status/{}".format(self.endpoint, sha)
        headers = { "Authorization": self.token }
        try:
            logger.info("Validating app with url: {}".format(url))
            response = requests.get(
                url=url,
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )
            # AppInspect responded with 404 Not Found:
            # SHA is not matching with any values on AppInspect
            if response.status_code == 404:
                message = ERROR_MESSAGE["NOT_FOUND"]
                logger.exception(message)
                raise AppInspectValidateException(message)

            # AppInspect responded with 403 Forbidden
            # Splunk credentials used to submit app on AppInspect is not
            #   matching with the user that uploads app on stack
            elif response.status_code == 403:
                message = ERROR_MESSAGE["FORBIDDEN"]
                logger.exception(message)
                raise AppInspectValidateException(message)

            # AppInspect responded with 200 Success
            # App can be found on AppInspect via SHA, but needs further
            #   if check to determine it passes validation
            elif response.status_code == 200:
                content = response.json()

                # App is still pending validation:
                if content.get("status") == "PROCESSING":
                    message = ERROR_MESSAGE["IN_PROGRESS"]
                    logger.exception(message)
                    raise AppInspectValidateException(message)

                # App passed validation only when all cases are TRUE:
                #   response["status"] == "SUCCESS":
                #       app has finished validation
                #   response["info"]["failure"] == 0:
                #       app has no outstanding failures from AppInspect
                #   response["info"]["error"] == 0:
                #       app has no runtime errors from AppInspect
                # TODO: AppInspect has a known bug that generates an error in
                # report, update this back to == 0 once AppInspect is fixed.
                if content.get("status") == "SUCCESS" and \
                    content.get("info", {}).get("failure") == 0 and \
                    content.get("info", {}).get("error") == 0:
                    logger.info("App with SHA {} passed validation".format(sha))
                    return True
                else:
                    message = ERROR_MESSAGE["VALIDATION_FAILED"]
                    logger.exception(message)
                    raise AppInspectValidateException(message)

            # AppInspect responded with other status code
            else:
                logger.exception(ERROR_MESSAGE["GENERAL_ERROR"])
                raise AppInspectValidateException(ERROR_MESSAGE["GENERAL_ERROR"])

        except AppInspectValidateException:
            raise
        except requests.exceptions.Timeout:
            logger.exception(ERROR_MESSAGE["GENERAL_ERROR"])
            raise AppInspectValidateException(ERROR_MESSAGE["GENERAL_ERROR"])
        except Exception as e:
            logger.exception(str(e))
            raise AppInspectValidateException(message=str(e))
