class AppInspectAuthenticateException(Exception):

    def __init__(self, message="Not authenticated"):
        super(AppInspectAuthenticateException, self).__init__(message)


class AppInpsectException(Exception):

    def __init__(self, message):
        super(AppInpsectException, self).__init__(message)

class AppInspectValidateException(Exception):

    def __init__(self, message="Bad Request"):
        super(AppInspectValidateException, self).__init__(message)

