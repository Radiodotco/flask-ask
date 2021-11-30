import json
import logging
from datetime import datetime

import aniso8601
import flask
from dateutil import tz

from flask_ask.verifiers.verifier_interface import VerifierInterface
from . import constants
from .verification_exception import VerificationException


class TimestampVerifier(VerifierInterface):

    def __init__(self):
        self._cert_cache = {}
        self.logger = logging.getLogger(self.__class__.__name__)

    def verify(self, request: flask.Request) -> None:
        local_now = datetime.now(tz.tzutc())

        raw_body = request.data
        payload = json.loads(raw_body)
        request = payload.get('request', None)
        if not request:
            raise VerificationException("Couldn't find Request in Body")

        request_timestamp = request.get('timestamp', None)
        if not request_timestamp:
            raise VerificationException("Timestamp not Found in Request")

        try:
            request_timestamp = aniso8601.parse_datetime(request_timestamp)
        except AttributeError:
            # Raised by aniso8601 if request_timestamp is not a valid string
            try:
                request_timestamp = datetime.utcfromtimestamp(request_timestamp)
            except:
                request_timestamp =  datetime.utcfromtimestamp(request_timestamp / 1000)

        timestamp_diff = abs((local_now - request_timestamp).total_seconds())
        if timestamp_diff > (constants.MAX_NORMAL_REQUEST_TOLERANCE_IN_MILLIS / 1000):
            # For skill events, need to check if timestamp difference in
            # max skill event timestamp tolerance limit
            request_type = request.get('object_type', None)
            if not request_type:
                raise VerificationException("Couldn't find Request Type in Body")

            if (request_type in constants.ALEXA_SKILL_EVENT_LIST and
                    timestamp_diff < (constants.MAX_SKILL_EVENT_TOLERANCE_IN_MILLIS / 1000)):
                return
            raise VerificationException("Timestamp Verification Failed")
