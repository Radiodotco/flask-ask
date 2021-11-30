import base64
import json
import os
import unittest
import warnings
from datetime import datetime, timedelta
from typing import Union
from unittest import mock

import freezegun
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_pem_x509_certificate, Certificate
from cryptography.x509.oid import NameOID
from dateutil.tz import tzutc, tzlocal
from flask import Request
from freezegun import freeze_time

from flask_ask.verifiers import RequestVerifier, VerificationException, TimestampVerifier
from flask_ask.verifiers.constants import SIGNATURE_CERT_CHAIN_URL_HEADER, SIGNATURE_HEADER, CERT_CHAIN_DOMAIN, \
    CHARACTER_ENCODING, MAX_NORMAL_REQUEST_TOLERANCE_IN_MILLIS


class TestTimestampVerifier(unittest.TestCase):

    @staticmethod
    def create_request(time: str = datetime.utcnow().isoformat()) -> Request:
        request = Request({})
        request._cached_data = json.dumps({
            'request': {
                'timestamp': time
            }
        })
        return request

    def test_timestamp_verification_with_expired_timestamp(self):
        timestamp = datetime(year=2019, month=1, day=1, tzinfo=tzutc()).isoformat()
        request = self.create_request(timestamp)

        verifier = TimestampVerifier()
        with self.assertRaises(VerificationException) as exc:
            verifier.verify(request)

            self.assertIn("Timestamp verification failed", str(exc.exception))

    def test_timestamp_verification_with_valid_future_server_timestamp(self):
        valid_tolerance = int(MAX_NORMAL_REQUEST_TOLERANCE_IN_MILLIS / 2 / 1000)
        valid_future_datetime = datetime.now(tzutc()) + timedelta(seconds=valid_tolerance)
        request = self.create_request(valid_future_datetime.isoformat())

        timestamp_verifier = TimestampVerifier()
        try:
            timestamp_verifier.verify(request)
        except:
            # Should never reach here
            raise self.fail(
                "Timestamp verification failed for a valid input request")

    def test_timestamp_verification_with_valid_timestamp(self):
        timestamp = datetime.now(tz=tzlocal()).isoformat()
        request = self.create_request(timestamp)
        timestamp_verifier = TimestampVerifier()

        try:
            timestamp_verifier.verify(request)
        except:
            # Should never reach here
            raise self.fail(
                "Timestamp verification failed for a valid input request")