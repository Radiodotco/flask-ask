import base64
import os
import unittest
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
from flask import Request

from flask_ask.verifiers import RequestVerifier, VerificationException
from flask_ask.verifiers.constants import SIGNATURE_CERT_CHAIN_URL_HEADER, SIGNATURE_HEADER, CERT_CHAIN_DOMAIN, \
    CHARACTER_ENCODING


class TestRequestVerifier(unittest.TestCase):
    PREPOPULATED_CERT_URL = "https://s3.amazonaws.com/echo.api/echo-api-cert-10.pem"
    VALID_URL = "https://s3.amazonaws.com/echo.api/cert"
    VALID_URL_WITH_PORT = "https://s3.amazonaws.com:443/echo.api/cert"
    VALID_URL_WITH_PATH_TRAVERSAL = (
        "https://s3.amazonaws.com/echo.api/../echo.api/cert")
    INVALID_URL_WITH_INVALID_HOST_NAME = "https://very.bad/echo.api/cert"
    INVALID_URL_WITH_INVALID_PORT = (
        "https://s3.amazonaws.com:563/echo.api/cert")
    INVALID_URL_WITH_INVALID_PATH = "https://s3.amazonaws.com/cert"
    INVALID_URL_WITH_INVALID_PATH_TRAVERSAL = (
        "https://s3.amazonaws.com/echo.api/../cert")
    INVALID_URL_WITH_INVALID_UPPER_CASE_PATH = (
        "https://s3.amazonaws.com/ECHO.API/cert")
    MALFORMED_URL = "badUrl"

    def setUp(self) -> None:
        self.headers = {
            SIGNATURE_CERT_CHAIN_URL_HEADER: "TestUrl",
            SIGNATURE_HEADER: "Test Signature"
        }
        self.request_verifier = RequestVerifier()

    @staticmethod
    def generate_private_key() -> RSAPrivateKeyWithSerialization:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def create_self_signed_certificate(self, start_time: datetime = None, end_time: datetime = None,  dns_name: str = CERT_CHAIN_DOMAIN) -> Certificate:
        self.private_key = self.generate_private_key()
        if not start_time:
            start_time = datetime.utcnow() - timedelta(minutes=5)

        if not end_time:
            end_time = datetime.utcnow() + timedelta(minutes=5)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"WA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Seattle"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Amazon Alexa"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"{}".format(self.PREPOPULATED_CERT_URL))
        ])

        extension = x509.SubjectAlternativeName([x509.DNSName(u"{}".format(dns_name))])
        self.mock_certificate = x509.CertificateBuilder()\
            .subject_name(subject)\
            .issuer_name(subject)\
            .public_key(self.private_key.public_key())\
            .serial_number(x509.random_serial_number())\
            .not_valid_before(start_time)\
            .not_valid_after(end_time)\
            .add_extension(extension, True)\
            .sign(private_key=self.private_key, algorithm=SHA1(), backend=default_backend())

        self.request_verifier._cert_cache[
            self.PREPOPULATED_CERT_URL] = self.mock_certificate
        return self.mock_certificate

    def load_valid_certificate(self) -> None:
        with open(os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                'data',
                'echo-api-cert-7.pem'), 'rb') as cert_response:
            self.cert_bytes = cert_response.read()

        self.mock_certificate = load_pem_x509_certificate(
            data=self.cert_bytes, backend=default_backend())

        self.request_verifier._cert_cache[
            self.PREPOPULATED_CERT_URL] = self.cert_bytes

    def sign_data(
            self, data, private_key=None,
            padding=PKCS1v15(), hash_algorithm=SHA1()) -> bytes:
        if private_key is None:
            private_key = self.private_key

        return private_key.sign(
            data=data.encode(CHARACTER_ENCODING),
            padding=padding,
            algorithm=hash_algorithm
        )

    @staticmethod
    def create_request(headers: dict = None, body: bytes = None) -> Request:
        request = Request({})
        if headers:
            request.headers = headers
        if body:
            request._cached_data = body
        return request

    def test_no_cert_url_header_throws_exception(self) -> None:
        with self.assertRaises(VerificationException) as exc:
            self.request_verifier.verify(self.create_request({
                SIGNATURE_HEADER: 'http://',
            }))

        self.assertIn(
            "Missing Signature/Certificate for the skill request",
            str(exc.exception))

    def test_no_signature_header_throws_exception(self) -> None:
        with self.assertRaises(VerificationException) as exc:
            self.request_verifier.verify(self.create_request({
                SIGNATURE_CERT_CHAIN_URL_HEADER: 'http://',
            }))

        self.assertIn(
            "Missing Signature/Certificate for the skill request",
            str(exc.exception))

    def test_validate_cert_url_scheme_mismatch_throw_exception(self) -> None:
        with self.assertRaises(VerificationException) as exc:
            self.request_verifier._retrieve_certificate_chain(self.MALFORMED_URL)

        self.assertIn(
            "Signature Certificate URL has invalid protocol",
            str(exc.exception))

    def test_validate_cert_url_hostname_mismatch_throw_exception(self) -> None:
        with self.assertRaises(VerificationException) as exc:
            self.request_verifier._retrieve_certificate_chain(self.INVALID_URL_WITH_INVALID_HOST_NAME)

        self.assertIn(
            "Signature Certificate URL has invalid hostname",
            str(exc.exception))

    def test_validate_cert_url_start_path_mismatch_throw_exception(self) -> None:
        with self.assertRaises(VerificationException) as exc:
            self.request_verifier._retrieve_certificate_chain(self.INVALID_URL_WITH_INVALID_PATH)

        self.assertIn(
            "Signature Certificate URL has invalid path", str(exc.exception))

    def test_validate_cert_url_normalized_start_path_mismatch_throw_exception(self) -> None:
        with self.assertRaises(VerificationException) as exc:
            self.request_verifier._retrieve_certificate_chain(self.INVALID_URL_WITH_INVALID_PATH_TRAVERSAL)

        self.assertIn(
            "Signature Certificate URL has invalid path", str(exc.exception))

    def test_validate_cert_url_start_path_case_mismatch_throw_exception(self) -> None:
        with self.assertRaises(VerificationException) as exc:
            self.request_verifier._retrieve_certificate_chain(self.INVALID_URL_WITH_INVALID_UPPER_CASE_PATH)

        self.assertIn(
            "Signature Certificate URL has invalid path", str(exc.exception))

    def test_validate_cert_url_port_mismatch_throw_exception(self) -> None:
        with self.assertRaises(VerificationException) as exc:
            self.request_verifier._retrieve_certificate_chain(self.INVALID_URL_WITH_INVALID_PORT)

        self.assertIn(
            "Signature Certificate URL has invalid port", str(exc.exception))

    def test_validate_cert_url_for_valid_url(self) -> None:
        self.create_self_signed_certificate()
        self.request_verifier._cert_cache[self.VALID_URL] = self.mock_certificate
        try:
            self.request_verifier._retrieve_certificate_chain(self.VALID_URL)
        except:
            # Should never reach here
            self.fail(
                "Request Verifier couldn't validate a valid certificate URL")

    def test_validate_cert_url_for_valid_url_with_port(self) -> None:
        self.create_self_signed_certificate()
        self.request_verifier._cert_cache[self.VALID_URL_WITH_PORT] = self.mock_certificate
        try:
            self.request_verifier._retrieve_certificate_chain(self.VALID_URL_WITH_PORT)
        except:
            # Should never reach here
            self.fail(
                "Request Verifier couldn't validate a valid certificate "
                "URL with valid port")

    def test_validate_cert_url_for_valid_url_with_path_traversal(self) -> None:
        self.create_self_signed_certificate()
        self.request_verifier._cert_cache[self.VALID_URL_WITH_PATH_TRAVERSAL] = self.mock_certificate
        try:
            self.request_verifier._retrieve_certificate_chain(self.VALID_URL_WITH_PATH_TRAVERSAL)
        except:
            # Should never reach here
            self.fail(
                "Request Verifier couldn't validate a valid certificate "
                "URL with path traversal")

    def test_load_cert_chain_invalid_cert_url_throw_exception(self) -> None:
        with self.assertRaises(VerificationException) as exc:
            self.request_verifier._retrieve_certificate_chain(self.MALFORMED_URL)

        self.assertIn(
            "Signature Certificate URL has invalid protocol", str(exc.exception))

    @freezegun.freeze_time('2001-01-01')
    def test_validate_cert_chain_invalid_path(self) -> None:
        self.load_valid_certificate()
        with self.assertRaises(VerificationException) as exc:
            self.request_verifier._validate_certificate_chain(certificate_chain=self.cert_bytes)

        self.assertIn("Certificate chain is not valid", str(exc.exception))

    @freezegun.freeze_time('2020-01-01')
    def test_validate_cert_chain_valid_path(self) -> None:
        self.load_valid_certificate()
        try:
            self.request_verifier._validate_certificate_chain(certificate_chain=self.cert_bytes)
        except:
            # Should never reach here
            self.fail("Request verifier couldn't validate a valid certificate chain")

    def test_validate_end_cert_expired_before_cert_throw_exception(self):
        mock_certificate = self.create_self_signed_certificate(
            datetime.utcnow() + timedelta(minutes=5),
            datetime.utcnow() + timedelta(minutes=100)
        )

        with self.assertRaises(VerificationException) as exc:
            self.request_verifier._validate_end_certificate(mock_certificate.public_bytes(Encoding("PEM")))

        self.assertIn("Signing Certificate expired", str(exc.exception))

    def test_validate_end_cert_expired_after_cert_throw_exception(self):
        mock_certificate = self.create_self_signed_certificate(
            datetime.utcnow() - timedelta(minutes=5),
            datetime.utcnow() - timedelta(minutes=1)
        )
        with self.assertRaises(VerificationException) as exc:
            self.request_verifier._validate_end_certificate(mock_certificate.public_bytes(Encoding("PEM")))

        self.assertIn("Signing Certificate expired", str(exc.exception))

    def test_validate_end_cert_domain_missing_throw_exception(self):
        mock_certificate = self.create_self_signed_certificate(dns_name='test')

        with self.assertRaises(VerificationException) as exc:
            self.request_verifier._validate_end_certificate(mock_certificate.public_bytes(Encoding("PEM")))

        self.assertIn(
            "domain missing in Signature Certificate Chain",
            str(exc.exception))

    def test_validate_end_cert_valid_cert(self):
        self.create_self_signed_certificate()
        try:
            self.request_verifier._validate_end_certificate(self.mock_certificate.public_bytes(Encoding("PEM")))
        except:
            # Should never reach here
            self.fail(
                "Request Verifier certificate validation failed for a "
                "valid certificate chain")

    def test_validate_request_body_for_valid_request(self):
        test_content = "This is some test content"
        self.create_self_signed_certificate()
        signature = self.sign_data(data=test_content)

        try:
            self.request_verifier._validate_request_body(
                request=self.create_request(self.headers, test_content.encode(CHARACTER_ENCODING)),
                cert_chain=self.mock_certificate,
                signature=base64.b64encode(signature).decode(CHARACTER_ENCODING)
            )
        except:
            # Should never reach here
            self.fail(
                "Request verifier validate request body failed for a valid "
                "signed request")

    def test_validate_request_body_for_invalid_request(self):
        test_content = "This is some test content"
        self.create_self_signed_certificate()

        different_private_key = self.generate_private_key()
        signature = self.sign_data(
            data=test_content, private_key=different_private_key)

        with self.assertRaises(VerificationException) as exc:

            self.request_verifier._validate_request_body(
                request=self.create_request(self.headers, test_content.encode(CHARACTER_ENCODING)),
                cert_chain=self.mock_certificate,
                signature=base64.b64encode(signature)
            )

        self.assertIn("Request body is not valid", str(exc.exception))

    def test_request_verification_for_valid_request(self):
        with mock.patch.object(
                RequestVerifier, '_retrieve_certificate_chain'):
            with mock.patch.object(
                    RequestVerifier, '_validate_request_body'):
                self.headers[
                    SIGNATURE_CERT_CHAIN_URL_HEADER] = self.PREPOPULATED_CERT_URL
                self.headers[SIGNATURE_HEADER] = self.generate_private_key()
                try:
                    request = self.create_request(self.headers, body=b"abc")
                    RequestVerifier().verify(request=request)
                except:
                    # Should never reach here
                    self.fail("Request verifier couldn't verify a valid signed request")

    def test_request_verification_for_invalid_request(self):
        with mock.patch.object(
                RequestVerifier, '_retrieve_certificate_chain'):
            with mock.patch.object(
                    RequestVerifier, '_validate_request_body',
                    side_effect=VerificationException(
                        'Request body is not valid')):
                self.headers[
                    SIGNATURE_CERT_CHAIN_URL_HEADER] = self.PREPOPULATED_CERT_URL
                self.headers[SIGNATURE_HEADER] = self.generate_private_key()

                with self.assertRaises(VerificationException) as exc:
                    request = self.create_request(self.headers, b"test")
                    RequestVerifier().verify(request=request)

                self.assertIn("Request body is not valid", str(exc.exception))
