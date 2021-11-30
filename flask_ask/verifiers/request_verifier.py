import base64
import datetime
import os
import logging
import flask
import six
import typing

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1
from six.moves.urllib.parse import urlparse
from six.moves.urllib.request import urlopen
from asn1crypto import pem
from certvalidator import CertificateValidator
from certvalidator.errors import ValidationError, PathError
from cryptography.x509 import (
    load_pem_x509_certificate, ExtensionOID, DNSName,
    SubjectAlternativeName, Certificate)

from .verification_exception import VerificationException
from .verifier_interface import VerifierInterface
from . import constants


class RequestVerifier(VerifierInterface):

    def __init__(self):
        self._cert_cache = {}
        self.logger = logging.getLogger(self.__class__.__name__)

    def verify(self, request: flask.Request) -> None:
        cert_url = None
        signature = None
        for header_key, header_value in six.iteritems(request.headers):
            if header_key.lower() == constants.SIGNATURE_CERT_CHAIN_URL_HEADER.lower():
                cert_url = header_value
            elif header_key.lower() == constants.SIGNATURE_HEADER.lower():
                signature = header_value

        if cert_url is None or signature is None:
            raise VerificationException("Missing Signature/Certificate for the skill request")

        self.logger.debug("Verifying Request. Certificate Url: {}, Signature: {}".format(cert_url, signature))
        cert_chain = self._retrieve_certificate_chain(cert_url)
        self._validate_request_body(request, cert_chain, signature)

    def _retrieve_certificate_chain(self, cert_url) -> Certificate:
        parsed_url = urlparse(cert_url)

        protocol = parsed_url.scheme
        if protocol.lower() != constants.CERT_CHAIN_URL_PROTOCOL.lower():
            raise VerificationException("Signature Certificate URL has invalid protocol. Expected: {}. Got: {}".format(
                constants.CERT_CHAIN_URL_PROTOCOL, protocol))

        hostname = parsed_url.hostname
        if hostname is None or hostname.lower() != constants.CERT_CHAIN_URL_HOSTNAME.lower():
            raise VerificationException("Signature Certificate URL has invalid Hostname. Expected: {}. Got: {}".format(
                constants.CERT_CHAIN_URL_HOSTNAME, hostname
            ))

        normalized_path = os.path.normpath(parsed_url.path)
        if not normalized_path.startswith(constants.CERT_CHAIN_URL_STARTPATH):
            raise VerificationException("Signature Certificate URL Starts with invalid path. Expected: {}. Got: {}".format(
                constants.CERT_CHAIN_URL_STARTPATH, normalized_path
            ))

        port = parsed_url.port
        if port is not None and port != constants.CERT_CHAIN_URL_PORT:
            raise VerificationException("Signature Certificate URL has invalid port. Expected: {}. Got: {}".format(
                constants.CERT_CHAIN_URL_PORT, port
            ))

        if cert_url in self._cert_cache:
            return self._cert_cache[cert_url]

        try:
            with urlopen(cert_url) as cert_response:
                cert_data = cert_response.read()
                self._validate_certificate_chain(cert_data)
        except ValueError as e:
            raise VerificationException("Unable to load Certificate from URL")

        certificate = self._validate_end_certificate(cert_data)
        self._cert_cache[cert_url] = certificate
        return certificate

    def _validate_certificate_chain(self, certificate_chain: bytes) -> None:
        try:
            end_cert = None
            intermediate_certs = []
            for type_name, headers, der_bytes in pem.unarmor(
                    certificate_chain, multiple=True):
                if end_cert is None:
                    end_cert = der_bytes
                else:
                    intermediate_certs.append(der_bytes)

            validator = CertificateValidator(end_cert, intermediate_certs)
            validator.validate_usage(key_usage={'digital_signature'})
        except (PathError, ValidationError) as e:
            raise VerificationException("Certificate chain is not valid", e)

    def _validate_end_certificate(self, certificate: bytes) -> Certificate:
        end_cert = load_pem_x509_certificate(data=certificate, backend=default_backend())
        now = datetime.datetime.utcnow()
        if not (end_cert.not_valid_before <= now <=
                end_cert.not_valid_after):
            raise VerificationException("Signing Certificate expired. Expires At: {}. Time Now: {}".format(
                end_cert.not_valid_after, now))

        ext = end_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        ext_value = typing.cast(SubjectAlternativeName, ext.value)
        if constants.CERT_CHAIN_DOMAIN not in ext_value.get_values_for_type(
                DNSName):
            raise VerificationException(
                "{} domain missing in Signature Certificate Chain".format(
                    constants.CERT_CHAIN_DOMAIN))
        return end_cert

    def _validate_request_body(self, request: flask.Request, cert_chain: Certificate, signature: str):
        decoded_signature = base64.b64decode(signature)
        public_key = cert_chain.public_key()  # type: rsa._RSAPublicKey

        try:
            public_key.verify(
                decoded_signature, request.data,
                PKCS1v15(), SHA1())
        except InvalidSignature as e:
            self.logger.error("Failed to Verify Signature. Body: {}, Signature: {}".format(request.data, decoded_signature))
            raise VerificationException("Request body is not valid", e)