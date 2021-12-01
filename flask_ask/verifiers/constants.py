import os

#: Header key to be used, to retrieve request header that contains the
#: URL for the certificate chain needed to verify the request signature.
#: For more info, check `link <https://developer.amazon.com/docs/custom-skills/host-a-custom-skill-as-a-web-service.html#check-request-signature>`__.
SIGNATURE_CERT_CHAIN_URL_HEADER = "SignatureCertChainUrl"

#: Header key to be used, to retrieve request header that contains the
#: request signature.
#: For more info, check `link <https://developer.amazon.com/docs/custom-skills/host-a-custom-skill-as-a-web-service.html#check-request-signature>`__.
SIGNATURE_HEADER = "Signature"

#: Case insensitive protocol to be checked on signature certificate url.
#: For more info, check `link <https://developer.amazon.com/docs/custom-skills/host-a-custom-skill-as-a-web-service.html#check-request-signature>`__.
CERT_CHAIN_URL_PROTOCOL = "https"

#: Case insensitive hostname to be checked on signature certificate url.
#: For more info, check `link <https://developer.amazon.com/docs/custom-skills/host-a-custom-skill-as-a-web-service.html#check-request-signature>`__.
CERT_CHAIN_URL_HOSTNAME = "s3.amazonaws.com"

#: Path presence to be checked on signature certificate url.
#: For more info, check `link <https://developer.amazon.com/docs/custom-skills/host-a-custom-skill-as-a-web-service.html#check-request-signature>`__.
CERT_CHAIN_URL_STARTPATH = "{0}echo.api{0}".format(os.path.sep)

#: Port to be checked on signature certificate url.
#: For more info, check `link <https://developer.amazon.com/docs/custom-skills/host-a-custom-skill-as-a-web-service.html#check-request-signature>`__.
CERT_CHAIN_URL_PORT = 443

#: Domain presence check in Subject Alternative Names (SANs) of
#: signing certificate.
#: For more info, check `link <https://developer.amazon.com/docs/custom-skills/host-a-custom-skill-as-a-web-service.html#check-request-signature>`__.
CERT_CHAIN_DOMAIN = "echo-api.amazon.com"

#: Character encoding used in the request.
CHARACTER_ENCODING = "utf-8"

#: Maximum allowable tolerance in request timestamp.
#: For more info, check `link <https://developer.amazon.com/docs/custom-skills/host-a-custom-skill-as-a-web-service.html#check-request-timestamp>`__.
MAX_NORMAL_REQUEST_TOLERANCE_IN_MILLIS = 150000

#: Maximum allowable tolerance for skill events in request timestamp.
#: For more info, check `link <https://developer.amazon.com/docs/smapi/skill-events-in-alexa-skills.html#delivery-of-events-to-the-skill>`__.
MAX_SKILL_EVENT_TOLERANCE_IN_MILLIS = 3600000

#: Skill events that can have max timestamp tolerance values of an hour
ALEXA_SKILL_EVENT_LIST = {'AlexaSkillEvent.SkillEnabled',
                          'AlexaSkillEvent.SkillDisabled',
                          'AlexaSkillEvent.SkillPermissionChanged',
                          'AlexaSkillEvent.SkillPermissionAccepted',
                          'AlexaSkillEvent.SkillAccountLinked'}