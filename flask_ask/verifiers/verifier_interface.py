from abc import ABCMeta, abstractmethod
import flask


class VerifierInterface(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def verify(self, request: flask.Request):
        raise NotImplementedError
