from abc import ABCMeta, abstractmethod
import flask


class VerifierInterface(object):
    """ Verifier Interface to allow for multiple different verification methods on a request. """
    __metaclass__ = ABCMeta

    @abstractmethod
    def verify(self, request: flask.Request):
        raise NotImplementedError
