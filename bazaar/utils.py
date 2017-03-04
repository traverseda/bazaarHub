"""
A collection of small utilities that should make my life a lot easier.
"""
import rpyc, os, cryptography, yaml
from bazaar.identity import verifyArgs,PermissionDenied

class ReadOnlyDict(dict):
    """
    A dictionary with a "readOnly" property that returns a
    read-only view of the dict itself.
    """
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.readOnly=rpyc.restricted(self, {"__getattribute__","__getitem__","__repr__","copy","keys","values","items","__contains__","__len__"})

    @property
    def exposed_readOnly(self):
        return self.readOnly


class FirstComeDict(ReadOnlyDict):
    """
    A dictionary that lets only the first identity to set a key
    change/delete it in the future.
    """
