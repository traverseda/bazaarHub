"""
A collection of small utilities that should make my life a lot easier.
"""
import rpyc, os, cryptography, yaml
from bazaar.identity import verifyArgs,PermissionDenied

class FirstComeRegistry(rpyc.Service):
    """
    A dictionary with a "readOnly" property that returns a
    read-only view of the dict.
    """
    def __init__(self, *args):
        self.objects=dict()
        self.readOnly=rpyc.restricted(self, {"__getattribute__","__getitem__","__repr__","copy","keys","values","items","__contains__","__len__"})

    @property
    def exposed_readOnly(self):
        return self.readOnly
    
    @verifyArgs
    def set(self,key,value):
        self.objects['key']=value

    def exposed_set(self, signedArgs):
        return self.set(signedArgs)
