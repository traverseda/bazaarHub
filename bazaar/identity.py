import rpyc, os, cryptography, yaml, collections, hashlib, time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

default_backend = cryptography.hazmat.backends.default_backend()

ArgSig = collections.namedtuple('ArgSig', ['args','kwargs','salt','hash','identity','idFingerprint'])

class PermissionDenied(Exception):
    pass
class SigatureVerificationFailed(PermissionDenied):
    pass

identityCache={}
"""
We use the "identityCache" object to avoid round-trips.
"""

def verifyArgs(protectedFunction):
    def wrapper(signature):
        sig=signature
        if not signature.idFingerprint in identityCache:
            fingerprint = hashlib.sha256(signature.identity.public_key).hexdigest()
            if fingerprint == signature.idFingerprint:
                identityCache[fingerprint]=signature.identity.public_key
            else:
                raise SigatureVerificationFailed("Fingerprint Mismatch")

        verifier = public_key.verifier(
            signature.hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verifier.update(sig.args+sig.kwargs+sig.salt)
        verifier.verify()

        args = rpyc.core.brine.load(signature.args)
        kwargs = rpyc.core.brine.load(signature.kwargs)
        kwargs = {k:v for k,v in kwargs if k != "identity"}

        return protectedFunction(*args,**kwargs,signature=signature)
    return wrapper


class Identity(object):
    """
    A public key implementation that can used to to verify identities.
    This version accepts a file or filepath for persistance, as there's not much
    point in a pubkey system without persistance.
    """
    def __init__(self, keyPath, password=None):
        keyPath=os.path.abspath(keyPath)
        if not os.path.isfile(keyPath):
            print("Generating new private key at "+keyPath)
            if password:
                print("Using password")
            else:
                password=""
                print("Not using password")
             
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend
            )
            with open(keyPath, "wb") as key_file:
                keyArgs = {
                    "encoding":serialization.Encoding.PEM,
                    "format":serialization.PrivateFormat.PKCS8,
                }
                if password:
                    keyArgs['encryption_algorithm']=serialization.BestAvailableEncryption(password.encode("utf-8"))
                else:
                    keyArgs['encryption_algorithm']=serialization.NoEncryption()

                pem = private_key.private_bytes(**keyArgs)
                key_file.write(pem)


        with open(keyPath, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
                backend=default_backend
            )
        self.private_key=private_key
        self.public_key=self.private.public_key()
        self.fingerprint = hashlib.sha256(self.public_key).hexdigest()

    @property
    def exposed_public_key(self):
        return self.public_key
    @property
    def exposed_fingerprint(self):
        return self.fingerprint

    def getSigner(self):#For threadSafety
        signer = self.private_key.signer(
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        return signer

    def sign(self, message):
        signer = self.getSigner()
        return signer.update(message).finalize()

    def getSalt(self):
        """
        A salt is used to prevent replay attacks, among other things.
        """
        return str(int(time.time()))

    def signArgs(self, *args, **kwargs):
        """
        Used to sign arguments (and kwargs).
        To verify use the "@verifyArgs" decorator in this module.
        include "signature" among the decorated functions kwargs.
        If you can see the signature kwarg, the args and kwargs
        you're seeing have been verified to have been signed by the identiy
        in `signature.identity`.
        """
        sig = {}
        sig['identity']=self
        sig['idFingerprint']=self.fingerprint

        sig['salt']=self.getSalt()
        sig['args']=rpyc.core.brine.dump(args)
        sig['kwargs']=rpyc.core.brine.dump(kwargs)
        sig['hash']=self.sign(sig['args']+sig['kwargs']+sig['salt'])

        return ArgSig(**sig)
        
        
