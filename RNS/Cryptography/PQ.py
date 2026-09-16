# Reticulum License
#
# Copyright (c) 2016-2025 Mark Qvist
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import annotations

import contextlib

try:
    import oqs
except Exception:  # pragma: no cover - optional dependency
    oqs = None

MLKEM_ALGORITHM = "ML-KEM-768"
MLKEM_PUBLIC_KEY_SIZE = 1184
MLKEM_PRIVATE_KEY_SIZE = 2400
MLKEM_CIPHERTEXT_SIZE = 1088
MLDSA_ALGORITHM = "ML-DSA-65"
MLDSA_PUBLIC_KEY_SIZE = 1952
MLDSA_PRIVATE_KEY_SIZE = 4032
MLDSA_SIGNATURE_SIZE = 3309


def capabilities():
    """Return the exact PQ algorithms exposed by the installed backend."""
    if oqs is None:
        return set()
    try:
        kem = set(oqs.get_enabled_kem_mechanisms())
        sig = set(oqs.get_enabled_sig_mechanisms())
    except Exception:
        return set()
    return kem.intersection({MLKEM_ALGORITHM}) | sig.intersection({MLDSA_ALGORITHM})


def available() -> bool:
    return capabilities() == {MLKEM_ALGORITHM, MLDSA_ALGORITHM}


def _require_bytes(data, size, label):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"{label} must be bytes")
    data = bytes(data)
    if len(data) != size:
        raise ValueError(f"{label} must be exactly {size} bytes")
    return data


def _require_backend():
    if not available():
        raise RuntimeError("required liboqs-python algorithms are not available")


def _require_ciphertext(data):
    return _require_bytes(data, MLKEM_CIPHERTEXT_SIZE, "ML-KEM ciphertext")


def _require_signature(data):
    return _require_bytes(data, MLDSA_SIGNATURE_SIZE, "ML-DSA signature")

class _BasePQKey:
    algorithm = None
    public_size = None
    private_size = None

    def __init__(self, public_bytes: bytes | None = None, private_bytes: bytes | None = None):
        self._public_bytes = _require_bytes(public_bytes, self.public_size, f"{self.algorithm} public key") if public_bytes is not None else None
        self._private_bytes = _require_bytes(private_bytes, self.private_size, f"{self.algorithm} private key") if private_bytes is not None else None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

class MLKEMPublicKey(_BasePQKey):
    algorithm = MLKEM_ALGORITHM
    public_size = MLKEM_PUBLIC_KEY_SIZE

    @classmethod
    def from_public_bytes(cls, data):
        return cls(public_bytes=data)

    def public_bytes(self):
        if self._public_bytes is None:
            raise KeyError("ML-KEM public key is unavailable")
        return self._public_bytes

    def encapsulate(self):
        _require_backend()
        if self._public_bytes is None:
            raise KeyError("ML-KEM public key is unavailable")
        with oqs.KeyEncapsulation(self.algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(self._public_bytes)
            return _require_ciphertext(ciphertext), bytes(shared_secret)


class MLKEMPrivateKey(_BasePQKey):
    algorithm = MLKEM_ALGORITHM
    public_size = MLKEM_PUBLIC_KEY_SIZE
    private_size = MLKEM_PRIVATE_KEY_SIZE

    @classmethod
    def generate(cls):
        _require_backend()
        with oqs.KeyEncapsulation(cls.algorithm) as kem:
            public_bytes = kem.generate_keypair()
            private_bytes = kem.export_secret_key()
        return cls(public_bytes=bytes(public_bytes), private_bytes=bytes(private_bytes))

    @classmethod
    def from_private_bytes(cls, data, public_bytes=None):
        return cls(public_bytes=public_bytes, private_bytes=data)

    def private_bytes(self):
        if self._private_bytes is None:
            raise KeyError("ML-KEM private key is unavailable")
        return self._private_bytes

    def public_key(self):
        if self._public_bytes is None:
            raise KeyError("ML-KEM public key is unavailable")
        return MLKEMPublicKey.from_public_bytes(self._public_bytes)

    def decapsulate(self, ciphertext):
        _require_backend()
        if self._private_bytes is None:
            raise KeyError("ML-KEM private key is unavailable")
        ciphertext = _require_ciphertext(ciphertext)
        with oqs.KeyEncapsulation(self.algorithm, secret_key=self._private_bytes) as kem:
            shared_secret = kem.decap_secret(ciphertext)
            return bytes(shared_secret)


class MLDSAPublicKey(_BasePQKey):
    algorithm = MLDSA_ALGORITHM
    public_size = MLDSA_PUBLIC_KEY_SIZE

    @classmethod
    def from_public_bytes(cls, data):
        return cls(public_bytes=data)

    def public_bytes(self):
        if self._public_bytes is None:
            raise KeyError("ML-DSA public key is unavailable")
        return self._public_bytes

    def verify(self, signature, message):
        _require_backend()
        if self._public_bytes is None:
            raise KeyError("ML-DSA public key is unavailable")
        signature = _require_signature(signature)
        with oqs.Signature(self.algorithm) as sig:
            return bool(sig.verify(message, signature, self._public_bytes))


class MLDSAPrivateKey(_BasePQKey):
    algorithm = MLDSA_ALGORITHM
    public_size = MLDSA_PUBLIC_KEY_SIZE
    private_size = MLDSA_PRIVATE_KEY_SIZE

    @classmethod
    def generate(cls):
        _require_backend()
        with oqs.Signature(cls.algorithm) as sig:
            public_bytes = sig.generate_keypair()
            private_bytes = sig.export_secret_key()
        return cls(public_bytes=bytes(public_bytes), private_bytes=bytes(private_bytes))

    @classmethod
    def from_private_bytes(cls, data, public_bytes=None):
        return cls(public_bytes=public_bytes, private_bytes=data)

    def private_bytes(self):
        if self._private_bytes is None:
            raise KeyError("ML-DSA private key is unavailable")
        return self._private_bytes

    def public_key(self):
        if self._public_bytes is None:
            raise KeyError("ML-DSA public key is unavailable")
        return MLDSAPublicKey.from_public_bytes(self._public_bytes)

    def sign(self, message):
        _require_backend()
        if self._private_bytes is None:
            raise KeyError("ML-DSA private key is unavailable")
        with oqs.Signature(self.algorithm, secret_key=self._private_bytes) as sig:
            return _require_signature(sig.sign(message))
