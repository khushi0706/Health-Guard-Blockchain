import ctypes
import os


sphincs_lib_path = '/home/khushi/Downloads/sphincsplus/sha2-avx2/libsphincs.so'
sphincs_lib = ctypes.CDLL(os.path.abspath(sphincs_lib_path))


SIGNATURE_BYTES = 17088
PUBLIC_KEY_BYTES = 32
SECRET_KEY_BYTES = 64


sphincs_lib.crypto_sign_keypair.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),   # pk
    ctypes.POINTER(ctypes.c_ubyte)    # sk
]
sphincs_lib.crypto_sign_keypair.restype = None

sphincs_lib.crypto_sign.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),   # sm
    ctypes.POINTER(ctypes.c_ulonglong),  # smlen
    ctypes.POINTER(ctypes.c_ubyte),   # m
    ctypes.c_ulonglong,               # mlen
    ctypes.POINTER(ctypes.c_ubyte)    # sk
]
sphincs_lib.crypto_sign.restype = ctypes.c_int

sphincs_lib.crypto_sign_open.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),   # m
    ctypes.POINTER(ctypes.c_ulonglong),  # mlen
    ctypes.POINTER(ctypes.c_ubyte),   # sm
    ctypes.c_ulonglong,               # smlen
    ctypes.POINTER(ctypes.c_ubyte)    # pk
]
sphincs_lib.crypto_sign_open.restype = ctypes.c_int


def generate_keypair():
    pk = (ctypes.c_ubyte * PUBLIC_KEY_BYTES)()
    sk = (ctypes.c_ubyte * SECRET_KEY_BYTES)()
    sphincs_lib.crypto_sign_keypair(pk, sk)
    return bytes(pk), bytes(sk)


def sign_message(message, sk):
    sm = (ctypes.c_ubyte * (len(message) + SIGNATURE_BYTES))()
    smlen = ctypes.c_ulonglong()
    message_ptr = ctypes.cast(message, ctypes.POINTER(ctypes.c_ubyte))
    sk_ptr = ctypes.cast(sk, ctypes.POINTER(ctypes.c_ubyte))

    if sphincs_lib.crypto_sign(sm, ctypes.byref(smlen), message_ptr, len(message), sk_ptr) != 0:
        raise RuntimeError("Error signing message")
    
    return bytes(sm[:smlen.value])


def verify_signature(signed_message, pk):
    m = (ctypes.c_ubyte * len(signed_message))()
    mlen = ctypes.c_ulonglong()
    sm_ptr = ctypes.cast(signed_message, ctypes.POINTER(ctypes.c_ubyte))
    pk_ptr = ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte))

    if sphincs_lib.crypto_sign_open(m, ctypes.byref(mlen), sm_ptr, len(signed_message), pk_ptr) != 0:
        raise RuntimeError("Error verifying signature")
    
    return bytes(m[:mlen.value])

