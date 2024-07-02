import ctypes
import os


dilithium_lib_path = '/home/khushi/Downloads/dilithium/avx2/libpqcrystals_all_in_one.so'
dilithium_lib = ctypes.CDLL(os.path.abspath(dilithium_lib_path))


PUBLIC_KEY_BYTES = 1312
SECRET_KEY_BYTES = 2528
SIGNATURE_BYTES = 2420


dilithium_lib.pqcrystals_dilithium2aes_avx2_keypair.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),   # pk
    ctypes.POINTER(ctypes.c_ubyte)    # sk
]
dilithium_lib.pqcrystals_dilithium2aes_avx2_keypair.restype = ctypes.c_int

dilithium_lib.pqcrystals_dilithium2aes_avx2_signature.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),   # sig
    ctypes.POINTER(ctypes.c_ulonglong),  # siglen
    ctypes.POINTER(ctypes.c_ubyte),   # msg
    ctypes.c_ulonglong,               # msglen
    ctypes.POINTER(ctypes.c_ubyte)    # sk
]
dilithium_lib.pqcrystals_dilithium2aes_avx2_signature.restype = ctypes.c_int

dilithium_lib.pqcrystals_dilithium2aes_avx2_verify.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),   # sig
    ctypes.c_ulonglong,               # siglen
    ctypes.POINTER(ctypes.c_ubyte),   # msg
    ctypes.c_ulonglong,               # msglen
    ctypes.POINTER(ctypes.c_ubyte)    # pk
]
dilithium_lib.pqcrystals_dilithium2aes_avx2_verify.restype = ctypes.c_int


def generate_keypair():
    pk = (ctypes.c_ubyte * PUBLIC_KEY_BYTES)()
    sk = (ctypes.c_ubyte * SECRET_KEY_BYTES)()
    if dilithium_lib.pqcrystals_dilithium2aes_avx2_keypair(pk, sk) != 0:
        raise RuntimeError("Error generating Dilithium keypair")
    return bytes(pk), bytes(sk)


def sign_message(message, sk):
    sig = (ctypes.c_ubyte * SIGNATURE_BYTES)()
    siglen = ctypes.c_ulonglong()
    message_ptr = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
    sk_ptr = (ctypes.c_ubyte * len(sk)).from_buffer_copy(sk)

    if dilithium_lib.pqcrystals_dilithium2aes_avx2_signature(sig, ctypes.byref(siglen), message_ptr, len(message), sk_ptr) != 0:
        raise RuntimeError("Error signing message with Dilithium")
    
    return bytes(sig[:siglen.value])


def verify_signature(message, sig, pk):
    message_ptr = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
    sig_ptr = (ctypes.c_ubyte * len(sig)).from_buffer_copy(sig)
    pk_ptr = (ctypes.c_ubyte * len(pk)).from_buffer_copy(pk)

    if dilithium_lib.pqcrystals_dilithium2aes_avx2_verify(sig_ptr, len(sig), message_ptr, len(message), pk_ptr) != 0:
        return False
    
    return True


