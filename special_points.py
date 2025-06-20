from cryptography.hazmat.primitives.asymmetric import x25519

# Special point from https://cr.yp.to/ecdh.html
public_int = 325606250916557431795983626356110631294008115727848805560023387167927233504
print(public_int.to_bytes(32, 'little').hex())

public_bytes = public_int.to_bytes(32, 'little')
public_key = x25519.X25519PublicKey.from_public_bytes(public_bytes)
for i in range(16):
    private_int = i << 3
    private_bytes = private_int.to_bytes(32, 'little')
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    # Will error for (some of the) points in the small subgroup
    shared_key = private_key.exchange(public_key)
