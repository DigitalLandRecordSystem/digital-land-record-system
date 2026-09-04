import pytest
from app.crypto import key_manager as km
from app.crypto import rsa_service, ecc_service


def test_serialisation_roundtrip():
    public, private = rsa_service.generate_keypair(1024)
    assert km.deserialise_key(km.serialise_key(public)) == public
    assert km.deserialise_key(km.serialise_key(private)) == private


def test_ecc_point_survives_serialisation():
    private, public = ecc_service.generate_keypair()
    restored = km.deserialise_key(km.serialise_key(public))
    assert restored == public
    assert isinstance(restored["Q"], tuple)      # not a list


def test_wrapped_private_key_roundtrip():
    _, private = rsa_service.generate_keypair(1024)
    assert km.unwrap_private_key(km.wrap_private_key(private)) == private


def test_wrapped_key_is_not_plaintext():
    _, private = rsa_service.generate_keypair(1024)
    wrapped = km.wrap_private_key(private)
    assert str(private["d"]) not in wrapped      # d must not appear in storage


def test_create_and_retrieve(conn, user_id):
    km.create_user_keys(conn, user_id)

    for algorithm in (km.RSA, km.ECC):
        public, private, version = km.get_active_key(conn, user_id, algorithm)
        assert version == 1

    # keys must actually work
    rsa_pub, rsa_priv, _ = km.get_active_key(conn, user_id, km.RSA)
    assert rsa_service.decrypt(rsa_service.encrypt(b"hello", rsa_pub), rsa_priv) == b"hello"

    ecc_pub, ecc_priv, _ = km.get_active_key(conn, user_id, km.ECC)
    assert ecc_service.decrypt(ecc_service.encrypt(b"deed", ecc_pub), ecc_priv) == b"deed"


def test_rotation(conn, user_id):
    km.create_user_keys(conn, user_id)
    old_public, old_private, _ = km.get_active_key(conn, user_id, km.RSA)

    km.rotate_key(conn, user_id, km.RSA)
    new_public, _, new_version = km.get_active_key(conn, user_id, km.RSA)

    assert new_version == 2
    assert new_public != old_public

    # the retired key is retained, so old records stay readable
    recovered_pub, recovered_priv = km.get_key_version(conn, user_id, km.RSA, 1)
    assert recovered_pub == old_public
    ciphertext = rsa_service.encrypt(b"old record", old_public)
    assert rsa_service.decrypt(ciphertext, recovered_priv) == b"old record"


def test_missing_key_raises(conn, user_id):
    with pytest.raises(LookupError):
        km.get_active_key(conn, user_id, km.RSA)