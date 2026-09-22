# Welcome to Secure Code Game Season-1/Level-5!

# This is the last level of our first season, good luck!

import binascii
import secrets
import hashlib
import os
import bcrypt

class Random_generator:

    # FIX: uses `secrets.choice` instead of `random.choice`. The `random`
    # module is a Mersenne Twister PRNG -- not cryptographically secure.
    # Its internal state can be reconstructed from observed outputs, making
    # tokens predictable. `secrets` is built on os.urandom() and is safe
    # for security-sensitive values like tokens, session ids, reset codes.
    def generate_token(self, length=8, alphabet=(
    '0123456789'
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    )):
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    # FIX: uses bcrypt's own gensalt() instead of hand-assembling a salt
    # string from `random.randint` digits. Rolling your own salt format is
    # both insecure (weak PRNG again) and error-prone (easy to violate
    # bcrypt's expected structure/alphabet without noticing).
    def generate_salt(self, rounds=12):
        return bcrypt.gensalt(rounds)

class SHA256_hasher:

    # produces the password hash by combining password + salt because hashing
    def password_hash(self, password, salt):
        password = binascii.hexlify(hashlib.sha256(password.encode()).digest())
        password_hash = bcrypt.hashpw(password, salt)
        return password_hash.decode('ascii')

    # verifies that the hashed password reverses to the plain text version on verification
    def password_verification(self, password, password_hash):
        password = binascii.hexlify(hashlib.sha256(password.encode()).digest())
        password_hash = password_hash.encode('ascii')
        return bcrypt.checkpw(password, password_hash)

# REMOVED: MD5_hasher.
# MD5 is unsuitable for password storage: it is fast by design (cheap to
# brute-force at scale), it is used here with no salt at all (identical
# passwords -> identical hashes, vulnerable to rainbow tables), and it is a
# cryptographically broken hash function. There is no safe configuration of
# MD5 for this purpose, so rather than leave it present-but-discouraged, it
# is removed to make it impossible to select accidentally. SHA256_hasher
# (SHA-256 + bcrypt) is the only hasher available now.

# a collection of sensitive secrets necessary for the software to operate
PRIVATE_KEY = os.environ.get('PRIVATE_KEY')
PUBLIC_KEY = os.environ.get('PUBLIC_KEY')
# FIX: loaded from the environment, like PRIVATE_KEY/PUBLIC_KEY, instead of
# being a hardcoded literal committed to source control (CWE-798: Use of
# Hardcoded Credentials). Anyone with read access to the repo -- or anyone
# who finds it in a leak, a fork, or a static-analysis dump -- previously
# had the real key.
SECRET_KEY = os.environ.get('SECRET_KEY')
# FIX: points at the secure hasher. The old value 'MD5_hasher' silently
# routed real password hashing to the broken algorithm above -- a plain
# string constant that no static analyzer would flag as dangerous on its
# own, since the risk only exists once something else does
# getattr(this_module, PASSWORD_HASHER)() at runtime.
PASSWORD_HASHER = 'SHA256_hasher'


# Contribute new levels to the game in 3 simple steps!
# Read our Contribution Guideline at github.com/skills/secure-code-game/blob/main/CONTRIBUTING.md