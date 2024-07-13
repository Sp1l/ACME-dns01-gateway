#!/usr/bin/env python3

"""Blake2b secure hash generation and checking"""

import argparse
import base64
from getpass import getpass
import hashlib
from tempfile import mkstemp
from os import urandom
from pathlib import Path
import sys
from typing import Tuple

# https://man.freebsd.org/cgi/man.cgi?query=crypt&sektion=3
# Use Modular Crypt, algorithm 7
# making a passwd in style username:$7$salt$saltedhash

if hasattr(hashlib, "scrypt"):
    key_derivation = "8"
else:
    key_derivation = "7"


PASSWDFILE="acmepasswd"

def b64encode(b: (bytes|str), ) -> str:
    """base64 encoding allowing str as well as bytes

    Args:
        b (bytes|str): The string or bytes object to encode

    Returns:
        str: single line base64 representation of input, padding removed
    """
    if isinstance(b, str):
        b = bytes(b, "utf-8")
    # Return the encoded string with trailing = removed
    return base64.b64encode(b).decode().rstrip("=")

def b64decode(b: (bytes|str)) -> bytes:
    """Raw, single-line base64 decoding allowing str as well as bytes without
    padding

    Args:
        b (str|bytes): raw base64 encoded string

    Returns:
        bytes: the decoded bytes
    """
    if isinstance(b, str):
        b = bytes(b, "ascii")
    # Add missing padding
    b = b.ljust(len(b)-len(b)%4+4,b"=")
    return base64.b64decode(b)

def crypt(passwd: str, usalt: str=None):
    """Derive a salted hash password (expensive)

    Args:
        passwd (str): The string to hash
        salt (str, optional): The salt to use. Defaults to None.

    Returns:
        str: base64 encoded generated or provided salt
        str: base64 encoded salted hash digest
    """

    if isinstance(passwd, str):
        passwd = passwd.encode()
    if usalt:
        usalt = b64decode(usalt)
    else:
        usalt = urandom(16)
    if key_derivation == "8":
        cdigest = hashlib.scrypt(password=passwd, salt=usalt, n=16384, r=8, p=1, dklen=32)
    else:
        cdigest = hashlib.pbkdf2_hmac("sha3_512", passwd, usalt, 262144, 32)
    return b64encode(usalt), b64encode(cdigest)

def get_user(user: str) -> Tuple[str, str]:
    """Retrieve user-information from passwd file

    Args:
        user (str): user to retrieve

    Returns:
        str: base64-encoded salt (None if no user not in file)
        str: base64-encoded digest (None if no user not in file)
    """
    usalt = None
    with Path(PASSWDFILE).open(encoding="ascii") as f:
        for line in f:
            if line.split(":", maxsplit=1)[0] == user:
                parts = line.split("$")
                # parts[0] = user:
                # parts[1] = 7
                usalt = parts[2]
                udigest = parts[3].rstrip("\r\n")
                break
    if usalt:
        return usalt, udigest
    else:
        return None, None

def check_password(user: str, passwd: str) -> bool:
    """Check password for a user against passwd file

    Args:
        user (str): user name
        passwd (str): user passwd

    Returns:
        bool: True  if password correct
              False if password incorrect
              None  if user not found
    """
    ssalt, sdigest = get_user(user)
    if not ssalt:
        # User does not exist
        return None
    csalt, cdigest = crypt(passwd, ssalt)
    if ssalt == csalt and sdigest == cdigest:
        return True
    return False

def manage_user(user: str, usalt: str, udigest: str, delete: bool=False):
    """UNSAFE update of passwd file

    Args:
        user (str): user name.
        salt (str): base64-encoded salt.
        digest (str): base64-encoded digest.
        action (str): update (also for add) or delete. Default update.
    """
    # UNSAFE, uses atomic rename at end
    src = Path(PASSWDFILE)
    _, abspath = mkstemp(prefix=f"{PASSWDFILE}.", dir=".")
    tgt = Path(abspath)
    updated = False
    deleted = False
    with tgt.open("w", encoding="ascii") as tmpfile:
        with src.open(encoding="ascii") as f:
            for line in f:
                if line.split(":", maxsplit=1)[0] == user:
                    if delete:
                        deleted = True
                    else:
                        tmpfile.write(f"{user}:${key_derivation}${usalt}${udigest}\n")
                    updated = True
                else:
                    tmpfile.write(line)
        if not updated:
            tmpfile.write(f"{user}:${key_derivation}${usalt}${udigest}\n")
    tgt.chmod(src.stat().st_mode)
    src.unlink()
    tgt.rename("acmepasswd")
    if delete and not deleted:
        result = "not found"
    elif delete:
        result = "deleted"
    elif updated:
        result = "updated"
    else:
        result = "added"
    return f"User \"{user}\" {result}"

if __name__ == "__main__":
    # Implements CLI
    parser = argparse.ArgumentParser(description="Manage user file for basic authentication")
    parser.add_argument("username")
    group1 = parser.add_mutually_exclusive_group()
    group1.add_argument("-i","--stdin", action="store_true",
         help="Read the password from stdin without verification (for script usage).")
    group1.add_argument("-g", "--generate", action="store_true",
        help="generate and set a 256-bit random password for user")
    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument("-D","--delete" , help="delete user", action="store_true")
    group2.add_argument("-v","--verify" , help="verify password", action="store_true")
    args = parser.parse_args()

    if not args.delete:
        if args.generate:
            password = base64.urlsafe_b64encode(urandom(32)).rstrip("=")
            print(f"setting password '{password}' for {args.username}")
        elif args.stdin:
            password = sys.stdin.readline()
        else:
            password = getpass()
    if args.delete:
        print(manage_user(args.username, None, None, delete=True))
    elif args.verify:
        passwd_ok = check_password(args.username, password)
        if passwd_ok is None:
            print(f"User \"{args.username}\" not found")
        elif not passwd_ok:
            print(f"Password incorrect for \"{args.username}\"")
        else:
            print(f"Password OK for \"{args.username}\"")
    else:
        salt, digest = crypt(password, None)
        print(manage_user(args.username, salt, digest))

    # user = sys.argv[1]
    # passwd = sys.argv[2]
    # salt, digests = get_user(sys.argv[1])
    # salt, digest = crypt(sys.argv[2], salt)
    # update_user(sys.argv[1], salt, digest)


