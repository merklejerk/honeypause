from Crypto.Hash import keccak
import secrets
from argparse import ArgumentParser

def keccak256(v):
    h = keccak.new(digest_bytes=32)
    h.update(v)
    return h.digest()

ap = ArgumentParser()
ap.add_argument('target_hash', type=str)
args = ap.parse_args()

target_hash = bytes.fromhex(args.target_hash[2:])
while True:
    preimage = secrets.token_bytes(32)
    if keccak256(preimage)[:len(target_hash)] == target_hash:
        print(f'0x{preimage.hex()}')
        break

