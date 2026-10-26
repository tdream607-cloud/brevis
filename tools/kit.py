#!/usr/bin/env python3
"""Private build kit for the status pages (encrypted, AES-256-GCM).

    KIT_KEY=<key> python3 tools/kit.py unpack <dir>   # decrypt tools/kit.enc into <dir>
    KIT_KEY=<key> python3 tools/kit.py pack <dir>     # encrypt <dir> into tools/kit.enc

The key is never stored in this repository.
"""
import sys, os, io, tarfile, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENC = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kit.enc')
ub = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
key = ub(os.environ['KIT_KEY'])
cmd, d = sys.argv[1], sys.argv[2]
if cmd == 'pack':
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as t:
        t.add(d, arcname='.')
    iv = os.urandom(12)
    open(ENC, 'wb').write(iv + AESGCM(key).encrypt(iv, buf.getvalue(), None))
    print('packed', os.path.getsize(ENC), 'bytes')
elif cmd == 'unpack':
    raw = open(ENC, 'rb').read()
    data = AESGCM(key).decrypt(raw[:12], raw[12:], None)
    os.makedirs(d, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as t:
        t.extractall(d, filter='data') if hasattr(tarfile, 'data_filter') else t.extractall(d)
    print('unpacked to', d)
