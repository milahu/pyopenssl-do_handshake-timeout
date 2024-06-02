#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import tempfile
import random
import atexit
import signal
import shutil
import select
import ssl
import datetime
import traceback
from urllib.parse import urlsplit
from multiprocessing import Process
from http.server import HTTPServer, SimpleHTTPRequestHandler

import OpenSSL
from OpenSSL import SSL

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs7

#import certifi

import timeout_decorator

# pyppeteer/util.py
import gc
import socket


def get_free_port() -> int:
    """Get free port."""
    sock = socket.socket()
    # sock.bind(('localhost', 0))
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    del sock
    gc.collect()
    return port


from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa



class TestFunctions:

    # note: no "self" arg

    def _version010(hostname, port, cafile):

        ip = hostname

        # https://github.com/pyca/pyopenssl/issues/168#issue-47259843
        # viraptor commented on Oct 30, 2014

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)

        #ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD) # tlsv1 alert protocol version
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
        #ctx.set_options(OpenSSL.SSL.OP_NO_SSLv2 | OpenSSL.SSL.OP_NO_SSLv3)
        #ctx.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda _a, _b, _c, _d, _e: None)
        ctx.load_verify_locations(cafile=cafile)

        conn = OpenSSL.SSL.Connection(ctx, s)
        conn.set_tlsext_host_name(hostname.encode('utf-8'))

        # FIXME ConnectionRefusedError: [Errno 111] Connection refused
        conn.connect((ip, port))

        s.settimeout(None)  # the workaround

        try:
            print("conn.do_handshake ...")
            # FIXME this can hang
            conn.do_handshake()
            print("conn.do_handshake ok")
        except OpenSSL.SSL.WantReadError:
            # this happens on every connection
            raise

        s.settimeout(2)  # restore socket timeout

        cert_chain = conn.get_peer_cert_chain()
        return cert_chain

    def version015(hostname, port, cafile):
        # https://github.com/pyca/pyopenssl/issues/168#issuecomment-61813592
        # exarkun commented on Nov 5, 2014
        """
        OpenSSL.SSL.Connection.do_handshake is not a native Python socket operation though.
        It is a call into OpenSSL's SSL_do_handshake API
        which operates on the actual (platform-level) socket directly.
        Python's timeout support puts that socket into non-blocking mode.
        OpenSSL's SSL_do_handshake encounters this
        and does the standard OpenSSL-level thing -
        translate the "EWOULDBLOCK" read error into an OpenSSL WantReadError
        (that's pyOpenSSL's spelling of the error
        but that's easier to talk about here).
        pyOpenSSL raises this exception up to the caller of do_handshake.

        The only idea I have for fixing this is
        to teach pyOpenSSL about Python's socket timeout feature:
        at every point in the API where there is an OpenSSL operation
        that operates directly on a platform-level socket,
        introduce the same kind of wait-and-retry logic
        that Python's own socket library has
        (which implements the timeout feature).

        timeout = self._socket.gettimeout()
        if timeout is not None:
            start = time()
        while True:
            try:
                return <some OpenSSL API>
            except (WantReadError, WantWriteError):
                if timeout is None or start + timeout > time():
                    raise
                select([self._socket], [self._socket], [], timeout - (time() - start))
                if <select timed out>:
                    raise <something - the original exception?  a specific timeout exception?>
        """

        ssl_context = OpenSSL.SSL.Context(method=OpenSSL.SSL.TLS_CLIENT_METHOD)
        ssl_context.load_verify_locations(cafile=cafile)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = SSL.Connection(context=ssl_context, socket=sock)
        #sock.settimeout(5) # no. sock.gettimeout() still returns None
        conn.settimeout(5)
        conn.connect((hostname, port))
        conn.setblocking(1)

        #conn.do_handshake()

        def do_handshake():
            conn.setblocking(0) # unblock conn.do_handshake
            #timeout = sock.gettimeout() # None
            #timeout = conn.gettimeout() # None
            timeout = 5
            print("timeout", timeout)
            if timeout is not None:
                start = time.time()
            last_remain = timeout
            while True:
                try:
                    #return <some OpenSSL API>
                    #print("conn.do_handshake ...")
                    res = conn.do_handshake()
                    print("conn.do_handshake ok")
                    conn.setblocking(1)
                    return res
                except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantWriteError) as exc:
                    #print("exc", exc)
                    remain = timeout - (time.time() - start)
                    t_step = last_remain - remain # 0.0004
                    last_remain = remain
                    #print("remain", remain)
                    #print("t_step", t_step)
                    #if timeout is None or start + timeout > time.time():
                    if remain < 0:
                        #raise
                        conn.setblocking(1)
                        raise TimeoutError
                    # TODO? handle timeout from select
                    readable, writable, errored = select.select(
                        # no. dont select writable sock
                        #[sock], [sock], [], remain
                        [sock], [], [], remain
                    )
                    print("select", (readable, writable, errored))
                    #if <select timed out>:
                    #    raise <something - the original exception?  a specific timeout exception?>
                    # no. this was only needed with select writable sock
                    # because the sock is always writable
                    #time.sleep(0.5) # reduce cpu load

        do_handshake()

        cert_chain = conn.get_peer_cert_chain()
        conn.shutdown()
        conn.close()
        return cert_chain

    def _version020(hostname, port, cafile):
        # https://github.com/pyca/pyopenssl/issues/168#issuecomment-289194607
        # brandond commented on Mar 25, 2017
        """
        Here's what works for me

        You can put a timeout on the connect and it will work as desired,
        you just have to put the socket back into blocking mode before calling into OpenSSL.
        Of course this just gets you a timeout on the TCP connection;
        if things stall during the SSL handshake
        you're still going to be left hanging but it's better than nothing.
        """
        ssl_context = OpenSSL.SSL.Context(method=OpenSSL.SSL.TLS_CLIENT_METHOD)
        ssl_context.load_verify_locations(cafile=cafile)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = SSL.Connection(context=ssl_context, socket=sock)
        conn.settimeout(5)
        conn.connect((hostname, port))
        conn.setblocking(1)
        # FIXME this hangs
        print("conn.do_handshake ...")
        conn.do_handshake()
        print("conn.do_handshake ok")
        cert_chain = conn.get_peer_cert_chain()
        conn.shutdown()
        conn.close()
        return cert_chain

    def _version030(host, port, cafile):
        # https://github.com/pyca/pyopenssl/issues/168#issuecomment-289235399
        # webratz commented on Mar 25, 2017
        # https://github.com/pyca/pyopenssl/issues/168#issuecomment-2143437339
        # milahu commented on Jun 1, 2024

        timeout = 5

        #host, port = "127.0.0.1", 4430

        ssl_context = OpenSSL.SSL.Context(method=OpenSSL.SSL.TLS_CLIENT_METHOD)
        ssl_context.load_verify_locations(cafile=cafile)

        conn = OpenSSL.SSL.Connection(
            ssl_context,
            socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        )
        conn.settimeout(timeout)
        conn.connect((host, port))
        conn.setblocking(1)
        conn.set_tlsext_host_name(host.encode())

        # use_signals=False is required for multithreading
        # https://github.com/pnpnpn/timeout-decorator#multithreading
        # but use_signals=False makes this fail
        # because conn.do_handshake runs in a separate process
        # so it is a different conn object

        #@timeout_decorator.timeout(timeout, timeout_exception=TimeoutError)
        @timeout_decorator.timeout(timeout, timeout_exception=TimeoutError, use_signals=False)
        def do_handshake():
            conn.do_handshake()

        #conn.do_handshake()
        do_handshake()

        cert_chain = conn.get_peer_cert_chain()
        return cert_chain

    def _version040(hostname, port, cafile):
        # https://github.com/pyca/pyopenssl/issues/168#issuecomment-463506908
        # hmahadik commented on Feb 14, 2019
        """
        I was able to work around this
        by doing a select before calling do_handshake

        setblocking(1) didn't work for me
        so I gave select a shot and it does work.
        """
        ssl_context = OpenSSL.SSL.Context(method=OpenSSL.SSL.TLS_CLIENT_METHOD)
        ssl_context.load_verify_locations(cafile=cafile)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = SSL.Connection(context=ssl_context, socket=sock)
        conn.settimeout(5)
        # FIXME this can throw ConnectionRefusedError
        conn.connect((hostname, port))
        #conn.setblocking(1)
        #time.sleep(0.01) # todo: is this needed?
        readable, writable, errored = select.select([sock], [], [], 10)
        if sock in readable:
            print("sock is readable")
        #sock.do_handshake() # 'socket' object has no attribute 'do_handshake'
        print("conn.do_handshake ...")
        # FIXME OpenSSL.SSL.WantReadError
        conn.do_handshake()
        print("conn.do_handshake ok")
        cert_chain = conn.get_peer_cert_chain()
        conn.shutdown()
        conn.close()
        return cert_chain

    def _version050(server_hostname, port, cafile):
        # https://github.com/pyca/pyopenssl/issues/168#issuecomment-638544445
        # vincentrussell commented on Jun 4, 2020
        ssl_context = OpenSSL.SSL.Context(method=OpenSSL.SSL.TLS_CLIENT_METHOD)
        ssl_context.load_verify_locations(cafile=cafile)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = OpenSSL.SSL.Connection(ssl_context, sock)
        conn.set_tlsext_host_name(server_hostname.encode('utf-8'))
        conn.set_connect_state() # ?
        print("sock timeout", sock.gettimeout()) # None
        while True:
            try:
                # FIXME OpenSSL.SSL.SysCallError: (32, 'EPIPE')
                # FIXME ssl.SSLError: ("bad handshake: SysCallError(32, 'EPIPE')",)
                conn.do_handshake()
                break
            except OpenSSL.SSL.WantReadError:
                rd, _, _ = select.select([sock], [], [], sock.gettimeout())
                if not rd:
                    raise TimeoutError('select timed out')
            except OpenSSL.SSL.Error as e:
                raise ssl.SSLError('bad handshake: %r' % e)
        cert_chain = conn.get_peer_cert_chain()
        conn.shutdown()
        conn.close()
        return cert_chain



def create_cert(
    name, issuer_cert=None, issuer_key=None, issuer_cert_url=None, is_leaf=False
):
    """
    create a cryptography certificate and key.

    note: not pyopenssl cert
    """

    print(f"creating cert {repr(name)}")

    # https://cryptography.io/en/latest/x509/tutorial/
    # https://cryptography.io/en/latest/x509/reference/#x-509-certificate-builder
    # https://stackoverflow.com/questions/56285000/python-cryptography-create-a-certificate-signed-by-an-existing-ca-and-export
    # https://gist.github.com/major/8ac9f98ae8b07f46b208

    is_root = issuer_cert is None

    key = rsa.generate_private_key(
        public_exponent=65537,
        # key_size=2048 is slow, but python requires 2048 bit RSA keys
        # https://github.com/python/cpython/raw/main/Modules/_ssl.c
        # @SECLEVEL=2: security level 2 with 112 bits minimum security (e.g. 2048 bits RSA key)
        key_size=2048,
        backend=default_backend(),
    )

    subject_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Texas"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Austin"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
    )

    issuer_name = subject_name if is_root else issuer_cert.subject

    issuer_key = key if is_root else issuer_key

    cert = x509.CertificateBuilder()

    cert = cert.subject_name(subject_name)
    cert = cert.issuer_name(issuer_name)
    cert = cert.public_key(key.public_key())
    cert = cert.serial_number(x509.random_serial_number())
    cert = cert.not_valid_before(datetime.datetime.utcnow())
    cert = cert.not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    )

    cert = cert.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False,
    )

    # https://stackoverflow.com/a/72320618/10440128
    # if is_root: # no. invalid CA certificate @ cert1

    if not is_leaf:
        cert = cert.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        cert = cert.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        cert = cert.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            ),
            critical=False,
        )

    if is_leaf:
        cert = cert.add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.ExtendedKeyUsageOID.SERVER_AUTH,
                ]
            ),
            critical=False,
        )

    if issuer_cert_url:
        # add AIA extension
        # https://github.com/pyca/cryptography/raw/main/tests/x509/test_x509.py
        # aia = x509.AuthorityInformationAccess
        cert = cert.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(issuer_cert_url),
                    ),
                ]
            ),
            critical=False,
        )

    # no. certificate signature failure
    # cert = cert.sign(key, hashes.SHA256(), default_backend())
    cert = cert.sign(issuer_key, hashes.SHA256(), default_backend())

    return cert, key


def run_http_server(args):

    host = args.get("host", "127.0.0.1")
    port = args.get("port", 80)
    ssl_cert_file = args.get("ssl_cert_file", None)
    ssl_key_file = args.get("ssl_key_file", None)
    root = args.get("root", "/tmp/www")
    # tmpdir = args.get("tmpdir", "/tmp")

    # https://stackoverflow.com/questions/22429648/ssl-in-python3-with-httpserver

    # SimpleHTTPRequestHandler serves files from workdir
    # this throws FileNotFoundError if root does not exist
    os.chdir(root)

    http_server = HTTPServer((host, port), SimpleHTTPRequestHandler)

    if ssl_cert_file and ssl_key_file:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.check_hostname = False  # If set to True, only the hostname that matches the certificate will be accepted
        # https://docs.python.org/3/library/ssl.html
        # The certfile string must be the path to a single file in PEM format containing the certificate
        # as well as any number of CA certificates needed to establish the certificate’s authenticity.
        # The keyfile string, if present, must point to a file containing the private key.
        ssl_context.load_cert_chain(ssl_cert_file, ssl_key_file)
        http_server.socket = ssl_context.wrap_socket(
            http_server.socket, server_side=True
        )

    http_server.serve_forever()


def print_cert(cert, label=None, indent=""):
    if label:
        print(indent + label + ":")
    if isinstance(cert, cryptography.x509.Certificate):
        # cryptography cert
        # https://cryptography.io/en/latest/x509/reference/
        print(indent + f"  subject: {cert.subject}")
        print(indent + f"    issuer: {cert.issuer})")
        print(indent + f"    fingerprint: {cert.fingerprint(hashes.SHA256())}")
        return
    if isinstance(cert, OpenSSL.crypto.X509):
        # pyopenssl cert
        print(indent + f"  subject: {cert.get_subject()}")
        print(indent + f"    issuer: {cert.get_issuer()})")
        print(indent + f'    fingerprint: {cert.digest("sha256")}')
        return
    raise ValueError("unknown cert type {type(cert)}")


def print_chain(cert_chain, label=None):
    if label:
        print(label + ":")
    if not cert_chain:
        print("  (empty)")
        return
    for idx, cert in enumerate(cert_chain):
        print_cert(cert, f"cert {idx}", "  ")


def run_test(tmpdir):

    print(f"using tempdir {repr(tmpdir)}")

    server_root = tmpdir + "/www"
    os.mkdir(server_root)

    # SSLContext.wrap_socket
    # Wrap an existing Python socket

    http_port = get_free_port()

    # create certs
    # TODO refactor ... create_cert_chain

    cert0, key0 = create_cert("root cert")
    cert0_path = f"{server_root}/cert0"
    with open(cert0_path, "wb") as f:
        # PEM format
        f.write(cert0.public_bytes(encoding=serialization.Encoding.PEM))
    url0 = f"http://127.0.0.1:{http_port}/cert0"

    '''
    cert1, key1 = create_cert("branch cert 1", cert0, key0, url0)
    cert1_path = f"{server_root}/cert1"
    with open(cert1_path, "wb") as f:
        # DER = ASN1 format
        f.write(cert1.public_bytes(encoding=serialization.Encoding.DER))
    url1 = f"http://127.0.0.1:{http_port}/cert1"

    # https://github.com/pyca/cryptography/raw/main/tests/hazmat/primitives/test_pkcs7.py
    # encoding = serialization.Encoding.PEM
    # encoding = serialization.Encoding.DER
    # p7 = pkcs7.serialize_certificates(certs, encoding)
    # f.write(cert2.public_bytes(encoding=serialization.Encoding.PEM))

    """
        f.write(pkcs7.serialize_certificates([cert2.to_cryptography()], Encoding.DER))
                                              ^^^^^^^^^^^^^^^^^^^^^
    AttributeError: 'cryptography.hazmat.bindings._rust.x509.Certificat' object has no attribute 'to_cryptography'

    fix: cert2 already is a cryptography cert

    nit: why "Certificat"? why not "Certificate" with a trailing "e"?
    """

    cert2, key2 = create_cert("branch cert 2", cert1, key1, url1)
    cert2_path = f"{server_root}/cert2"
    with open(cert2_path, "wb") as f:
        # PKCS7-DER format
        # f.write(pkcs7.serialize_certificates([cert2.to_cryptography()], Encoding.DER))
        f.write(pkcs7.serialize_certificates([cert2], Encoding.DER))
    url2 = f"http://127.0.0.1:{http_port}/cert2"

    cert3, key3 = create_cert("branch cert 3", cert2, key2, url2)
    cert3_path = f"{server_root}/cert3"
    with open(cert3_path, "wb") as f:
        # PKCS7-PEM format
        # f.write(pkcs7.serialize_certificates([cert3.to_cryptography()], Encoding.PEM))
        f.write(pkcs7.serialize_certificates([cert3], Encoding.PEM))
    url3 = f"http://127.0.0.1:{http_port}/cert3"

    # TODO test invalid url3 with invalid host or port

    # no. pycurl.error: (60, "SSL: certificate subject name 'leaf cert' does not match target host name '127.0.0.1'")
    # cert4, key4 = create_cert("leaf cert", cert3, key3, url3, is_leaf=True)

    cert4, key4 = create_cert("127.0.0.1", cert3, key3, url3, is_leaf=True)
    '''

    cert4, key4 = create_cert("127.0.0.1", cert0, key0, url0, is_leaf=True)
    # cert4_path = f"{server_root}/cert4"

    all_ca_certs = [
        cert0,  # root cert
        #cert1,
        #cert2,
        #cert3,
        # cert4, # leaf cert
    ]

    all_ca_certs_pem_path = f"{server_root}/all-certs.pem"
    with open(all_ca_certs_pem_path, "wb") as f:
        f.write(
            b"\n".join(
                map(
                    lambda c: c.public_bytes(encoding=serialization.Encoding.PEM),
                    all_ca_certs,
                )
            )
        )

    server_cert, server_key = cert4, key4

    https_server_cert_file = tempfile.mktemp(suffix=".pem", prefix="cert-", dir=tmpdir)
    with open(https_server_cert_file, "wb") as f:
        # cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, server_cert) # pyopenssl
        cert_pem = server_cert.public_bytes(
            encoding=serialization.Encoding.PEM
        )  # cryptography
        f.write(cert_pem)

    https_server_key_file = tempfile.mktemp(suffix=".pem", prefix="key-", dir=tmpdir)
    with open(https_server_key_file, "wb") as f:
        # key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, server_key) # pyopenssl
        # cryptography
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        key_pem = server_key.private_bytes(
            encoding=serialization.Encoding.PEM,  # PEM, DER
            format=serialization.PrivateFormat.PKCS8,  # TraditionalOpenSSL, OpenSSH, PKCS8
            encryption_algorithm=serialization.NoEncryption(),  # BestAvailableEncryption, NoEncryption
        )
        f.write(key_pem)

    # start http server
    schema = "http"
    http_server_url = f"{schema}://127.0.0.1:{http_port}"
    print(f"starting {schema} server on {http_server_url}")
    http_server_args = dict(
        host="127.0.0.1",
        port=http_port,
        ssl_cert_file=None,
        ssl_key_file=None,
        root=server_root,
        # tmpdir=tmpdir,
    )
    http_server_process = Process(target=run_http_server, args=(http_server_args,))
    http_server_process.start()
    http_server_process.stop = lambda: os.kill(http_server_process.pid, signal.SIGSTOP)
    http_server_process.cont = lambda: os.kill(http_server_process.pid, signal.SIGCONT)

    # start https server
    schema = "https"
    https_port = get_free_port()
    https_server_url = f"{schema}://127.0.0.1:{https_port}"
    print(f"starting {schema} server on {https_server_url}")
    https_server_args = dict(
        host="127.0.0.1",
        port=https_port,
        ssl_cert_file=https_server_cert_file,
        ssl_key_file=https_server_key_file,
        root=server_root,
        # tmpdir=tmpdir,
    )
    https_server_process = Process(target=run_http_server, args=(https_server_args,))
    https_server_process.start()
    https_server_process.stop = lambda: os.kill(
        https_server_process.pid, signal.SIGSTOP
    )
    https_server_process.cont = lambda: os.kill(
        https_server_process.pid, signal.SIGCONT
    )

    def handle_exit():
        process_list = [
            http_server_process,
            https_server_process,
        ]
        for process in process_list:
            try:
                process.kill()
            except Exception:
                pass

    atexit.register(handle_exit)

    #time.sleep(999999) # debug: test http servers

    print("-" * 80)

    print("conn.do_handshake tests ...")

    print("-" * 80)

    host = "127.0.0.1"
    port = https_port
    cafile = cert0_path
    server_cert_digest = OpenSSL.crypto.X509.from_cryptography(server_cert).digest("sha256")

    print("host, port =", host, port)

    test_fns_class = TestFunctions

    for attr in dir(test_fns_class):
        if attr[0] == "_":
            continue
        test_fn = getattr(test_fns_class, attr)
        #print(attr, test_fn)

        for test_variant in ["normal", "timeout"]:

            # wait for https server
            # fix ConnectionRefusedError
            time.sleep(0.05)

            test_name = f"conn.do_handshake {attr} {test_variant}"

            print("-" * 80)
            print(f"{test_name} ...")

            if test_variant == "timeout":
                https_server_process.stop()

            t1 = time.time()
            try:
                cert_chain = test_fn(host, port, cafile)
                assert cert_chain != None
                #print_chain(cert_chain, "cert_chain")
                assert cert_chain[0].digest("sha256") == server_cert_digest
                t2 = time.time()
                print("dt", t2 - t1)
                print(f"{test_name} ok")
            except Exception as exc:
                t2 = time.time()
                print("dt", t2 - t1)
                expected_exc_types = (
                    TimeoutError,
                )
                if test_variant == "timeout" and isinstance(exc, expected_exc_types):
                    print(f"{test_name} ok")
                else:
                    print(f"{test_name} fail")
                    traceback.print_exception(exc)

            if test_variant == "timeout":
                https_server_process.cont()

        #break # debug

    print("-" * 80)

    print("conn.do_handshake tests done")

    print("-" * 80)

    keep_servers = False
    #keep_servers = True

    if keep_servers:
        # keep servers running for manual testing
        print(f"keeping servers running: {https_server_url} and {http_server_url}")
        time.sleep(3600)

    print(f"cleanup")
    handle_exit()

    print("ok")


def main():

    main_tempdir = f"/run/user/{os.getuid()}"
    if not os.path.exists(main_tempdir):
        main_tempdir = None

    with (
        tempfile.TemporaryDirectory(
            prefix="ssl-handshake-timeout.",
            dir=main_tempdir,
            # ignore_cleanup_errors=False,
        ) as tmpdir,
    ):

        return run_test(tmpdir)


if __name__ == "__main__":

    main()
