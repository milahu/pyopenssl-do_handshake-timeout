#!/usr/bin/env python3

import sys
import time
import select
import socket
from urllib.parse import urlsplit

import OpenSSL # pyopenssl
import certifi

cafile = certifi.where()

def get_cert_chain(hostname, port, timeout=5):

    # https://github.com/pyca/pyopenssl/issues/168#issuecomment-61813592
    # exarkun commented on Nov 5, 2014

    ssl_context = OpenSSL.SSL.Context(method=OpenSSL.SSL.TLS_CLIENT_METHOD)
    ssl_context.load_verify_locations(cafile=cafile)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = OpenSSL.SSL.Connection(context=ssl_context, socket=sock)
    #sock.settimeout(5) # no. sock.gettimeout() still returns None
    conn.settimeout(5) # is this needed?
    conn.connect((hostname, port))
    conn.setblocking(1)

    #conn.do_handshake()

    def do_handshake():
        conn.setblocking(0) # unblock conn.do_handshake
        #timeout = sock.gettimeout() # None
        #timeout = conn.gettimeout() # None
        timeout = 5
        #print("timeout", timeout)
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
                readable, writable, errored = select.select([sock], [sock], [], remain)
                print("select", (readable, writable, errored))
                #if <select timed out>:
                #    raise <something - the original exception?  a specific timeout exception?>
                time.sleep(0.5) # reduce cpu load

    do_handshake()

    cert_chain = conn.get_peer_cert_chain()
    conn.shutdown()
    conn.close()
    return cert_chain

hostname = sys.argv[1]
port = int(sys.argv[2])
try:
    get_cert_chain = get_cert_chain(hostname, port)
except TimeoutError:
    print("timeout")
