#local lib
import config

#standard libs
from six import raise_from
import socket
import traceback
import sys
import struct
import ssl
import logging

#pypi libs
import OpenSSL.crypto as crypto
from OpenSSL import SSL

class Error(Exception): pass
class eStreamerKeyError(Error): pass
class eStreamerCertError(Error): pass
class eStreamerVerifyError(Error): pass

class PKCS12Manager():

    def __init__(self, p12file, passphrase):
	# open it, using password. Supply/read your own from stdin.
	self.p12 = crypto.load_pkcs12(open(p12file, 'rb').read(), passphrase)

    def getKey(self):
        return self.p12.get_privatekey() 

    def getCert(self):
        return self.p12.get_certificate()  

'''
    :host = eStreamer host
    :port = eStreamer port (default: 8302)
    :cert_path = cert file (string/path to, not file handle)
    :pkey_path = private key file (string / path to, not file handle)
    :pkey_passphase = passphrase for private key file
    :verify - PEM file to verify host
'''
class eStreamerConnection(object):


    def __init__(self, host, port, p12path, pkey_passphrase=''):
        self.host = host
        self.port = port

	self.pkcs12 = PKCS12Manager(p12path,pkey_passphrase);

        self.ctx = None
        self.sock = None
        self._bytes = None

	privateKey = self.pkcs12.getKey();

	cryptoType = crypto.FILETYPE_PEM
	certificate = self.pkcs12.getCert();

	self.privateKeyFilepath = host+"_"+str(port)+".key"
	self.certificateFilepath = host+"_"+str(port)+".cert"

        with open( self.privateKeyFilepath, 'wb+' ) as privateKeyFile:
            privateKeyFile.write( crypto.dump_privatekey( cryptoType, privateKey ) )

        with open( self.certificateFilepath, 'wb+' ) as certificateFile:
            certificateFile.write( crypto.dump_certificate( cryptoType, certificate ) )

	self.logger = logging.getLogger( self.__class__.__name__ )
    def __enter__(self):

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Default TLS
        tlsVersion = ssl.PROTOCOL_TLSv1

        if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
             tlsVersion = ssl.PROTOCOL_TLSv1_2
             self.logger.info('Using TLS v1.2')

        else:
             self.logger.warning('PROTOCOL_TLSv1_2 not found. Using TLS v1.0')


	print str(tlsVersion)

        self.sock = ssl.wrap_socket(
            sock,
            keyfile = self.privateKeyFilepath,
            certfile = self.certificateFilepath,
            do_handshake_on_connect = True,
            ssl_version = tlsVersion)

        try:
            #self.sock.settimeout( 10 )
            self.sock.connect( ( self.host, self.port ) )

        except socket.timeout:
            raise Error("Timeout")
                 

        except socket.gaierror as gex:
            # Convert to a nicer exception
            raise Error( 'socket.gaierror ({0})'.format(gex) )

        except ssl.SSLError as sslex:
            # Convert to a nicer exception
	    raise Error(str(sslex))

        # We're setting the socket to be blocking but with a short timeout
        #self.sock.settimeout( 10 )
	return self


    def __exit__(self, exc_type, exc_al, exc_tb):
        self.close()

    def validate_cert(self, conn, cert, errnum, depth, ok):
        ''' This does not properly check the cert so it will fail '''
        # just handle the self-signed use case
        if not ok and (errnum == 19 or errnum == 18):
            if cert.get_pubkey() == self.trusted_cert.get_pubkey() and cert.get_issuer() == self.trusted_cert.get_issuer():
                if not cert.has_expired():
                    return 1
        return ok

    def close(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    @property
    def bytes(self):
        return self._bytes

    @bytes.setter
    def bytes(self, buf):
        self._bytes = value

    def request(self, buf):
        try:
            self.sock.send(buf)
        except SSL.Error as exc:
            raise_from(Error("SSL Error"), exc)
        else:
            try:
                #peek_bytes = self.sock.recv(8, socket.MSG_PEEK) # peeky no worky?!
                peek_bytes = self.sock.recv(8)
            except SSL.WantReadError as exc:
                # SSL timeout does not work properly. If no data is available from server,
                # we'll get this error
                pass
            except SSL.Error as exc:
                raise
                #raise_from(Error("SSL Error"), exc)
            else:
                (ver, type_, length) = struct.unpack('>HHL', peek_bytes)
                return bytearray(peek_bytes + self.sock.recv(length))

    def response(self):
        try:
            peek_bytes = self.sock.recv(8, socket.MSG_PEEK)
        except SSL.Error as exc:
            raise_from(Error("SSL Error"), exc)
        else:
            (ver, type_, length) = struct.unpack('>HHL', peek_bytes)
            return bytearray(peek_bytes + self.sock.recv(length))
