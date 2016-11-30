import secure_smtpd
import smtpd
import base64
import secure_smtpd
import asynchat
import logging
import ssl

from asyncore import ExitNow
from smtpd import NEWLINE, EMPTYSTRING


def decode_b64(data):
    '''Wrapper for b64decode, without having to struggle with bytestrings.'''
    byte_string = data.encode('utf-8')
    decoded = base64.b64decode(byte_string)
    return decoded.decode('utf-8')


def encode_b64(data):
    '''Wrapper for b64encode, without having to struggle with bytestrings.'''
    byte_string = data.encode('utf-8')
    encoded = base64.b64encode(byte_string)
    return encoded.decode('utf-8')


class SMTPChannel(smtpd.SMTPChannel):

    def __init__(self, smtp_server, newsocket, fromaddr, require_authentication=False, credential_validator=None, map=None):
        smtpd.SMTPChannel.__init__(self, smtp_server, newsocket, fromaddr)
        asynchat.async_chat.__init__(self, newsocket, map=map)

        self.socket = newsocket

        self.require_authentication = require_authentication
        self.authenticating = False
        self.authenticated = False
        self.auth_type = None
        self.username = None
        self.password = None
        self.credential_validator = credential_validator
        self.logger = logging.getLogger(secure_smtpd.LOG_NAME)

        self.logger.info("S: init smtp channel")

    def smtp_QUIT(self, arg):
        self.push('221 Bye')
        self.close_when_done()
        raise ExitNow()

    def smtp_EHLO(self, arg):
        if not arg:
            self.logger.warning('S: 501 Syntax: EHLO hostname')
            self.push('501 Syntax: EHLO hostname')
            return

        if self.__greeting:
            self.logger.warning('S: 503 Duplicate: HELO/EHLO')
            self.push('503 Duplicate HELO/EHLO')
        else:
            self.__greeting = arg
            self.logger.warning('s: 250 %s AUTH PLAIN' % self.__fqdn)
            self.push('250-%s' % self.__fqdn)
            self.push('250-SIZE 1000000')
            self.push('250-AUTH PLAIN')

            if self.__server.starttls:
                self.logger.info('s: 250 STARTTLS')
                self.push('250 STARTTLS')
            
    def smtp_STARTTLS(self, arg):
        self.logger.info('s: init tls')
        if arg:
            self.logger.warning('s: 501 syntax error (no parameters allowed)')
            self.push('501 Syntax error (no parameters allowed)')
        elif self.__server.starttls and not isinstance(self.__conn, ssl.SSLSocket):
            self.logger.info('s: 220 ready to start tls')
            self.push('220 Ready to start TLS')
            self.__conn.settimeout(30)
            self.__conn = ssl.wrap_socket(
                self.__conn,
                server_side=True,
                certfile=self.__server.certfile,
                keyfile=self.__server.keyfile,
                ssl_version=self.__server.ssl_version
                )
            self.__conn.settimeout(None)
            # re-init channel
            asynchat.async_chat.__init__(self, self.__conn)
            self.__line = []
            self.__state = self.COMMAND
            self.__greeting = 0
            self.__mailfrom = None
            self.__rcpttos = []
            self.__data = ''
            self.logger.info('s: Peer: %s - negotiated TLS: %s' % (repr(self.__addr), repr(self.__conn.cipher())))
        else:
            self.logger.info('s: 454 tls not available due to temporary reason')
            self.push('454 TLS not available due to temporary reason')

    def collect_incoming_data(self, data):
        self.logger.info('d: ' + data)
        if not isinstance(data, str):
            # We're on python3, so we have to decode the bytestring
            data = data.decode('utf-8')
        self.__line.append(data)

    def smtp_AUTH(self, arg):
        if 'PLAIN' in arg or self.auth_type=='PLAIN':
            if arg == 'PLAIN':
                self.authenticating = True
                self.auth_type = 'PLAIN'
                self.logger.info('s: 334 ')
                self.push('334 ')
            else:
                split_args = arg.split(' ')
                if len(split_args) == 2:
                    auth_arg = split_args[1]
                else:
                    auth_arg = arg
                self.authenticating = False
                # second arg is Base64-encoded string of blah\0username\0password
                authbits = decode_b64(auth_arg).split('\0')
                self.username = authbits[1]
                self.password = authbits[2]
                self.logger.info('username: ' + self.username)
                self.logger.info('pass: ' + self.password)
                if self.credential_validator and self.credential_validator.validate(self.username, self.password):
                    self.authenticated = True
                    self.logger.info('s: 235 Authentication successful.')
                    self.push('235 Authentication successful.')
                else:
                    self.logger.info('s: 454 Temporary authentication failure.')
                    self.push('454 Temporary authentication failure.')
                    raise ExitNow()             
        elif 'LOGIN' in arg or self.auth_type=='LOGIN':
            self.authenticating = True
            split_args = arg.split(' ')

            # Some implmentations of 'LOGIN' seem to provide the username
            # along with the 'LOGIN' stanza, hence both situations are
            # handled.
            if len(split_args) == 2:
                self.username = decode_b64(arg.split(' ')[1])
                self.push('334 ' + encode_b64('Username'))
            else:
                self.logger.info('s: 334 ' + encode_b64('Username'))
                self.push('334 ' + encode_b64('Username'))
        elif not self.username:
            self.username = decode_b64(arg)
            self.push('334 ' + encode_b64('Password'))
            self.push('334 ' + encode_b64('Password'))
        else:
            self.authenticating = False
            self.password = decode_b64(arg)
            if self.credential_validator and self.credential_validator.validate(self.username, self.password):
                self.authenticated = True
                self.push('235 Authentication successful.')
            else:
                self.push('454 Temporary authentication failure.')
                raise ExitNow()

    # This code is taken directly from the underlying smtpd.SMTPChannel
    # support for AUTH is added.
    def found_terminator(self):
        line = EMPTYSTRING.join(self.__line)

        self.logger.info('c: ' + line)

        if self.debug:
            self.logger.info('s: found_terminator(): data: %s' % repr(line))

        self.__line = []
        if self.__state == self.COMMAND:
            if not line:
                self.push('500 Error: bad syntax')
                return
            method = None
            i = line.find(' ')

            if self.authenticating:
                # If we are in an authenticating state, call the
                # method smtp_AUTH.
                arg = line.strip()
                command = 'AUTH'
            elif i < 0:
                command = line.upper()
                arg = None
            else:
                command = line[:i].upper()
                arg = line[i + 1:].strip()

            # self.logger.info(command)

            # White list of operations that are allowed prior to AUTH.
            if not command in ['AUTH', 'EHLO', 'HELO', 'NOOP', 'RSET', 'QUIT', 'STARTTLS']:
                if self.require_authentication and not self.authenticated:
                    self.logger.warning('530 Authentication required')
                    self.push('530 Authentication required')
                    return

            method = getattr(self, 'smtp_' + command, None)
            if not method:
                self.logger.warning('502 Error: command "%s" not implemented' % command)
                self.push('502 Error: command "%s" not implemented' % command)
                return
            method(arg)
            return
        else:
            if self.__state != self.DATA:
                self.logger.warning('451 Internal confusion')
                self.push('451 Internal confusion')
                return
            # Remove extraneous carriage returns and de-transparency according
            # to RFC 821, Section 4.5.2.
            data = []
            for text in line.split('\r\n'):
                if text and text[0] == '.':
                    data.append(text[1:])
                else:
                    data.append(text)
            self.__data = NEWLINE.join(data)
            status = self.__server.process_message(
                self.__peer,
                self.__mailfrom,
                self.__rcpttos,
                self.__data
            )
            self.__rcpttos = []
            self.__mailfrom = None
            self.__state = self.COMMAND
            self.set_terminator(b'\r\n')
            if not status:
                self.logger.info('250 Ok')
                self.push('250 Ok')
            else:
                self.logger.info(status)
                self.push(status)
