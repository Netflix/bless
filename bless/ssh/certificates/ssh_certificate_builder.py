"""
.. module: bless.ssh.certificates.ssh_certificate_builder
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import base64

import os
from bless.ssh.protocol.ssh_protocol import pack_ssh_string, pack_ssh_uint64, pack_ssh_uint32


class SSHCertificateType(object):
    USER = 1
    HOST = 2


class SSHCertifiedKeyType(object):
    RSA = 'ssh-rsa-cert-v01@openssh.com'
    ED25519 = 'ssh-ed25519-cert-v01@openssh.com'
    # todo support more key types:
    # 'ecdsa-sha2-nistp256-cert-v01@openssh.com'
    # 'ecdsa-sha2-nistp384-cert-v01@openssh.com'
    # 'ecdsa-sha2-nistp521-cert-v01@openssh.com'


class SSHCertificateBuilder(object):
    def __init__(self, ca, cert_type):
        """
        An abstract base class used to produce an SSH Certificate for various public key types.
        :param ca: The SSHCertificateAuthority that will sign the certificate.  The
        SSHCertificateAuthority type does not need to be the same type as the
        SSHCertificateBuilder.
        :param cert_type: The SSHCertificateType.  Is this a User or Host certificate?  Some of
        the SSH Certificate fields do not apply or have a slightly different meaning depending on
        the certificate type.
        See http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
        """
        self.ca = ca  # required
        self.nonce = None  # optional, has default = os.urandom(32)
        self.public_key_comment = None
        self.serial = None  # can be set, has default = 0
        self.cert_type = None  # required: User = 1, Host = 2
        self.key_id = None  # optional, default = ''
        self.valid_principals = list()  # optional, default = ''
        self.valid_after = None  # optional, default = 0
        self.valid_before = None  # optional, default = 2^64-1
        self.critical_option_force_command = None  # optional, default = ''
        self.critical_option_source_address = None  # optional, default = ''
        self.extensions = None  # optional, default = ''
        self.reserved = ''  # should always be this value
        self.signature = None
        self.signed_cert = None
        self.public_key_comment = None
        self.cert_type = cert_type

    # todo real abstract classes
    def _serialize_ssh_public_key(self):
        """
        Serialize the Public Key per the spec:
        http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
        :return: The bytes that belong in the SSH Certificate between the nonce and the
        certificate serial number.
        """
        raise NotImplementedError("Child classes should override this")

    def set_nonce(self, nonce=None):
        """
        Sets the nonce to be included as a part of the certificate body.
        :param nonce:  If no nonce is specified, this will fetch 32 Bytes from os.urandom.
        """
        if nonce is None:
            nonce = os.urandom(32)
        self.nonce = nonce

    def set_serial(self, serial=0):
        """
        Sets an optional serial number of the SSH Certificate.
        :param serial:  A uint64 serial number.
        """
        self.serial = serial

    def set_key_id(self, key_id=''):
        """
        Sets the key id of a certificate, which is just a string that ends up getting singed by
        the CA.  This key id is super useful because it gets logged by sshd when the certificate
        is used to successfully authenticate users.  Depending on your environment, the logging of
        this string will eventually be truncated at ~325 characters.
        :param key_id: String to include in the certificate, to be logged when the certificate
        is used.
        """
        self.key_id = key_id

    def add_valid_principal(self, valid_principal):
        """
        Individually add one valid principal to the certificate.  You can add many principals to an
        SSH Certificate.

        For User SSH Certificates, a valid principal defines which remote user account(s) the
        certificate is valid for.

        For Host SSH Certificates, a valid principal defines which hostname(s) the certificate is
        valid for.

        You want to set at least one valid principal.  Not doing means the certificate is valid
        for any user/hostname.
        See http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
        :param valid_principal: String with the username or hostname.
        """
        if valid_principal:
            if valid_principal not in self.valid_principals:
                self.valid_principals.append(valid_principal)
            else:
                raise ValueError("Principal {} already added.".format(valid_principal))
        else:
            raise ValueError("Provide a non-null string")

    def set_valid_after(self, after=0):
        """
        Sets the SSH Certificate validity start time.  Not setting a value will result in an SSH
        Certificate that is valid since time 0.
        :param after: Integer of the desired Unix epoch time.
        """
        self.valid_after = after

    def set_valid_before(self, before=18446744073709551615):
        """
        Sets the SSH Certificate validity end time.  Not setting a value will result in an SSH
        Certificate that never expires.  Probably not what you want to do.
        :param before: Integer of the desired Unix epoch time
        """
        self.valid_before = before

    def set_critical_option_force_command(self, command):
        """
        Sets a command that will be executed whenever this SSH Certificate is used for
        authentication.  This will replace any command specified by the SSH command.
        :param command: String of the program (and arguments) to run on the remote host.
        """
        if command:
            self.critical_option_force_command = command
        else:
            raise ValueError("Provide a non-null string")

    def set_critical_option_source_addresses(self, address):
        """
        Sets which IP address(es) this certificate can be used from for authentication.  Addresses
        should be comma-separated and can be individual IPs or CIDR format (nn.nn.nn.nn/nn or
        hhhh::hhhh/nn).

        Not setting this means the SSH Certificate is valid from any IP.  Probably not what you
        want to do.
        :param address: String of one or more comma-separated IPs or CIDRs.
        """
        if address:
            self.critical_option_source_address = address
        else:
            raise ValueError("Provide a non-null string")

    def clear_extensions(self):
        """
        Removes any previously set SSH Certificate Extensions.
        """
        self.extensions = set()

    def set_extensions_to_default(self):
        """
        Sets the SSH Certificate Extensions set to the same defaults ssh-keygen would provide.

        SSH Certificate Extensions enable certain SSH features.  If they are not present,
        sessions authenticated with the certificate cannot use them.

        See http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
        """
        if self.cert_type is SSHCertificateType.USER:
            self.extensions = {'permit-X11-forwarding',
                               'permit-agent-forwarding',
                               'permit-port-forwarding',
                               'permit-pty', 'permit-user-rc'}
        else:
            # SSHCertificateType.HOST has no applicable extensions.
            self.clear_extensions()

    def add_extension(self, extension):
        """
        Add an individual SSH Certificate Extension to the certificate.

        SSH Certificate Extensions enable certain SSH features.  If they are not present,
        sessions authenticated with the certificate cannot use them.

        See http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
        :param extension: the extension to include
        """
        if self.extensions is None:
            self.extensions = set()

        self.extensions.add(extension)

    def get_cert_file(self, bypass_time_validity_check=False):
        """
        Generate the SSH Certificate that can be written to id_rsa-cert.pub or similar file.

        This will initialize any unset SSH Certificate attributes to sane defaults, verify the
        validity range, and sign the certificate.
        :return: String with all of the required SSH Certificate contents, that can be written
        to a file.
        """
        file_contents = (
            "{} {} {}"
        ).format(self.cert_key_type,
                 str(base64.b64encode(self._sign_cert(bypass_time_validity_check)), encoding='ascii'),
                 self.public_key_comment)
        return file_contents

    def _initialize_unset_attributes(self):
        if self.nonce is None:
            self.set_nonce()

        if self.serial is None:
            self.set_serial()

        if self.valid_after is None:
            self.set_valid_after()

        if self.valid_before is None:
            self.set_valid_before()

        if self.key_id is None:
            self.set_key_id()

        if self.extensions is None:
            self.set_extensions_to_default()

        if not self.public_key_comment:
            self.public_key_comment = \
                'Certificate type[{}] principals[{}] with the id[{}]'.format(
                    self.cert_type, ','.join(self.valid_principals), self.key_id)

    def _validate_cert_properties(self):
        if self.valid_after >= self.valid_before:
            raise ValueError("Impossible validity period")

    def _sign_cert(self, bypass_time_validity_check=False):
        if self.signed_cert is None:
            # build cert body
            self._initialize_unset_attributes()
            if not bypass_time_validity_check:
                self._validate_cert_properties()
            body_bytes = self._serialize_certificate_body()

            # sign the body
            sig_bytes = self.ca.sign(body_bytes)
            self.signed_cert = body_bytes + sig_bytes
        return self.signed_cert

    def _serialize_certificate_body(self):
        body = pack_ssh_string(self.cert_key_type)
        body += pack_ssh_string(self.nonce)
        body += self._serialize_ssh_public_key()
        body += pack_ssh_uint64(self.serial)
        body += pack_ssh_uint32(self.cert_type)
        body += pack_ssh_string(self.key_id)
        body += pack_ssh_string(self._serialize_valid_principals())
        body += pack_ssh_uint64(self.valid_after)
        body += pack_ssh_uint64(self.valid_before)
        body += pack_ssh_string(self._serialize_critical_options())
        body += pack_ssh_string(self._serialize_extensions())
        body += pack_ssh_string('')
        body += pack_ssh_string(self.ca.get_signature_key())
        return body

    def _serialize_extensions(self):
        # Options must be lexically ordered by "name" if they appear in the
        # sequence. Each named option may only appear once in a certificate.
        extensions_list = sorted(self.extensions)

        serialized = b''
        # Format is a series of {extension name}{empty string}
        for extension in extensions_list:
            serialized += pack_ssh_string(extension)
            serialized += pack_ssh_string('')

        return serialized

    def _serialize_valid_principals(self):
        serialized = b''

        for principal in self.valid_principals:
            serialized += pack_ssh_string(principal)

        return serialized

    def _serialize_critical_options(self):
        # Options must be lexically ordered by "name" if they appear in the
        # sequence. Each named option may only appear once in a certificate.
        serialized = b''

        if self.critical_option_force_command is not None:
            serialized += pack_ssh_string('force-command')
            serialized += pack_ssh_string(
                pack_ssh_string(self.critical_option_force_command))

        if self.critical_option_source_address is not None:
            serialized += pack_ssh_string('source-address')
            serialized += pack_ssh_string(
                pack_ssh_string(self.critical_option_source_address))

        return serialized
