#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : GetFortinetSerialNumber.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Jan 2022

import argparse
import os
import re
import ssl
import requests
import OpenSSL

# Disable warings of insecure connection for invalid cerificates
requests.packages.urllib3.disable_warnings()
# Allow use of deprecated and weak cipher methods
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
except AttributeError:
    pass


def detect_forti_from_sn(sn, verbose=False):
    fortinet_serial_number_patterns = {'FGT20A': 'FortiGate 20A', 'FGT20B': 'FortiGate 20B', 'FGT20C': 'FortiGate 20C', 'FGT20D': 'FortiGate 20D', 'FGT20E': 'FortiGate 20E', 'FGT20F': 'FortiGate 20F', 'FGT30A': 'FortiGate 30A', 'FGT30B': 'FortiGate 30B', 'FGT30C': 'FortiGate 30C', 'FGT30D': 'FortiGate 30D', 'FGT30E': 'FortiGate 30E', 'FGT30F': 'FortiGate 30F', 'FGT40A': 'FortiGate 40A', 'FGT40B': 'FortiGate 40B', 'FGT40C': 'FortiGate 40C', 'FGT40D': 'FortiGate 40D', 'FGT40E': 'FortiGate 40E', 'FGT40F': 'FortiGate 40F', 'FGT50A': 'FortiGate 50A', 'FGT50B': 'FortiGate 50B', 'FGT50C': 'FortiGate 50C', 'FGT50D': 'FortiGate 50D', 'FGT50E': 'FortiGate 50E', 'FGT50F': 'FortiGate 50F', 'FGT60A': 'FortiGate 60A', 'FGT60B': 'FortiGate 60B', 'FGT60C': 'FortiGate 60C', 'FGT60D': 'FortiGate 60D', 'FGT60E': 'FortiGate 60E', 'FGT60F': 'FortiGate 60F', 'FGT61A': 'FortiGate 61A', 'FGT61B': 'FortiGate 61B', 'FGT61C': 'FortiGate 61C', 'FGT61D': 'FortiGate 61D', 'FGT61E': 'FortiGate 61E', 'FGT61F': 'FortiGate 61F', 'FGT70A': 'FortiGate 70A', 'FGT70B': 'FortiGate 70B', 'FGT70C': 'FortiGate 70C', 'FGT70D': 'FortiGate 70D', 'FGT70E': 'FortiGate 70E', 'FGT70F': 'FortiGate 70F', 'FGT80A': 'FortiGate 80A', 'FGT80B': 'FortiGate 80B', 'FGT80C': 'FortiGate 80C', 'FGT80D': 'FortiGate 80D', 'FGT80E': 'FortiGate 80E', 'FGT80F': 'FortiGate 80F', 'FGT81A': 'FortiGate 81A', 'FGT81B': 'FortiGate 81B', 'FGT81C': 'FortiGate 81C', 'FGT81D': 'FortiGate 81D', 'FGT81E': 'FortiGate 81E', 'FGT81F': 'FortiGate 81F', 'FGT90A': 'FortiGate 90A', 'FGT90B': 'FortiGate 90B', 'FGT90C': 'FortiGate 90C', 'FGT90D': 'FortiGate 90D', 'FGT90E': 'FortiGate 90E', 'FGT90F': 'FortiGate 90F', 'FG100A': 'FortiGate 100A', 'FG100B': 'FortiGate 100B', 'FG100C': 'FortiGate 100C', 'FG100D': 'FortiGate 100D', 'FG100E': 'FortiGate 100E', 'FG100F': 'FortiGate 100F', 'FG101A': 'FortiGate 101A', 'FG101B': 'FortiGate 101B', 'FG101C': 'FortiGate 101C', 'FG101D': 'FortiGate 101D', 'FG101E': 'FortiGate 101E', 'FG101F': 'FortiGate 101F', 'FG140A': 'FortiGate 140A', 'FG140B': 'FortiGate 140B', 'FG140C': 'FortiGate 140C', 'FG140D': 'FortiGate 140D', 'FG140E': 'FortiGate 140E', 'FG140F': 'FortiGate 140F', 'FG200A': 'FortiGate 200A', 'FG200B': 'FortiGate 200B', 'FG200C': 'FortiGate 200C', 'FG200D': 'FortiGate 200D', 'FG200E': 'FortiGate 200E', 'FG200F': 'FortiGate 200F', 'FG201A': 'FortiGate 201A', 'FG201B': 'FortiGate 201B', 'FG201C': 'FortiGate 201C', 'FG201D': 'FortiGate 201D', 'FG201E': 'FortiGate 201E', 'FG201F': 'FortiGate 201F', 'FG240A': 'FortiGate 240A', 'FG240B': 'FortiGate 240B', 'FG240C': 'FortiGate 240C', 'FG240D': 'FortiGate 240D', 'FG240E': 'FortiGate 240E', 'FG240F': 'FortiGate 240F', 'FG280A': 'FortiGate 280A', 'FG280B': 'FortiGate 280B', 'FG280C': 'FortiGate 280C', 'FG280D': 'FortiGate 280D', 'FG280E': 'FortiGate 280E', 'FG280F': 'FortiGate 280F', 'FG300A': 'FortiGate 300A', 'FG300B': 'FortiGate 300B', 'FG300C': 'FortiGate 300C', 'FGT3HD': 'FortiGate 300D', 'FGT3HE': 'FortiGate 300E', 'FGT3HF': 'FortiGate 300F', 'FG310A': 'FortiGate 310A', 'FG310B': 'FortiGate 310B', 'FG310C': 'FortiGate 310C', 'FG310D': 'FortiGate 310D', 'FG310E': 'FortiGate 310E', 'FG310F': 'FortiGate 310F', 'FG400A': 'FortiGate 400A', 'FG400B': 'FortiGate 400B', 'FG400C': 'FortiGate 400C', 'FG400D': 'FortiGate 400D', 'FG400E': 'FortiGate 400E', 'FG400F': 'FortiGate 400F', 'FG500A': 'FortiGate 500A', 'FG500B': 'FortiGate 500B', 'FG500C': 'FortiGate 500C', 'FG500D': 'FortiGate 500D', 'FG500E': 'FortiGate 500E', 'FG500F': 'FortiGate 500F', 'FG600A': 'FortiGate 600A', 'FG600B': 'FortiGate 600B', 'FG600C': 'FortiGate 600C', 'FG600D': 'FortiGate 600D', 'FG600E': 'FortiGate 600E', 'FG600F': 'FortiGate 600F', 'FG900A': 'FortiGate 900A', 'FG900B': 'FortiGate 900B', 'FG900C': 'FortiGate 900C', 'FG900D': 'FortiGate 900D', 'FG900E': 'FortiGate 900E', 'FG900F': 'FortiGate 900F', 'FGVM00': 'FortiGate VM ', 'FGVM02': 'FortiGate VM ', 'FGVM2V': 'FortiGate VM ', 'FWF60A': 'FortiWifi 60A', 'FWF60B': 'FortiWifi 60B', 'FWF60C': 'FortiWifi 60C', 'FWF60D': 'FortiWifi 60D', 'FWF60E': 'FortiWifi 60E', 'FWF60F': 'FortiWifi 60F', 'FWF61A': 'FortiWifi 61A', 'FWF61B': 'FortiWifi 61B', 'FWF61C': 'FortiWifi 61C', 'FWF61D': 'FortiWifi 61D', 'FWF61E': 'FortiWifi 61E', 'FWF61F': 'FortiWifi 61F', 'FWF80F': 'FortiWifi 80F', 'FWF81F': 'FortiWifi 81F', 'FWF90D': 'FortiWifi 90D'}


    sn = sn.upper().strip()
    if len(sn) == 16:
        ftype, number = sn[:6], sn[6:]
        if ftype in fortinet_serial_number_patterns:
            _r = {"fullname": fortinet_serial_number_patterns[ftype], "number": number, "model": ftype, "sn": sn}
            print("  |   Detected \x1b[92m%s\x1b[0m (%s-%s)" % (_r["fullname"], _r["model"], _r["number"]))
            print("  |   If you have a console access, here is the default password:")
            print("  |   | \x1b[93mUsername\x1b[0m: \x1b[96mmaintainer\x1b[0m")
            print("  |   | \x1b[93mPassword\x1b[0m: \x1b[96mbcpb%s%s\x1b[0m" % (_r["model"], _r["number"]))
            return _r
        else:
            if verbose:
                print("[!] Unknown model %s (%s)" % (ftype, sn))
            return None
    else:
        if verbose:
            print("[!] Invalid SN length: %d (%s)" % (len(sn), sn))
        return None


def parseArgs():
    parser = argparse.ArgumentParser(description="A Python script to extract the serial number of a remote Fortinet device. ")
    parser.add_argument("-H", "--host", default=None, required=True, help='Fortinet target')
    parser.add_argument("-P", "--port", default=443, type=int, required=False, help='Fortinet target')
    parser.add_argument("-o", "--output-cert", default=None, required=False, help='Ouput PEM certificate.')
    parser.add_argument("-v", "--verbose", default=False, required=False, action='store_true', help='Ouput PEM certificate.')
    return parser.parse_args()


if __name__ == '__main__':
    options = parseArgs()

    if options.verbose:
        print("[+] Retrieving the server certificate in PEM format ...")
    # Connecting to remote server
    cert = None
    try:
        if options.verbose:
            print("[>] Trying to connect to %s:%d using TLS ..." % (options.host, options.port))
        cert = ssl.get_server_certificate((options.host, options.port), ssl_version=ssl.PROTOCOL_TLS)
        if options.verbose:
            print(cert)
    except ssl.SSLError as e:
        if options.verbose:
            print("[!] %s" % e)
            print("[>] Trying to connect to %s:%d using SSL v2/v3  ..." % (options.host, options.port))
        try:
            cert = ssl.get_server_certificate((options.host, options.port), ssl_version=ssl.PROTOCOL_SSLv23)
            if options.verbose:
                print(cert)
        except ssl.SSLError as e:
            if options.verbose:
                print("[!] %s" % e)

    # Parsing certificate
    if cert is not None:
        if options.output_cert is not None:
            if not os.path.exists(os.path.dirname(options.output_cert)) and len(os.path.dirname(options.output_cert)) != 0:
                os.makedirs(os.path.dirname(options.output_cert), exist_ok=True)
            f = open(options.output_cert, "w")
            f.write(cert)
            f.close()
            if options.verbose:
                print("[+] Certificate saved to %s!" % options.output_cert)

        print("[+] Getting certificate information ...")
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

        _altnames = []
        ext_count = x509.get_extension_count()
        for i in range(0, ext_count):
            ext = x509.get_extension(i)
            if 'subjectAltName'.lower() in str(ext.get_short_name()).lower():
                _altnames = [e.strip().lstrip('DNS:') for e in ext.__str__().split(',')]
        if len(_altnames) != 0:
            print("  | \x1b[93mAlternative names\x1b[0m:")
            for altname in _altnames:
                print("  |   | \x1b[96m%s\x1b[0m" % altname)

        serial_numbers_found = []

        # Parsing Issuer
        full_issuer = '/'.join(['%s=%s' % (e[0].decode('utf-8'), e[1].decode('utf-8')) for e in x509.get_issuer().get_components()])
        if options.verbose:
            print("[+] Issuer: %s" % full_issuer)
        for property, value in x509.get_issuer().get_components():
            if property.lower() == b'cn':
                _matched = re.match('([A-Z0-9](-)?){16}', value.decode('utf-8').upper().strip())
                if _matched is not None:
                    sn = _matched.group()
                    print("  | \x1b[93mSerial number\x1b[0m: \x1b[96m%s\x1b[0m" % sn)
                    serial_numbers_found.append(sn)
                    detect_forti_from_sn(sn)

        # Parsing Subject
        full_subject = '/'.join(['%s=%s' % (e[0].decode('utf-8'), e[1].decode('utf-8')) for e in x509.get_subject().get_components()])
        if options.verbose:
            print("[+] Subject: %s" % full_subject)
        for property, value in x509.get_subject().get_components():
            if property.lower() == b'cn':
                _matched = re.match('([A-Z0-9](-)?){16}', value.decode('utf-8').upper().strip())
                if _matched is not None:
                    sn = _matched.group()
                    print("  | \x1b[93mSerial number\x1b[0m: \x1b[96m%s\x1b[0m" % sn)
                    serial_numbers_found.append(sn)
                    detect_forti_from_sn(sn)
        if len(serial_numbers_found) == 0:
            print("[!] No serial number found in %s:%d certificate information." % (options.host, options.port))
        else:
            print("[+] %d serial number(s) found in %s:%d certificate information." % (len(serial_numbers_found), options.host, options.port))
    else:
        print("[!] Could not retrieve certificate.")
