import re

from spacy.tokens import Token

from publicsuffix2 import PublicSuffixList
psl = PublicSuffixList()

from .expressions import (
    ipv4_expr,
    ipv6_expr,
    url_expr,
    detection_expr,
    cve_expr,
    md5_expr,
    sha1_expr,
    sha256_expr,
    sha512_expr,
)

ipv4_re = re.compile(ipv4_expr, re.VERBOSE | re.I | re.UNICODE)
ipv6_re = re.compile(ipv6_expr, re.VERBOSE | re.I | re.UNICODE)
url_re = re.compile(url_expr, re.VERBOSE | re.I | re.UNICODE)
detection_re = re.compile(detection_expr, re.VERBOSE | re.UNICODE)
cve_re = re.compile(cve_expr, re.VERBOSE | re.I | re.UNICODE)

md5_re = re.compile(md5_expr, re.VERBOSE | re.I | re.UNICODE)
sha1_re = re.compile(sha1_expr, re.VERBOSE | re.I | re.UNICODE)
sha256_re = re.compile(sha256_expr, re.VERBOSE | re.I | re.UNICODE)
sha512_re = re.compile(sha512_expr, re.VERBOSE | re.I | re.UNICODE)


def is_ipv4(token):
    return bool(ipv4_re.match(token.text))

def is_ipv6(token):
    return bool(ipv6_re.match(token.text))

def is_url(token):
    return bool(url_re.match(token.text))

def is_url_without_protocol(token):
    # There should be at least one / in URL, either in :// or in the URL itself.
    if token.text.find('/') == -1:
        return False
    # Calculate how much information is left when IPv4 and IPv6 are taken away
    l = len(token)
    ipv4 = ipv4_re.match(token.text)
    if ipv4:
        l = l - len(ipv4[0])
    ipv6 = ipv6_re.match(token.text)
    if ipv6:
        l = l - len(ipv6[0])
    if l < 3:                       # a heuristic threshold
        return False
    return bool(url_re.match(token.text))

def is_detection(token):
    commonDetectionNames = [
        'ADW', 'ADWIND', 'Adware',
        'ALS',
        'ANDROIDOS',
        'AUTOIT',
        'AUTORUN',
        'BAT',
        'BKDR', 'Backdoor',
        'CRCK',
        'COINMINER', 'CoinMiner', 'Coinminer',
        'Cryp',
        'EXPL',
        'FLSourcing',          # Which vendor is this?
        'Fileless',
        'GEN',
        'HEUR',
        'HKTL',
        'HKTL64',
        'HO64',
        'HTML',
        'HA', 'HB', 'HI', 'HM', 'HS', 'HT', 'HZ',
        'HackTool',
        'HackingTools',
        'INF',
        'JS',
        'KYLG',
        'LNK',
        'Linux',
        'MSIL',
        'MAL', 'Mal', 'Malware',
        'OBFUS',
        'OSX',
        'PAK',
        'PE',
        'PHP',
        'PUA',
        'PUP',
        'Ransom',
        'SMA',
        'SWF',
        'TROJ', 'TROJ64', 'TSPY', 'Trojan',
        'VBS',
        'Virus',
        'W2KM', 'X2KM',
        'W32', 'W64',
        'W97M', 'X97M',
        'WCRY',
        'WEBSHELL',
        'WORM', 'Worm',
        'Win32', 'Win64',
    ]
    detectionNameInfixes = [
        'KEYLOG',
        'RANSOM',
    ]
    if not detection_re.match(token.text):
        return False
    toks = re.split(r'[_./:]', token.text)
    for tok in toks:
        if tok in commonDetectionNames:
            return True
        for e in detectionNameInfixes:
            if tok.find(e) != -1:
                return True
    return False

def is_cve(token):
    return bool(cve_re.match(token.text))

def is_md5(token):
    return bool(md5_re.match(token.text))

def is_sha1(token):
    return bool(sha1_re.match(token.text))

def is_sha256(token):
    return bool(sha256_re.match(token.text))

def is_sha512(token):
    return bool(sha512_re.match(token.text))


#
# To identify domain, we check if the string contains a valid 
# second-level domain (sld)
#
def is_domain(token):
    text = token.text

    # if domain is obfuscated with [.]
    text = text.replace('[.]', '.').replace('{.}', '.')

    # XXX: I thought regex solves it.
    if text.find('_'):
        return False

    # Special cases
    for suffix in ['.sh', '.zip']:
        if text.endswith(suffix):
            return False
    
    sld = psl.get_sld(text, strict=True)

    if bool(sld):
        if (len(text) >= len(sld)) and \
           (text.find(".") > 0) and \
           (text.find("@") == -1) and \
           (text.find(":") == -1) and \
           (text.find("\\") == -1) and \
           (text.find("/") == -1):
            return True
        else:
            return False
    else:
        return False


#
# define custom extensions for our Tokens
#
Token.set_extension("is_ipv4", getter=is_ipv4, force=True)
Token.set_extension("is_ipv6", getter=is_ipv6, force=True)
Token.set_extension("is_url", getter=is_url, force=True)
Token.set_extension("is_detection", getter=is_detection, force=True)
Token.set_extension("is_cve", getter=is_cve, force=True)
Token.set_extension("is_domain", getter=is_domain, force=True)
Token.set_extension("is_md5", getter=is_md5, force=True)
Token.set_extension("is_sha1", getter=is_sha1, force=True)
Token.set_extension("is_sha256", getter=is_sha256, force=True)
Token.set_extension("is_sha512", getter=is_sha512, force=True)
