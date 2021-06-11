import re

#
# from cyberspacy
#
# Taken from Regular Expressions Cookbook 2nd edition by Levithan and Goyvaerts
#
ipv4_expr = r"""
(?:
(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])[\[{]?\.[\]}]?
(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])[\[{]?\.[\]}]?
(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])[\[{]?\.[\]}]?
(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])
)(?:/(3[0-2]|[1-2][0-9]|[0-9]))?
"""

#
# from cyberspacy
#
# Taken from Regular Expressions Cookbook 2nd edition by Levithan and Goyvaerts
#
ipv6_expr = r"""
(?:
# Mixed
 (?:
  # Non-compressed
  (?:[A-F0-9]{1,4}:){6}
  # Compressed with at most 6 colons
 |(?=(?:[A-F0-9]{0,4}:){0,6}
     (?:[0-9]{1,3}\.){3}[0-9]{1,3}  # and 4 bytes
     (?![:.\w]))                    # and anchored
  # and at most 1 double colon
  (?:(?:[0-9A-F]{1,4}:){0,5}|:)(?:(?::[0-9A-F]{1,4}){1,5}:|:)
  # Compressed with 7 colons and 5 numbers
 |::(?:[A-F0-9]{1,4}:){5}
 )
 # 255.255.255.
 (?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}
 # 255
 (?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])
|# Standard
 (?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}
|# Compressed with at most 7 colons
 (?=(?:[A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}
    (?![:.\w]))  # and anchored
 # and at most 1 double colon
 (?:(?:[0-9A-F]{1,4}:){1,7}|:)(?:(?::[0-9A-F]{1,4}){1,7}|:)
 # Compressed with 8 colons
|(?:[A-F0-9]{1,4}:){7}:|:(?::[A-F0-9]{1,4}){7}
)(/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))?
"""

# Should cover regular domain, one letter (x.com), xn-- IDN domain, and [.] escaped domains
# https://stackoverflow.com/questions/10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd
domain_expr = r"""
(?:
  ^(?:
    (?!-)
    (?:xn--)?
    [a-z0-9-]{0,61}[a-z0-9]{1,1}
    (?:\.|\[\.\])
  )*
  (?:xn--)?
  (?:[a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}
    (?:\.|\[\.\])
    (?:[a-z]{2,})
  )$
)
"""

# from https://gist.github.com/pchc2005/b5f13e136a9c9bb2984e5b92802fc7c9, which is based on
# https://gist.github.com/dperini/729294
#
# Modified the regex in the protocol part so we could identify obfuscated URLs (hxxp, fxp).
# Original protocal RE: (?:(?:(?:https?|ftp):)?//)
url_expr = (
    r"^"
    # protocol identifier
    r"(?:(?:(?:ht|hx|f)[tx]p(?:s?):)?//)"
    # user:pass authentication
    r"(?:\S+(?::\S*)?@)?"
    r"(?:"
    + ipv4_expr + r"|"
    + ipv6_expr + r"|"
    # host & domain names, may end with dot
    # can be replaced by a shortest alternative
    # r"(?![-_])(?:[-\w\u00a1-\uffff]{0,63}[^-_]\.)+"
    # r"(?:(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)"
    # # domain name
    # r"(?:\.(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)*"
    r"(?:"
    r"(?:"
    r"[a-z0-9\u00a1-\uffff]"
    r"[a-z0-9\u00a1-\uffff_-]{0,62}"
    r")?"
    r"[a-z0-9\u00a1-\uffff]\[?\.\]?"
    r")+"
    # TLD identifier name, may end with dot
    r"(?:[a-z\u00a1-\uffff]{2,}\.?)"
    r")"
    # port number (optional)
    r"(?::\d{2,5})?"
    # resource path (optional)
    r"(?:[/?#]\S*)?"
    r"$"
)


#
# Malware detection
#
detection_expr = r"""
(?:
    ^
    (?:(?:PUP|W32)/)?
    (?:(?:W|Win)(?:32|64)[\._])?
    (?:[A-Za-z0-9]+)
    (?:[\._][A-Za-z0-9]+)
    (?:[\._][A-Za-z0-9]+)?
    (?:[\._][A-Za-z0-9-]+)?$
)
"""

# cve numbers
cve_expr = r"""
(?:
   ^(?:
   (?:CVE[ -])
   (?:(?:19|20)\d{2})\-
   (?:\d{3,7})
   |
   (?:MS-[0-9]{2}-[0-9]{3})
   )$
)
"""

#
# hashes
#
md5_expr = r"""(?:^[a-f0-9]{32}$)"""
sha1_expr = r"""(?:^[a-f0-9]{40}$)"""
sha256_expr = r"""(?:^[a-f0-9]{64}$)"""
sha512_expr = r"""(?:^[a-f0-9]{128}$)"""
