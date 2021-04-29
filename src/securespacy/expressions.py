import re

#
# from cyberspacy
#
# Taken from Regular Expressions Cookbook 2nd edition by Levithan and Goyvaerts
#
ipv4_expr = r"""
(?:
(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.
(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.
(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.
(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])
)
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
)
"""

# from https://gist.github.com/pchc2005/b5f13e136a9c9bb2984e5b92802fc7c9, which is based on
# https://gist.github.com/dperini/729294
#
# Modified the regex in the protocol part so we could identify obfuscated URLs (hxxp, fxp).
# Original protocal RE: (?:(?:(?:https?|ftp):)?//)
url_expr = r"""
    (?:(?:(?:ht|hx|f)[tx]p(?:s?):)?//)
    (?:\S+(?::\S*)?@)?
    (?:
    (?!(?:10|127)(?:\.\d{1,3}){3})
    (?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})
    (?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})
    (?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])
    (?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}
    (?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))
    |
    (?:\.(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)*
    (?:
    (?:
    [a-z0-9\u00a1-\uffff]
    [a-z0-9\u00a1-\uffff_-]{0,62}
    )?
    [a-z0-9\u00a1-\uffff]\.
    )+
    (?:[a-z\u00a1-\uffff]{2,}\.?)
    )
    (?::\d{2,5})?
    (?:[/?#]\S*)
"""

#
# Malware detection
#
detection_expr = r"""
(?:
   ^(?:[A-Za-z0-9]+[\._])
   (?:[A-Za-z0-9]+[\._])
   (?:[A-Za-z0-9]+)
   (?:[\._][A-Za-z0-9]+)?$
)
"""

# cve numbers
cve_expr = r"""
(?:
   ^(?:CVE)\-
   (?:(?:19|20)\d{2})\-
   (?:\d{3,5})$
)
"""

#
# hashes
#
md5_expr = r"""(?:^[a-f0-9]{32}$)"""
sha1_expr = r"""(?:^[a-f0-9]{40}$)"""
sha256_expr = r"""(?:^[a-f0-9]{64}$)"""
sha512_expr = r"""(?:^[a-f0-9]{128}$)"""