# -*- coding: utf8 -*-
import os
import re
import spacy
from spacy.tokenizer import Tokenizer

from .expressions import (
    detection_expr,
    cve_expr,
    url_expr,
    domain_expr,
    mitre_expr,
)


pwd = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(pwd, "data", "intrusion_set.txt"), "r", encoding='utf-8') as fh:
    INTRUSION_SETS = [l.strip() for l in fh]

with open(os.path.join(pwd, "data", "countries.txt"), "r", encoding='utf-8') as fh:
    COUNTRIES = [l.strip() for l in fh]

with open(os.path.join(pwd, "data", "cities.txt"), "r", encoding='utf-8') as fh:
    CITIES = [l.strip() for l in fh]

with open(os.path.join(pwd, "data", "campaigns.txt"), "r", encoding='utf-8') as fh:
    CAMPAIGNS = [l.strip() for l in fh]

with open(os.path.join(pwd, "data", "malware.txt"), "r", encoding='utf-8') as fh:
    MALWARE = [l.strip() for l in fh]

with open(os.path.join(pwd, "data", "malware-cased.txt"), "r", encoding='utf-8') as fh:
    MALWARE_CASED = [l.strip() for l in fh]

with open(os.path.join(pwd, "data", "tools.txt"), "r", encoding='utf-8') as fh:
    TOOLS = [l.strip() for l in fh]

with open(os.path.join(pwd, "data", "orgs.txt"), "r", encoding='utf-8') as fh:
    ORGS = [l.strip() for l in fh]

with open(os.path.join(pwd, "data", "products.txt"), "r", encoding='utf-8') as fh:
    PRODUCTS = [l.strip() for l in fh]

with open(os.path.join(pwd, "data", "vulnerabilities.txt"), "r", encoding='utf-8') as fh:
    VULNERABILITIES = [l.strip() for l in fh]

with open(os.path.join(pwd, "data", "regions.txt"), "r", encoding='utf-8') as fh:
    REGIONS = [l.strip() for l in fh]

def token_match(text):
    if text.lower == "circus spider":
        return True


#
# define our custom Tokenizer function
#
def custom_tokenizer(nlp):

    #
    # we can optionally define regex to tokenize target text. We use the detection
    # regex because Spacy sometimes tokenizes detection string wrong
    #
    token_re = re.compile(f"{detection_expr}|{cve_expr}|{url_expr}|{domain_expr}|{mitre_expr}", re.VERBOSE | re.I | re.UNICODE)

    default_prefixes = nlp.Defaults.prefixes
    default_infixes = nlp.Defaults.infixes
    default_suffixes = nlp.Defaults.suffixes
    default_url_match = nlp.Defaults.url_match

    prefixes_re = spacy.util.compile_prefix_regex(default_prefixes)
    suffixes_re = spacy.util.compile_suffix_regex(default_suffixes)
    infixes_re  = spacy.util.compile_infix_regex(default_infixes)

    return Tokenizer(nlp.vocab,
                     rules=nlp.tokenizer.rules,
                     prefix_search=prefixes_re.search,
                     suffix_search=suffixes_re.search,
                     infix_finditer=infixes_re.finditer,
                     token_match=token_re.search,
                     url_match=nlp.Defaults.url_match
                    )

