
import os
import re
import spacy
from spacy.tokenizer import Tokenizer

from .expressions import (
    detection_expr,
    cve_expr
)


def build_special_cases():

    special_cases = {}
    pwd = os.path.dirname(os.path.realpath(__file__))

    with open(os.path.join(pwd, "data", "intrusion_set.txt"), "r") as fh:
        for l in fh:
            line = l.strip()

            special_cases[line] = [
                {
                    "ORTH": line
                }
            ]

    return special_cases


#
# define our custom Tokenizer function
#
def custom_tokenizer(nlp):

    #
    # we can optionally define regex to tokenize target text. We use the detection
    # regex because Spacy sometimes tokenizes detection string wrong
    #
    token_re = re.compile(f"{detection_expr}|{cve_expr}", re.VERBOSE | re.I | re.UNICODE)

    #
    # special cases dictionary
    #
    special_cases = build_special_cases()

    default_prefixes = nlp.Defaults.prefixes
    default_infixes = nlp.Defaults.infixes
    default_suffixes = nlp.Defaults.suffixes
    default_url_match = nlp.Defaults.url_match

    prefixes_re = spacy.util.compile_prefix_regex(default_prefixes)
    suffixes_re = spacy.util.compile_suffix_regex(default_suffixes)
    infixes_re  = spacy.util.compile_infix_regex(default_infixes)

    return Tokenizer(nlp.vocab,
                     rules=special_cases,
                     prefix_search=prefixes_re.search,
                     suffix_search=suffixes_re.search,
                     infix_finditer=infixes_re.finditer,
                     token_match=token_re.search,
                     url_match=nlp.Defaults.url_match
                    )

