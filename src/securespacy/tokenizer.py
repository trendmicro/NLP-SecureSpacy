
import re
import spacy
from spacy.tokenizer import Tokenizer

from .expressions import (
    detection_expr,
    cve_expr
)

#
# define our custom Tokenizer function
#
def custom_tokenizer(nlp):

    #
    # we can optionally define regex to tokenize target text. We use the detection
    # regex because Spacy sometimes tokenizes detection string wrong
    #
    token_re = re.compile(f"{detection_expr}|{cve_expr}", re.VERBOSE | re.I | re.UNICODE)

    default_prefixes = nlp.Defaults.prefixes
    default_infixes = nlp.Defaults.infixes
    default_suffixes = nlp.Defaults.suffixes
    default_url_match = nlp.Defaults.url_match

    prefixes_re = spacy.util.compile_prefix_regex(default_prefixes)
    suffixes_re = spacy.util.compile_suffix_regex(default_suffixes)
    infixes_re  = spacy.util.compile_infix_regex(default_infixes)

    return Tokenizer(nlp.vocab,
                     prefix_search=prefixes_re.search,
                     suffix_search=suffixes_re.search,
                     infix_finditer=infixes_re.finditer,
                     token_match=token_re.search,
                     url_match=nlp.Defaults.url_match
                    )

