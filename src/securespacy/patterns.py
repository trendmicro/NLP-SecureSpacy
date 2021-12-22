from spacy.matcher import PhraseMatcher

from .tokenizer import (
    INTRUSION_SETS,
    COUNTRIES,
    CITIES,
    CAMPAIGNS,
    MALWARE,
    MALWARE_CASED,
    TOOLS,
    ORGS,
    PRODUCTS,
    VULNERABILITIES,
    REGIONS,
)


#
# [2021-04-12] I'm actually kinda lost in how the Spacy configurations work. 
# This is taken from a Spacy tutorial
#
config = {
    "phrase_matcher_attr": None,
    "validate": True,
    "overwrite_ents": True,
    "ent_id_sep": "||",
}

#
# To extend Spacy's NER, we use the Entity Ruler component. This component uses a list of
# labelled patterns, with matches taken from the Spacy's tokenization and the Token
# extensions defined previously
#
# these are the patterns that enable us to recognize additional named entities using
# a rules-based method
#
patterns = [
#     {
#         "label": "IPv4",
#         "pattern": [
#             {"IS_DIGIT": True},
#             {"IS_PUNCT": True},
#             {"ENT_TYPE": "CARDINAL"},
#             {"IS_PUNCT": True},
#             {"ENT_TYPE": "CARDINAL"},
#             {"IS_PUNCT": True},
#             {"ENT_TYPE": "CARDINAL"},
#         ]
#     },
    {
        "label": "IP",
        "pattern": [
            {
                "_": {
                    "is_ipv4": True
                }
            }
        ]
    },
    {
        "label": "IP",
        "pattern": [
            {
                "_": {
                    "is_ipv6": True
                }
            }
        ]
    },
#    {
#        "label": "URL",
#        "pattern": [
#            {"LIKE_URL": True},
#        ]
#    },
    {
        "label": "URL",
        "pattern": [
            {
                "_": {
                    "is_url": True
                }
            }
        ]
    },
    {
        "label": "EMAIL",
        "pattern": [
            {"LIKE_EMAIL": True},
        ]
    },
    {
        "label": "MALWARE",
        "pattern": [
            {
                "_": {
                    "is_detection": True
                }
            }
        ]
    },
    {
        "label": "CVE",
        "pattern": [
            {
                "_": {
                    "is_cve": True
                }
            }
        ]
    },
    {
        "label": "HASH",
        "pattern": [
            {
                "_": {
                    "is_md5": True
                }
            }
        ]
    },
    {
        "label": "HASH",
        "pattern": [
            {
                "_": {
                    "is_sha1": True
                }
            }
        ]
    },
    {
        "label": "HASH",
        "pattern": [
            {
                "_": {
                    "is_sha256": True
                }
            }
        ]
    },
    {
        "label": "HASH",
        "pattern": [
            {
                "_": {
                    "is_sha512": True
                }
            }
        ]
    },
    {
        "label": "DOMAIN",
        "pattern": [
            {
                "_": {
                    "is_domain": True,
                    'is_detection': False,
                }
            }
        ]
    },
    {
        "label": "MITRE",
        "pattern": [
            {
                "_": {
                    "is_mitre": True,
                }
            }
        ]
    },
]


def add_entity_ruler_pipeline(nlp):
    rulers = []
    for pipe in ['entity_ruler_regex', 'entity_ruler_case_sensitive', 'entity_ruler_case_insensitive']:
        if pipe in nlp.component_names:
            nlp.remove_pipe(pipe)
        rulers.append(nlp.add_pipe("entity_ruler", name=pipe, config=config))

# PhraseMathcer for case sensitive terms
    matcher = PhraseMatcher(nlp.vocab)
    matcher.add('COUNTRY', nlp.tokenizer.pipe(COUNTRIES))
    matcher.add('CITY', nlp.tokenizer.pipe(CITIES))
    matcher.add('ORG', nlp.tokenizer.pipe(ORGS))
    matcher.add('MALWARE', nlp.tokenizer.pipe(MALWARE_CASED))
    matcher.add('VULNERABILITY', nlp.tokenizer.pipe(VULNERABILITIES))
    matcher.add('REGION', nlp.tokenizer.pipe(REGIONS))

# Second PhraseMathcer for case insensitive terms :(
    i_matcher = PhraseMatcher(nlp.vocab, attr='LOWER')
    i_matcher.add('INTRUSION_SET', nlp.tokenizer.pipe(INTRUSION_SETS))
    i_matcher.add('MALWARE', nlp.tokenizer.pipe(MALWARE))
    i_matcher.add('TOOL', nlp.tokenizer.pipe(TOOLS))
    i_matcher.add('CAMPAIGN', nlp.tokenizer.pipe(CAMPAIGNS))
    i_matcher.add('PRODUCT', nlp.tokenizer.pipe(PRODUCTS))

    dummy_patterns = [{"label": "DUMMY", "pattern": "__dummy pattern to surpress warnings__"}]
    rulers[0].add_patterns(patterns)
    rulers[1].phrase_matcher = matcher
    rulers[1].add_patterns(dummy_patterns)
    rulers[2].phrase_matcher = i_matcher
    rulers[2].add_patterns(dummy_patterns)
    return nlp
