
from .tokenizer import intrusion_sets


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
        "label": "IPv4",
        "pattern": [
            {
                "_": {
                    "is_ipv4": True
                }
            }
        ]
    },
    {
        "label": "IPv6",
        "pattern": [
            {
                "_": {
                    "is_ipv6": True
                }
            }
        ]
    },
    {
        "label": "URL",
        "pattern": [
            {"LIKE_URL": True},
        ]
    },
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
        "label": "DOMAIN",
        "pattern": [
            {
                "_": {
                    "is_domain": True
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
        "label": "MD5",
        "pattern": [
            {
                "_": {
                    "is_md5": True
                }
            }
        ]
    },
    {
        "label": "SHA1",
        "pattern": [
            {
                "_": {
                    "is_sha1": True
                }
            }
        ]
    },
    {
        "label": "SHA256",
        "pattern": [
            {
                "_": {
                    "is_sha256": True
                }
            }
        ]
    },
    {
        "label": "SHA512",
        "pattern": [
            {
                "_": {
                    "is_sha512": True
                }
            }
        ]
    },
]

#
# we add the intrusion set list into our patterns
#
for intrusion_set in intrusion_sets:
    patterns.append(
        {
            "label": "INTRUSION_SET",
            "pattern": [
                { "LOWER": intrusion_set.lower() }
            ]
        }
    )
