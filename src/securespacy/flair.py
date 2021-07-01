import re
import spacy
from flair.data import Sentence
from .tagger import (
    is_ipv4,
    is_ipv6,
    is_url,
    is_detection,
    is_cve,
    is_md5,
    is_sha1,
    is_sha256,
    is_sha512,
    is_domain,
)
from .tokenizer import (
    custom_tokenizer,
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


# cf.: https://stackoverflow.com/questions/201323/how-to-validate-an-email-address-using-a-regular-expression
EMAIL_REGEX = re.compile(r"""(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])""", re.I | re.UNICODE)

def is_email(tok):
    return EMAIL_REGEX.match(tok.text)

class SecureSpacyFlairWrapper():
    model = None
    PHRASE_MATCHER_TUPLE = [
        ('INTRUSION_SET', INTRUSION_SETS, False),
        ('CAMPAIGN', CAMPAIGNS, False),
        ('VULNERABILITY', VULNERABILITIES, True),
        ('MALWARE', MALWARE_CASED, True),
        ('MALWARE', MALWARE, False),
        ('TOOL', TOOLS, False),
        ('COUNTRY', COUNTRIES, True),
        ('REGION', REGIONS, True),
        ('CITY', CITIES, True),
        ('PRODUCT', PRODUCTS, False),
        ('ORG', ORGS, True),
    ]
    tokenized_text = {}
    
    def __init__(self, spacy_model='en_core_web_sm'):
        if self.model is None:
            self.model = spacy.load(spacy_model)
        self.model.tokenizer = custom_tokenizer(self.model)

    def tokenizer(self, text):
        from flair.data import Token
        previous_token = None
        tokens = []
        doc = self.model(text)
        for word in doc:
            if len(word.text.strip()) == 0:
                continue
            token = Token(text=word.text, start_position=word.idx, whitespace_after=True)
            tokens.append(token)
            if previous_token is not None and token.start_pos == previous_token.start_pos + len(previous_token.text):
                previous_token.whitespace_after = False
            previous_token = token
        return tokens
    
    def phrase_matcher_internal(self, sent, dictionary, label, cased):
        DONT_REPLACE_LABELS = [e[0] for e in self.PHRASE_MATCHER_TUPLE]
        if label == 'PRODUCT':
            DONT_REPLACE_LABELS.remove('ORG')
        if cased:
            cmp = lambda x,y: x.text == y.text
        else:
            cmp = lambda x,y: x.text.casefold() == y.text.casefold()
        p = False
        for x in dictionary:
            # accelerator
            if x not in self.tokenized_text:
                self.tokenized_text[x] = self.tokenizer(x)
            xs = self.tokenized_text[x]
            i = 0
            while i < len(sent):
                if str(sent[i].get_tag('ner').value).split('-')[-1] in DONT_REPLACE_LABELS:
                    i += 1
                    continue
                if cmp(sent[i], xs[0]):
                    if len(xs) == 1:
                        sent[i].add_tag('ner', f'S-{label}')
                        i += 1
                    else:
                        for j in range(1, len(xs)):
                            if len(sent) <= i+j or not cmp(sent[i+j], xs[j]):
                                i += 1
                                break
                        else:
                            sent[i].add_tag('ner', f'B-{label}')
                            for j in range(1, len(xs) - 1):
                                sent[i+j].add_tag('ner', f'I-{label}')
                            sent[i+len(xs)-1].add_tag('ner', f'E-{label}')
                            i += len(xs)
                else:
                    i += 1
        return sent
    
    def phrase_matcher(self, sentence):
        for tok in sentence:
            if is_ipv4(tok) or is_ipv6(tok):
                tok.add_tag('ner', 'S-IP')
            elif is_url(tok):
                tok.add_tag('ner', 'S-URL')
            elif is_detection(tok):
                tok.add_tag('ner', 'S-MALWARE')
            elif is_cve(tok):
                tok.add_tag('ner', 'S-CVE')
            elif is_md5(tok) or is_sha1(tok) or is_sha256(tok) or is_sha512(tok):
                tok.add_tag('ner', 'S-HASH')
            elif is_domain(tok):  # implied NOT is_detection()
                tok.add_tag('ner', 'S-DOMAIN')
            elif is_email(tok):
                tok.add_tag('ner', 'S-EMAIL')
        for label, dictionary, cased in self.PHRASE_MATCHER_TUPLE:
            sentence = self.phrase_matcher_internal(sentence, dictionary, label, cased)
        return sentence
