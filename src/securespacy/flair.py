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


class SecureSpacyFlairWrapper():
    model = None
    PHRASE_MATCHER_CASED = {
        'COUNTRY': COUNTRIES,
        'CITY': CITIES,
        'ORG': ORGS,
        'MALWARE': MALWARE_CASED,
        'VULNERABILITY': VULNERABILITIES,
        'REGION': REGIONS,
    }
    PHRASE_MATCHER_UNCASED = {
        'INTRUSION_SET': INTRUSION_SETS,
        'MALWARE': MALWARE,
        'TOOL': TOOLS,
        'CAMPAIGN': CAMPAIGNS,
        'PRODUCT': PRODUCTS,
    }
    
    def __init__(self, spacy_model='en_core_web_sm'):
        if self.model is None:
            self.model = spacy.load(spacy_model)
        self.model.tokenizer = custom_tokenizer(self.model)

    def tokenizer(self, text):
        t = ' '.join(text.split())
        doc = self.model(t)
        return Sentence([x.text for x in doc])
    
    def phrase_matcher_internal(self, sent, dictionary, label, cased):
        if cased:
            cmp = lambda x,y: x.text == y
        else:
            cmp = lambda x,y: x.text.casefold() == y.casefold()
        for x in dictionary:
            xs = x.strip().split()
            i = 0
            while i < len(sent):
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
                                sentence[i+j].add_tag('ner', f'I-{label}')
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
        for label, dictionary in self.PHRASE_MATCHER_CASED.items():
            sentence = self.phrase_matcher_internal(sentence, dictionary, label, True)
        for label, dictionary in self.PHRASE_MATCHER_UNCASED.items():
            sentence = self.phrase_matcher_internal(sentence, dictionary, label, False)
        return sentence
    
    def flair_sentence(self, text):
        s1 = self.tokenizer(text)
        s2 = self.phrase_matcher(s1)
        return s2