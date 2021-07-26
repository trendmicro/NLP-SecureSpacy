import os
import re
import pickle
import spacy
from flair.data import Sentence
from securespacy.tagger import (
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
from securespacy.tokenizer import custom_tokenizer


# cf.: https://stackoverflow.com/questions/201323/how-to-validate-an-email-address-using-a-regular-expression
EMAIL_REGEX = re.compile(r"""(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])""", re.I | re.UNICODE)

def is_email(tok):
    return EMAIL_REGEX.match(tok.text)

class SecureSpacyFlairWrapper():
    model = None
    tokenized_matcher_tuple = []
    tokenized_matcher_pickle = os.path.expanduser('~/.tokenized_matcher.pickle')
    
    def __init__(self, spacy_model='en_core_web_sm', force_regenerate=False):
        if self.model is None:
            self.model = spacy.load(spacy_model)
        self.model.tokenizer = custom_tokenizer(self.model)
        if not os.path.exists(self.tokenized_matcher_pickle) or force_regenerate:
            self.generate_tokenized_dictionary()
            self.save_tokenized_dictionary()
        else:
            self.load_tokenized_dictionary()

    def load_tokenized_dictionary(self, fn=None):
        if fn is None:
            fn = self.tokenized_matcher_pickle
        print(f'Load tokenized dictionary from {fn}')
        with open(fn, 'rb') as f:
            self.tokenized_matcher_tuple = pickle.load(f)

    def save_tokenized_dictionary(self, fn=None):
        if fn is None:
            fn = self.tokenized_matcher_pickle
        print(f'Save tokenized dictionary to {fn}')
        with open(fn, 'wb') as f:
            pickle.dump(self.tokenized_matcher_tuple, f)

    def generate_tokenized_dictionary(self):
        from securespacy.tokenizer import (
            INTRUSION_SETS, COUNTRIES, CITIES, CAMPAIGNS, MALWARE,
            MALWARE_CASED, TOOLS, ORGS, PRODUCTS, VULNERABILITIES,
            REGIONS,)
        PHRASE_MATCHER_TUPLE = [
            # label,     list,        case sensitive?
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
        for label, dictionary, case in PHRASE_MATCHER_TUPLE:
            tokenized_items = []
            for item in dictionary:
                tokenized_items.append(self.tokenizer(item))
            ti = sorted(tokenized_items, key=lambda x: -len(x))     # Longest match first
            self.tokenized_matcher_tuple.append((label, ti, case))

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
    
    def phrase_matcher_internal(self, sent, dictionary, label, cased, ner_toks):
        REPLACEABLE = ['O', '', 'LOC']
        if cased:
            cmp = lambda x,y: x.text == y.text
        else:
            cmp = lambda x,y: x.text.casefold() == y.text.casefold()
        p = False
        for dict_tok in dictionary:
            # accelerator
            len_dict_tok = len(dict_tok)
            len_sent = len(sent)
            # main loop
            i = 0
            while i < len_sent:
                if not ner_toks[i] in REPLACEABLE:          # do not change when it is labeled by ML model
                    i += 1
                    continue
                if not cmp(sent[i], dict_tok[0]):           # Can be more beautiful, but let's compromise for speed
                    i += 1
                    continue
                if len_dict_tok == 1:
                    sent[i].add_tag('ner', f'S-{label}')
                    i += 1
                    continue
                if i + len_dict_tok > len_sent:
                    i += 1
                    continue
                for j in range(1, len_dict_tok):
                    if not cmp(sent[i+j], dict_tok[j]):
                        i += 1
                        break
                else:
                    sent[i].add_tag('ner', f'B-{label}')
                    ner_toks[i] = f'B-{label}'
                    for j in range(1, len_dict_tok - 1):
                        sent[i+j].add_tag('ner', f'I-{label}')
                        ner_toks[i+j] = f'I-{label}'
                    sent[i+len_dict_tok-1].add_tag('ner', f'E-{label}')
                    ner_toks[i+len_dict_tok-1] = f'E-{label}'
                    i += len_dict_tok                       # Matcher longer entitiies first
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
        ner_cache = self.build_ner_cache(sentence)
        for label, dictionary, cased in self.tokenized_matcher_tuple:
            sentence = self.phrase_matcher_internal(sentence, dictionary, label, cased, ner_cache)
        return sentence

    def build_ner_cache(self, sent):
        ner_toks = []
        for tok in sent:
            ner_toks.append(tok.get_tag('ner').value.split('-')[-1])
        return ner_toks

if __name__ == '__main__':
    pass
