# securespacy

`securespacy` is a Python module that contains our custom tokenizer and named entity extractor for Spacy v3. The following named entities can be extracted by using `securespacy`:

- IP
- URL
- DOMAIN
- EMAIL
- MALWARE
- CVE
- HASH
- INTRUSION_SET
- CITY
- COUNTRY

`securespacy` uses Spacy's **Entity Ruler**, which is a rules-based matching approach in order to extract additional named entities from the text. In other words, this is a fancy way of saying that we're using regex and other static rules to detect entities, in order to complement Spacy's named entity recognition (NER) that uses trained language models.

## Installation
```bash
$ pip install https://github.com/trendmicro/NLP-SecureSpacy.git
```


## Usage

```
import spacy

import securespacy
from securespacy import tagger
from securespacy.tokenizer import custom_tokenizer
from securespacy.patterns import add_entity_ruler_pipeline

text = ('The quick brown fox owns the domain quickbrownfox[.]sh with the ip address 10.231.31.8 '
'with the server located in Manila, Philippines.')

nlp = spacy.load("en_core_web_sm")
nlp.tokenizer = custom_tokenizer(nlp)
add_entity_ruler_pipeline(nlp)
doc = nlp(text)

for ent in doc.ents:
    print(f"{ent.label_:<15} {ent}")

DOMAIN          quickbrownfox[.]sh
IP              10.231.31.8
CITY            Manila
COUNTRY         Philippines
```

## Flair Wrapper

securespacy can be used with Flair. The API is slightly different.

**N.B.** In order to accelerate `phrase_matcher()`, a dictionary will be written in `~/.tokenized_matcher.pickle`.
Delete the file to regenerate it when dictionary files are updated (usually when you update SecureSpacy.)

```python
from flair.models import SequenceTagger
from flair.data import Sentence
from securespacy.flair import SecureSpacyFlairWrapper

tagger = SequenceTagger.load('ner')
text = 'We were able to find a second variant (detected as Trojan.MacOS.GMERA.B) that was uploaded to VirusTotal.'
wrapper = SecureSpacyFlairWrapper()
sentence = Sentence(text, use_tokenizer=wrapper.tokenizer)
model.predict(sentence)
wrapper.phrase_matcher(sentence)
for ent in sentence.get_spans('ner'):
    print(ent)
```

The type of sentence is `flair.data.sentence`.

## References
- https://spacy.io/usage/rule-based-matching#entityruler


## Maintenance

To import the latest data from [MITRE ATT&CK Techniques](https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack), download the latest JSON and run
`./src/securespacy/data/convert-mitre-enterprise.py`. Do a manual pass before mergin the converted files, as
short software names (such as `Net`, `at`, `at.exe`) can cause false classifications.

Merge `mitre-malware.txt` into the case-sensitive list `malware-cased.txt`.

## License

See LICENSE.
