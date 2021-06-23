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
$ pip install git+ssh://git@github.trendmicro.com/CoreTech-FTR/securespacy.git
```

Alternatively, you can download and install from the latest binary release here:
- https://github.trendmicro.com/CoreTech-FTR/securespacy/releases

## Usage

```
>>> import spacy
>>>
>>> import securespacy
>>> from securespacy import tagger
>>> from securespacy.tokenizer import custom_tokenizer
>>> from securespacy.patterns import add_entity_ruler_pipeline
>>>
>>> text = ('The quick brown fox owns the domain quickbrownfox[.]sh with the ip address 10.231.31.8 '
>>>         'with the server located in Manila, Philippines.')
>>>
>>> nlp = spacy.load("en_core_web_sm")
>>> nlp.tokenizer = custom_tokenizer(nlp)
>>> self.nlp.tokenizer = custom_tokenizer(self.nlp)
>>> add_entity_ruler_pipeline(self.nlp)
>>> doc = nlp(text)
>>>
>>> for ent in doc.ents:
...     print(f"{ent.label_:<15} {ent}")
...
DOMAIN          quickbrownfox[.]sh
IP              10.231.31.8
CITY            Manila
COUNTRY         Philippines
```

## Flair Wrapper

securespacy can be used with Flair. The API is slightly different.

```python
from flair.models import SequenceTagger
from flair.data import Sentence
from securespacy.flair import SecureSpacyFlairWrapper

tagger = SequenceTagger.load('ner')
wrapper = SecureSpacyFlairWrapper()
sentence = Sentence(text, use_tokenizer=wrapper.tokenizer)
text = 'We were able to find a second variant (detected as Trojan.MacOS.GMERA.B) that was uploaded to VirusTotal.'
model.predict(sentence)
wrapper.phrase_matcher(sentence)
for ent in sentence.get_spans('ner'):
    print(ent)
```

The type of sentence is `flair.data.sentence`.

## References
- https://spacy.io/usage/rule-based-matching#entityruler
