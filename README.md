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
>>> from securespacy.patterns import config, patterns
>>>
>>> text = ('The quick brown fox owns the domain quickbrownfox[.]sh with the ip address 10.231.31.8 '
>>>         'with the server located in Manila, Philippines.')
>>>
>>> nlp = spacy.load("en_core_web_sm")
>>> nlp.tokenizer = custom_tokenizer(nlp)
>>> ruler = nlp.add_pipe("entity_ruler", config=config)
>>> ruler.add_patterns(patterns)
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

## References
- https://spacy.io/usage/rule-based-matching#entityruler
