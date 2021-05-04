# securespacy

## Usage

```
>>> import spacy
>>>
>>> import securespacy
>>> from securespacy import tagger
>>> from securespacy.tokenizer import custom_tokenizer
>>> from securespacy.patterns import config, patterns
>>>
>>> text = 'The quick brown fox owns the domain quickbrownfox.sh'
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
DOMAIN          quickbrownfox.sh
```
