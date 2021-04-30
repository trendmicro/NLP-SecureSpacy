from collections import Counter
from unittest import TestCase

import spacy


import securespacy
from securespacy import tagger
from securespacy.tokenizer import custom_tokenizer
from securespacy.patterns import config, patterns


text = ('However, at the time of writing, we were unable to decrypt this file since the upload URL https://appstockfolio.com/panel/upload.php '
        'was inaccessible (according to VirusTotal, the domain was active from January to February 2019). Furthermore, we suspect that the full '
        'malware routine uses the TOR network due to the presence of the unused address gmzera54l5qpa6lm.onion.\nUsing the digital certificate '
        'of the first sample, we were able to find a second variant (detected as Trojan.MacOS.GMERA.B) that was uploaded to VirusTotal on June '
        '2019.\n This IP address 10.2.13.1 is from the local network. It connects to the IP address 192.168.2.14.\nAnother is a new loader called '
        '“Ascentor Loader” (TROJ_DLOADR.SULQ or TROJ_DLOADR), used by GrandSoft’s customers.\n'
        'The stolen data was then uploaded to hxxps://appstockfolio.com/panel/upload[.]php and .\n'
        'The domain gmzera54l5qpa6lm[.]onion was used as the C&C.\n'
        'The message was sent to the email addresses joey_costoya@trendmicro.com and joey.costoya@trendmicro.com.\n'
        'These are example IPv6 addresses: 2404:6800:4008:801::2004, 2600:1408:5c00:1a9::356e/64, and 2600:1408:5c00:198::356e.\n'
        'Here are some hashes:\n'
        '54efe3af6406673464eef89bb032f96e8b98bd16  corpus/trendBlogDocs.json\n'
        'fa7fe0a7271b3b07ed4fdfa7a59298527f57f11511b6699bc80f9ded7f11ad06  corpus/trendBlogDocs.json\n'
        '90f9fe128f01562b5d87565ac669cf8ff4883f07abf6a56ec074cc7a8b0f3411343ce8aef6fe07afb511ddc811ed06997a1a1e7c451303e390aff72753581615  corpus/trendBlogDocs.json\n'
        '71cfd7d692a301ac9bff0e1e7605e7c2  corpus/trendBlogDocs.json\n'
        'These are cve numbers: CVE-1999-2012 CVE-2004-0003 CVE-2021-26855\n'
        'Meanwhile, CIRCUS SPIDER and Wolf Research are in the house.\n'
        'Additional detections: Win32.Virlock.A and Win64.Virlock.A and not a valid detection Win65.Virlock.A')



def print_tokens(doc):
    print(f"{'Fine-grained POS':<18} {'Coarse-grained POS':<20} {'Explaination':<50} {'Token':<15}\n")

    for token in doc:
        print(f"{token.tag_:<18} ", end='')
        print(f"{token.pos_:<20}", end='')

        try:
            print(f"{spacy.explain(token.tag_):<50} ", end='')
        except:
            print(f"{'':<30} ", end='')
            
        print(f"{repr(token):<15}")


def print_entities(doc):
    print(f"{'Label':<15} {'Entity'}\n")

    for ent in doc.ents:
        print(f"{ent.label_:<15} {ent}")

    print()


class TestTagger(TestCase):

    def setUp(self):
        self.nlp = spacy.load("en_core_web_sm")
        self.nlp.tokenizer = custom_tokenizer(self.nlp)

        ruler = self.nlp.add_pipe("entity_ruler", config=config)
        ruler.add_patterns(patterns)


    expected_results = {
        "URL": [
            'https://appstockfolio.com/panel/upload.php',
            'hxxps://appstockfolio.com/panel/upload[.]php'
        ],
        "ORG": ['VirusTotal', 'TOR', 'VirusTotal', 'IP', 'IP', 'GrandSoft’s', 'IPv6'],
        "DATE": ['January to February 2019', 'June 2019'],
        "DOMAIN":  [
            'gmzera54l5qpa6lm.onion',
            'gmzera54l5qpa6lm[.]onion'
        ],
        "ORDINAL": ['first', 'second'],
        "MALWARE": ['Trojan.MacOS.GMERA.B', 'TROJ_DLOADR.SULQ', 'Win32.Virlock.A', 'Win64.Virlock.A'],
        "IPv4": ['10.2.13.1', '192.168.2.14'],
        "IPv6": ['2404:6800:4008:801::2004', '2600:1408:5c00:1a9::356e/64', '2600:1408:5c00:198::356e'],
        "WORK_OF_ART": ['Ascentor Loader'],
        "EMAIL": ['joey_costoya@trendmicro.com', 'joey.costoya@trendmicro.com'],
        "SHA1": ['54efe3af6406673464eef89bb032f96e8b98bd16'],
        "SHA256": ['fa7fe0a7271b3b07ed4fdfa7a59298527f57f11511b6699bc80f9ded7f11ad06'],
        "SHA512": ['90f9fe128f01562b5d87565ac669cf8ff4883f07abf6a56ec074cc7a8b0f3411343ce8aef6fe07afb511ddc811ed06997a1a1e7c451303e390aff72753581615'],
        "MD5": ['71cfd7d692a301ac9bff0e1e7605e7c2'],
        "CVE": ['CVE-1999-2012', 'CVE-2004-0003', 'CVE-2021-26855'],
        "INTRUSION_SET": ['CIRCUS SPIDER', 'Wolf Research']
    }

    def test_entity_extractor(self):

        doc = self.nlp(text)

        label_counts = Counter([ent.label_ for ent in doc.ents])
        for label in label_counts:
            print(f"expected {len(self.expected_results[label]):02} {label}")
            print(f"got      {len([ent.text for ent in doc.ents if ent.label_ == label]):02} {label}")
            print()
            self.assertTrue(len(self.expected_results[label]) == label_counts[label])

        print("----------\n")

        for entity in doc.ents:
            print(f"expected: {entity.label_}: {self.expected_results[entity.label_]}")
            print(f"got:      {entity.label_}: {entity.text}")
            print()
            self.assertTrue( entity.text in self.expected_results[entity.label_] )


if __name__ == "__main__":
    unittest.main()