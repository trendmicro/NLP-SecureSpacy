from collections import Counter
from unittest import TestCase

import spacy


import securespacy
from securespacy import tagger
from securespacy.tokenizer import custom_tokenizer
from securespacy.patterns import add_entity_ruler_pipeline


text = ('However, at the time of writing, we were unable to decrypt this file since the upload URL https://appstockfolio.com/panel/upload.com '
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
        'These are cve numbers: CVE-1999-2012 CVE-2004-0003 CVE-2021-26855 MS-10-017 MS16-017 APSB12-16 CVE-2019-1003000\n'
        'Meanwhile, CIRCUS SPIDER and Wolf Research are in the house.\n'
        'Additional detections: Win32.Virlock.A and Win64.Virlock.A and not a valid detection Win65.Virlock.A\n'
        'These strings 103[.]5.3.123 63.234[.]34.2 90.234.51[.]5 9[.]9[.]9[.]9 9{.}9{.}9{.}9 are examples of obfuscated ipaddresses.\n'
        'Taiwan, Philippines, Czech Republic, and United States of America (USA) are countries to be recognized by ner. \n'
        'As well the following cities: Taipei, Manila, Saint Petersburg, The Hague, Nukuʻalofa\n'
        'Cities in lower case like taipei, manila, san jose should no longer be extracted.\n'
        'Detection names in lower case like tspy_gammarue.a should not be detected, either.\n'
        'Malware deploys newinit.sh in /var/lib/www/ and extracts download.zip to directories\n'
        'Several exploit kits: Angler EK, Rig EK. StuxNet is an old malware.\n'
        'Trend Micro Deep Discovery Inspector\n'
        'https://appstockfolio.com/panel/upload.com?asdf=adf#werss\n'
        'hxxp://drivestransfer.com\n'
        'hxxp://drivestransfer[.]com\n'
        'hxxps://drivestransfer[.]com\n'
        'hxxp://subs[.]drivestransfer.com\n'
        'hxxps://subs[.]drivestransfer.com\n'
        'hxxps://subs[.]drivestransfer[.]com\n'
        'hxxps://103[.]7.224.25\n'
        'hxxps://103.7[.]224.25\n'
        'hxxps://103.7.224[.]25\n'
        'hxxps://103[.]7[.]224[.]25\n'
        'de.gengine[.]com.de\n'
        'de.gsearch[.]com.de\n'
        'global.bitmex[.]com.de\n'
        'hxxp://146.71.79[.]230/363A3EDC10A2930DVNICE/sysguard\n'
        'hxxp://146.71.79[.]230/363A3EDC10A2930DVNICE/sysupdate\n'
        'hxxp://146.71.79[.]230/363A3EDC10A2930DVNICE/update.sh\n'
        'hmrc[.]covid[.]19-support-grant[.]com\n'
        'fund4-covid19[.]com\n'
        'furlough-grant[.]com\n'
        'PeNet.Structures.MetaDataTables\n'         # Should be excluded
        'furlough-grant.notatld\n'
        'fb.com paypal.com, not paypal.co.uk \n'
        '8.3.0.0767\n'
        # 'dl[.]haqo[.]net/ins2.exez\n'
        # 'i[.]haqo[.]net/i.png\n'
        # 'ii[.]haqo[.]net/u.png\n'
        # 'v[.]beahh[.]com/v\n'
        # '132[.]162[.]107[.]97/xmrig-32_1.mlz\n'
        # '139[.]162[.]107[.]97/h.bat\n'
        )



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
        add_entity_ruler_pipeline(self.nlp)


    expected_results = {
        "URL": [
            'https://appstockfolio.com/panel/upload.com',
            'hxxps://appstockfolio.com/panel/upload[.]php',
            'https://appstockfolio.com/panel/upload.com?asdf=adf#werss',
            'hxxp://drivestransfer.com',
            'hxxp://drivestransfer[.]com',
            'hxxps://drivestransfer[.]com',
            'hxxp://subs[.]drivestransfer.com',
            'hxxps://subs[.]drivestransfer.com',
            'hxxps://subs[.]drivestransfer[.]com',
            'hxxps://103[.]7.224.25',
            'hxxps://103.7[.]224.25',
            'hxxps://103.7.224[.]25',
            'hxxps://103[.]7[.]224[.]25',
            'hxxp://146.71.79[.]230/363A3EDC10A2930DVNICE/sysguard',
            'hxxp://146.71.79[.]230/363A3EDC10A2930DVNICE/sysupdate',
            'hxxp://146.71.79[.]230/363A3EDC10A2930DVNICE/update.sh',
            # 'dl[.]haqo[.]net/ins2.exez',
            # 'i[.]haqo[.]net/i.png',
            # 'ii[.]haqo[.]net/u.png',
            # 'v[.]beahh[.]com/v',
            # '132[.]162[.]107[.]97/xmrig-32_1.mlz',
            # '139[.]162[.]107[.]97/h.bat',
        ],
        "ORG": ['VirusTotal', 'VirusTotal', 'IP', 'Trend Micro'],
        "DATE": ['January to February 2019', 'June 2019'],
        "DOMAIN":  [
            'gmzera54l5qpa6lm.onion',
            'gmzera54l5qpa6lm[.]onion',
            'de.gengine[.]com.de',
            'de.gsearch[.]com.de',
            'global.bitmex[.]com.de',
            'hmrc[.]covid[.]19-support-grant[.]com',
            'fund4-covid19[.]com',
            'furlough-grant[.]com',
            'fb.com',
            'paypal.com',
            'paypal.co.uk'
        ],
        "ORDINAL": ['first', 'second'],
        "MALWARE": [
            'Trojan.MacOS.GMERA.B',
            'TROJ_DLOADR.SULQ',
            'TROJ_DLOADR',
            'Win32.Virlock.A',
            'Win64.Virlock.A',
            'Angler',
            'Rig',
            'StuxNet',
            'Ascentor Loader',
            'GrandSoft',
        ],
        "IP": [
            '10.2.13.1',
            '192.168.2.14',
            '103[.]5.3.123',
            '63.234[.]34.2',
            '90.234.51[.]5',
            '9[.]9[.]9[.]9',
            '9{.}9{.}9{.}9',
            '2404:6800:4008:801::2004',
            '2600:1408:5c00:1a9::356e/64',
            '2600:1408:5c00:198::356e'
        ],
        "EMAIL": ['joey_costoya@trendmicro.com', 'joey.costoya@trendmicro.com'],
        "HASH": [
            '71cfd7d692a301ac9bff0e1e7605e7c2',
            '54efe3af6406673464eef89bb032f96e8b98bd16',
            'fa7fe0a7271b3b07ed4fdfa7a59298527f57f11511b6699bc80f9ded7f11ad06',
            '90f9fe128f01562b5d87565ac669cf8ff4883f07abf6a56ec074cc7a8b0f3411343ce8aef6fe07afb511ddc811ed06997a1a1e7c451303e390aff72753581615'
        ],
        "CVE": ['CVE-1999-2012', 'CVE-2004-0003', 'CVE-2021-26855', 'MS-10-017', 'MS16-017', 'APSB12-16', 'CVE-2019-1003000'],
        "INTRUSION_SET": ['CIRCUS SPIDER', 'Wolf Research'],
        "COUNTRY": [
            'Taiwan',
            'Philippines',
            'Czech Republic',
            'United States of America',
            'USA'
        ],
        "CITY": [
            'Taipei',
            'Manila',
            'Saint Petersburg',
            'The Hague',
            'Nukuʻalofa',
        ],
        "TOOL": [
            'TOR',
        ],
        'PRODUCT': [
            'Deep Discovery Inspector',
        ],
        'NORP': [
            'IPv6',                         # FIXME: not a NORP
        ],
        'GPE': [
            'taipei',                       # OK to be here.
            'manila',
            'san jose',
        ],
        'PERSON': [
            'Malware',                      # FIXME: not a person
        ],
    }

    def test_entity_extractor(self):

        doc = self.nlp(text)

        label_counts = Counter([ent.label_ for ent in doc.ents])

        for key in self.expected_results:
            print(f"{key} in extracted entity types")
            self.assertTrue(key in label_counts)

        for label in label_counts:
            if label not in self.expected_results:
                print(f'Unknown label: {label}')
                for ent in doc.ents:
                    if ent.label_ == label:
                        print(ent.label_, ent.text, sep='\t')
            print(f"expected {len(self.expected_results[label]):02} {label}: {self.expected_results[label]}")
            print(f"got      {len([ent.text for ent in doc.ents if ent.label_ == label]):02} {label}: {[ent.text for ent in doc.ents if ent.label_ == label]}")
            print()
            self.assertTrue(len(self.expected_results[label]) == label_counts[label])

        print("----------\n")

        for entity in doc.ents:
            print(f"expected: {entity.label_}: {self.expected_results[entity.label_]}")
            print(f"got:      {entity.label_}: {entity.text}")
            print()
            self.assertTrue( entity.text in self.expected_results[entity.label_] )


    def conditionals(self, text, expected_results):

        doc = self.nlp(text)
        label_counts = Counter([ent.label_ for ent in doc.ents])

        for key in expected_results:
            print(f"{key} in extracted entity types")
            self.assertTrue(key in label_counts)

        for label in label_counts:
            print(f"expected {len(expected_results[label]):02} {label}: {expected_results[label]}")
            print(f"got      {len([ent.text for ent in doc.ents if ent.label_ == label]):02} {label}: {[ent.text for ent in doc.ents if ent.label_ == label]}")
            print()
            self.assertTrue(len(expected_results[label]) == label_counts[label])

        print("----------\n")

        for entity in doc.ents:
            print(f"expected: {entity.label_}: {expected_results[entity.label_]}")
            print(f"got:      {entity.label_}: {entity.text}")
            print()
            self.assertTrue( entity.text in expected_results[entity.label_] )


    def test_extraction_malware(self):
        """Tests for extracting malware entities
        """

        text = """bunch of malware detection names:
detected as Trojan.MacOS.GMERA.B
TROJ_DLOADR.SULQ or TROJ_DLOADR
Win32.Virlock.A and Win64.Virlock.A
PUP/Win32.MyWebSearch.R133138
PUP.WebToolbar.MyWebSearch
W32.HfsAdware.1166
PUA.Mindsparki.Gen
FLSourcing.AMSI.AllPSDownload.src
OSX_REFOGKEYLOGGER.MSGKD15
FLSourcing.AMSI.PowershellDownload
HEUR_STATISTICS
FLSourcing.AMSI.ScriptExecution
BKDR_KILLAV.SMA
Trojan.HTML.PHISH.SMMR
Trojan.W97M.POWLOAD.SMRV08
TROJ_GEN.R002C0PEL21
HEUR_SWFOBF.B
PUA.Win32.HaoZip.C
PE_JEEFO.E
HackTool.Win32.RAdmin
HEUR_JS.O.ELBP
PE_SALITY.SM
PE_SALITY.SM-O
PE_PATCHED.ASA
StuxNet
Angler
Rig
"""
        expected_results = {
            "MALWARE": [
                'Trojan.MacOS.GMERA.B',
                'TROJ_DLOADR.SULQ',
                'TROJ_DLOADR',
                'Win32.Virlock.A',
                'Win64.Virlock.A',
                'PUP/Win32.MyWebSearch.R133138',
                'PUP.WebToolbar.MyWebSearch',
                'W32.HfsAdware.1166',
                'PUA.Mindsparki.Gen',
                'FLSourcing.AMSI.AllPSDownload.src',
                'OSX_REFOGKEYLOGGER.MSGKD15',
                'FLSourcing.AMSI.PowershellDownload',
                'HEUR_STATISTICS',
                'FLSourcing.AMSI.ScriptExecution',
                'BKDR_KILLAV.SMA',
                'Trojan.HTML.PHISH.SMMR',
                'Trojan.W97M.POWLOAD.SMRV08',
                'TROJ_GEN.R002C0PEL21',
                'HEUR_SWFOBF.B',
                'PUA.Win32.HaoZip.C',
                'PE_JEEFO.E',
                'HackTool.Win32.RAdmin',
                'HEUR_JS.O.ELBP',
                'PE_SALITY.SM',
                'PE_SALITY.SM-O',
                'PE_PATCHED.ASA',
                'StuxNet',
                'Angler',
                'Rig',
            ],
        }

        self.conditionals(text, expected_results)



    def test_extraction_domains(self):
        """Tests for extracting domain entities
        """

        text = """These are domains:
gmzera54l5qpa6lm.onion
gmzera54l5qpa6lm[.]onion
de.gengine[.]com.de
de.gsearch[.]com.de
global.bitmex[.]com.de
hmrc[.]covid[.]19-support-grant[.]com
fund4-covid19[.]com
furlough-grant[.]com
fb.com
paypal.com
paypal.co.uk
"""

        expected_results = {
            "DOMAIN":  [
                'gmzera54l5qpa6lm.onion',
                'gmzera54l5qpa6lm[.]onion',
                'de.gengine[.]com.de',
                'de.gsearch[.]com.de',
                'global.bitmex[.]com.de',
                'hmrc[.]covid[.]19-support-grant[.]com',
                'fund4-covid19[.]com',
                'furlough-grant[.]com',
                'fb.com',
                'paypal.com',
                'paypal.co.uk',
            ],
        }

        self.conditionals(text, expected_results)


    def test_extraction_negative(self):
        """Put text here that are not supposed to be extracted
        """

        text = """The following text should not be recognized as entities:
'PeNet.Structures.MetaDataTables
this.domain.does.not.exist
"""

        expected_results = []

        self.conditionals(text, expected_results)


    def test_mitre_attack_pattern(self):
        text = '''T1012 MALWARE : Query Registry
Command and Control T1573.002 MALWARE : Encrypted Channel
Payload transfer from remote host T1105 MALWARE : Ingress Tool Transfer
Payloads in modified RC4-encrypted chunks T1027.002 MALWARE : Obfuscated Files or Information: Software Packing'''
        expected_results = {
            "MITRE":  [
                'T1012',
                'T1573.002',
                'T1105',
                'T1027.002',
            ],
        }

        self.conditionals(text, expected_results)


if __name__ == "__main__":
    unittest.main()
