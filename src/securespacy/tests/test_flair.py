import unittest
from flair.data import Sentence
from securespacy.flair import SecureSpacyFlairWrapper

class TestFlairWrapper(unittest.TestCase):
    text = '''
    However, at the time of writing, we were unable to decrypt this file since the upload URL https://appstockfolio.com/panel/upload.com
    was inaccessible (according to VirusTotal, the domain was active from January to February 2019). Furthermore, we suspect that the full
    malware routine uses the TOR network due to the presence of the unused address gmzera54l5qpa6lm.onion.\nUsing the digital certificate
    of the first sample, we were able to find a second variant (detected as Trojan.MacOS.GMERA.B) that was uploaded to VirusTotal on June
    2019.\n This IP address 10.2.13.1 is from the local network. It connects to the IP address 192.168.2.14.\nAnother is a new loader called
    “Ascentor Loader” (TROJ_DLOADR.SULQ or TROJ_DLOADR), used by GrandSoft’s customers.
    '''

    def setUp(self):
        self.wrapper = SecureSpacyFlairWrapper(force_regenerate=True)

    def test_tokenizer(self):
        sentence = Sentence(self.text, use_tokenizer=self.wrapper.tokenizer)
        self.assertEqual(len(sentence), 132)
        self.assertEqual(sentence[49].text, 'TOR')
        self.assertEqual(sentence[87].start_pos, 533)

    def test_phrase_matcher(self):
        sentence = Sentence(self.text, use_tokenizer=self.wrapper.tokenizer)
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence[19].get_tag('ner').value, 'S-URL')
        self.assertEqual(sentence[49].get_tag('ner').value, 'S-TOOL')
        self.assertEqual(sentence[59].get_tag('ner').value, 'S-DOMAIN')
        self.assertEqual(sentence[81].get_tag('ner').value, 'S-MALWARE')
        self.assertEqual(sentence[95].get_tag('ner').value, 'S-IP')
        self.assertEqual(sentence[108].get_tag('ner').value, 'S-IP')
        self.assertEqual(sentence[117].get_tag('ner').value, 'B-MALWARE')
        self.assertEqual(sentence[118].get_tag('ner').value, 'E-MALWARE')
        self.assertEqual(sentence[121].get_tag('ner').value, 'S-MALWARE')
        self.assertEqual(sentence[123].get_tag('ner').value, 'S-MALWARE')
        self.assertEqual(sentence[123].start_pos, 734)
        self.assertEqual(sentence[123].end_pos, 745)

    def test_phrase_matcher_2(self):
        from flair.models import SequenceTagger
        text = 'Although the identities and motivations of the actors behind the campaign have yet to be identified, we have found that the command-and-control (C&C) servers used in this campaign were located in four countries: Taiwan (43% of the servers), USA (36%), Hong Kong (14%) and the UAE (7%).'
        sentence = Sentence(text, use_tokenizer=self.wrapper.tokenizer)
        model = SequenceTagger.load('ner')
        model.predict(sentence)
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence[41].get_tag('ner').value, 'S-COUNTRY')
        self.assertEqual(sentence[50].get_tag('ner').value, 'S-COUNTRY')
        self.assertEqual(sentence[56].get_tag('ner').value, 'B-CITY')
        self.assertEqual(sentence[57].get_tag('ner').value, 'E-CITY')
        self.assertEqual(sentence[64].get_tag('ner').value, 'S-COUNTRY')

    def test_three_labels(self):
        text = 'This is dubbed as Operation Poison Needle.'
        sentence = Sentence(text, use_tokenizer=self.wrapper.tokenizer)
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence[4].get_tag('ner').value, 'B-CAMPAIGN')
        self.assertEqual(sentence[5].get_tag('ner').value, 'I-CAMPAIGN')
        self.assertEqual(sentence[6].get_tag('ner').value, 'E-CAMPAIGN')
        self.assertEqual(sentence.get_spans('ner')[0].start_pos, 18)
        self.assertEqual(sentence.get_spans('ner')[0].end_pos, 41)

    def test_emails(self):
        text = 'Test email address: abcd.efgh@gmail.com  myname+tag@gmail.com  ccc@ccc.de etc.'
        sentence = Sentence(text, use_tokenizer=self.wrapper.tokenizer)
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence[4].get_tag('ner').value, 'S-EMAIL')
        self.assertEqual(sentence[5].get_tag('ner').value, 'S-EMAIL')
        self.assertEqual(sentence[6].get_tag('ner').value, 'S-EMAIL')

    def test_corner_cases(self):
        text = 'St. Petersburg is a big city.'
        sentence = Sentence(text, use_tokenizer=self.wrapper.tokenizer)
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence.get_spans('ner')[0].start_pos, 0)
        self.assertEqual(sentence.get_spans('ner')[0].end_pos, 14)
        text = 'It is a script designed to run in RouterOS.'
        sentence = Sentence(text, use_tokenizer=self.wrapper.tokenizer)
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence[8].get_tag('ner').value, 'S-PRODUCT')
        text = 'Trend Micro™ Mobile Security to block threats that may leverage Dirty COW from app stores before they can be installed.'
        sentence = Sentence(text, use_tokenizer=self.wrapper.tokenizer)
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence.get_spans('ner')[1].labels[0].value, 'VULNERABILITY')
        text = 'Arid Viper was advanced; Advtravel was less so.'
        sentence = Sentence(text, use_tokenizer=self.wrapper.tokenizer)
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence.get_spans('ner')[0].labels[0].value, 'CAMPAIGN')
        self.assertEqual(sentence.get_spans('ner')[1].labels[0].value, 'CAMPAIGN')
        text = 'Uche and Okiki made use of the information they captured in looking for more opportunities to steal from their victims.'
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence.get_spans('ner')[0].labels[0].value, 'CAMPAIGN')
        self.assertEqual(sentence.get_spans('ner')[1].labels[0].value, 'CAMPAIGN')

    def test_org_product(self):
        text = 'Trend Micro endpoint solutions such as Trend Micro™ Security, Trend Micro™ Smart Protection Suites, and Trend Micro Worry-Free™ Business Security can protect users systems from SAMSAM crypto-ransomware by detecting the malicious files.'
        sentence = Sentence(text, use_tokenizer=self.wrapper.tokenizer)
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence.get_spans('ner')[0].labels[0].value, 'ORG')
        self.assertEqual(sentence.get_spans('ner')[1].labels[0].value, 'ORG')
        self.assertEqual(sentence.get_spans('ner')[2].labels[0].value, 'ORG')
        self.assertEqual(sentence.get_spans('ner')[3].labels[0].value, 'PRODUCT')
        self.assertEqual(sentence.get_spans('ner')[4].labels[0].value, 'ORG')
        self.assertEqual(sentence.get_spans('ner')[5].labels[0].value, 'PRODUCT')

    def test_longest_match(self):
        text = 'Trend Micro™ HouseCall™ for Home Networks and Deep Discovery™ Email Inspector and Vulnerability Protection employ Deep Packet Inspection (DPI) technology to inspect networking packets.'
        sentence = Sentence(text, use_tokenizer=self.wrapper.tokenizer)
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence.get_spans('ner')[1].text, 'HouseCall ™ for Home Networks')
        self.assertEqual(sentence.get_spans('ner')[2].text, 'Deep Discovery ™ Email Inspector')
        self.assertEqual(sentence.get_spans('ner')[3].text, 'Vulnerability Protection')
        text = 'Trend Micro™ OfficeScan™ with XGen™ endpoint security provides enterprise protection with Smart Protection Suites with XGen™ endpoint security.'
        sentence = Sentence(text, use_tokenizer=self.wrapper.tokenizer)
        self.wrapper.phrase_matcher(sentence)
        self.assertEqual(sentence.get_spans('ner')[1].text, 'OfficeScan ™ with XGen ™ endpoint security')
        self.assertEqual(sentence.get_spans('ner')[3].text, 'XGen ™ endpoint security')
        self.assertEqual(sentence.get_spans('ner')[3].start_pos, 119)
        self.assertEqual(sentence.get_spans('ner')[3].end_pos, 142)


if __name__ == "__main__":
    unittest.main()
