import unittest
from securespacy.flair import SecureSpacyFlairWrapper

class TestFlairWrapper(unittest.TestCase):
    def setUp(self):
        self.wrapper = SecureSpacyFlairWrapper()

    def test_wrapper(self):
        text = '''
    However, at the time of writing, we were unable to decrypt this file since the upload URL https://appstockfolio.com/panel/upload.com
    was inaccessible (according to VirusTotal, the domain was active from January to February 2019). Furthermore, we suspect that the full
    malware routine uses the TOR network due to the presence of the unused address gmzera54l5qpa6lm.onion.\nUsing the digital certificate
    of the first sample, we were able to find a second variant (detected as Trojan.MacOS.GMERA.B) that was uploaded to VirusTotal on June
    2019.\n This IP address 10.2.13.1 is from the local network. It connects to the IP address 192.168.2.14.\nAnother is a new loader called
    “Ascentor Loader” (TROJ_DLOADR.SULQ or TROJ_DLOADR), used by GrandSoft’s customers.
    '''
        sentence = self.wrapper.flair_sentence(text)
        self.assertEqual(len(sentence), 132)
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

    def test_three_labels(self):
        text = 'This is dubbed as Operation Poison Needle.'
        sentence = self.wrapper.flair_sentence(text)
        self.assertEqual(sentence[4].get_tag('ner').value, 'B-CAMPAIGN')
        self.assertEqual(sentence[5].get_tag('ner').value, 'I-CAMPAIGN')
        self.assertEqual(sentence[6].get_tag('ner').value, 'E-CAMPAIGN')

if __name__ == "__main__":
    unittest.main()
