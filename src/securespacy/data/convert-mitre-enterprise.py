# Convert MITRE Enterprise ATT&CK techniques to text files, including
# campaigns.txt  intrusion_set.txt  malware-cased.txt  tools.txt

import json

mitre = json.load(open('./enterprise-attack-15.0.json'))
hx = {
        'campaign': {},
        'intrusion-set': {},
        'malware': {},
        'tool': {},
        }

for obj in mitre['objects']:
    if obj['type'] in hx:
        name = obj['name']
        external_id = obj['external_references'][0]['external_id']
        hx[obj['type']][name] = True
        for alias in obj.get('aliases', []) + obj.get('x_mitre_aliases', []):
            hx[obj['type']][alias] = True

for key in hx:
    with open(f'mitre-{key}.txt', 'w') as f:
        for name in sorted(hx[key]):
            f.write(name + '\n')
