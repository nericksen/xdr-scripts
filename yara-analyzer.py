import yara
import os
import requests

#rules = yara.compile(source='rule foo: bar {strings: $a = "lmn" condition: $a}')

#RULES_URL = 'http://10.0.0.66:8090/rules.txt'

def get_yara_rules(rules_url):
  res = requests.get(rules_url)
  return yara.compile(source=res.text)

def run(path, rules_url):
  path = os.path.expanduser(path)
  path = os.path.expandvars(path)
  results = []

  rules = get_yara_rules(rules_url)

  if not os.path.exists(path):
    return f'No file found at {path}'
  if os.path.isdir(path):
    # All files in given path (exclude sub dirs)
    files = [f for f in os.listdir(path) if not os.path.isdir(f)] 
    for tmp in files:
      try:
        full_path = os.path.join(path,tmp)
        with open(full_path) as tmp_file:
          match = rules.match(data=tmp_file.read())
          if match[0].rule:
            results.append(f"{full_path}")
      except:
        print('Something went wrong, call someone...')
    return results
  else: 
    # Single file analysis
    with open(path) as f:
      matches = rules.match(data=f.read())

    return matches[0].rule
