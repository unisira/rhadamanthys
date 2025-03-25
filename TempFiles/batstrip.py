import re

f = open("Spare.wmv.bat", "r")
n = open("Spare.wmv.stripped.bat", "w")
new_lines = []

substitutions = {}

def parse_assignment(statement):
    pattern = r"^Set\s+(\w+)\s*=\s*(.+)$"
    match = re.match(pattern, statement)
    
    if match:
        variable_name = match.group(1)
        value = match.group(2)
        return variable_name, value
    else:
        return None

def apply_substitutions(text):
    pattern = r"%([^%]+)%"

    def worker(match):
        key = match.group(1)
        return substitutions.get(key, match.group(0))

    return re.sub(pattern, worker, text)

for l in f.readlines():
    l = apply_substitutions(l)
    s = parse_assignment(l)
    if s != None:
        variable_name, value = s
        substitutions[variable_name] = value
    new_lines.append(l)

n.writelines(new_lines)
f.close()
n.close()