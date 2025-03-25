import re

f = open("script.au3", "r")

# Decrypts all encoded strings which use the 'RANGECOMING' function
def decrypt_str(text):
    pattern = r"RANGECOMING\s?\(\s?\"(.+?)\"\s?,\s?(.+?)\s?\)"

    def decryptor(m):
        s = m.group(1)
        i = m.group(2)
        try:
            v = eval(i) & 0xFFFFFFFF
        except:
            return "unable-to-decrypt"
        chars = s.split("-")
        chars = [chr(int(c) - v) for c in chars]
        return f"\"{''.join(chars)}\""

    return re.sub(pattern, decryptor, text)

newlines = []
for l in f.readlines():
    newlines.append(decrypt_str(l))

n = open("script_strdec.au3", "w")
n.writelines(newlines)
n.close()
f.close()

