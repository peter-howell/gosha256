fname = "SHA256LongMsg.rsp"


with open(fname, "r") as f:
    lines = [l.strip() for l in f.readlines()]

messages = 0

i = 0
while i < len(lines):
    line = lines[i]
    if len(line) < 6:
        i += 1
        continue
    words = line.split()
    if words[0] == "Msg":
        msg = words[2]
        with open(f"messages/msg{messages}", "wb") as f:
            f.write(bytes.fromhex(msg))
        with open(f"hashes/hash{messages}", "w") as f:
            f.write(lines[i+1].split()[2])
        messages += 1
        i += 2
    else:
        i += 1

