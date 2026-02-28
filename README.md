# XWALL
Tools for supervising and system guarding

```
hkey = HKEY.HKEY_ROOT() 
found = [] 
for k ib hkey.walk():
    if "word" in k.name:
        found.append(k)
    if isinstance(k, EKEY) and "word" in k.name.lower():
        found.append(k)

for k in found:
    confirmed = input(f"Delete key '{k.name}'?")
    if confirmed =="y":
        k.delete(preview = False)
```

