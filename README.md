# HVCI-loldrivers-check
Checks to see which drivers from loldrivers.io are not blocked by a certain HVCI blocklist.

### Requirements
* Powershell 6.0+

### Usage
```
.\check_allowed_drivers.ps1 -loldrivers_path <path to loldrivers JSON> -policy_path <path to policy XML>
```
* The loldrivers JSON file can be found here: https://www.loldrivers.io/
* To recover the HVCI driver policy you can use this script: https://gist.github.com/mattifestation/92e545bf1ee5b68eeb71d254cec2f78e

### Output
```
Allowed:
MD5: <hash> SHA1: <hash> SHA256: <hash>
MD5: <hash> SHA1: <hash> SHA256: <hash>
...

Maybe allowed:
MD5: <hash> SHA1: <hash> SHA256: <hash>
MD5: <hash> SHA1: <hash> SHA256: <hash>
...
```

All drivers have at least one of their MD5, SHA1, or SHA256 hashes available on loldrivers.io, but some of them have one or two of these missing.

The drivers outputted under "allowed" are drivers that do not match any of the criteria that the blocklist uses to determine which drivers are blocked.

The drivers outputted under "maybe allowed" are drivers that have a `FileAttribRef` that matches the drivers' `OriginalFileName` + `FileVersion`, but don't have an explcitly blocked TBS certificate (with the information available to us from the loldrivers json). 

Note: The script is limited to the information available in the loldrivers json. For example, the json does not include the SHA384 TBS hashes for the drivers, which are used in the blocklist.