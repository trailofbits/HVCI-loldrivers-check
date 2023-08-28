# HVCI-loldrivers-check
Checks to see which drivers from loldrivers.io are not blocked by the current HVCI blocklist on the system.

### Requirements
* Powershell 6.0+

### Usage
```
.\check_allowed_drivers.ps1
```
* The script will automatically pull the loldrivers JSON file which can be found here: https://www.loldrivers.io/
* The script will automatically parse the HVCI driver policy.
  If you'd like to extract the list yourself, you can use this script: https://gist.github.com/mattifestation/92e545bf1ee5b68eeb71d254cec2f78e

### Output
```
Number of blocked drivers: <number>
Number of allowed drivers: <number>

Allowed:
MD5: <hash> SHA1: <hash> SHA256: <hash>
MD5: <hash> SHA1: <hash> SHA256: <hash>
...
```

All drivers have at least one of their MD5, SHA1, or SHA256 hashes available on loldrivers.io, but some of them have one or two of these missing.

The drivers outputted under "allowed" are drivers that do not match any of the criteria that the blocklist uses to determine which drivers are blocked:
- Blocked by MD5, SHA1 or SHA256 of the file
- Blocked by a combination of Original File Name and signer, and in some cases also file version.
  The signer list uses the issuer of the intermediate signature and can be an MD5, SHA1, SHA256 or SHA384.
