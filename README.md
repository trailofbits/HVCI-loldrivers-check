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