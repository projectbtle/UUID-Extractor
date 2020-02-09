# UUID Extractor
Androguard-based program slicing tool to extract UUIDs from APKs

## Usage
Navigate to `src` folder and execute:
```
usage: main_uuid.py [-h] [-f FILE] [-d DIR] [-a APK]

Extract UUIDs.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Get APK list from file. File must contain absolute paths to APKs.
  -d DIR, --dir DIR     Enumerate APKs in a directory. Argument must specify absolute path to directory.
  -a APK, --apk APK     Extract from a single APK.
  ```
