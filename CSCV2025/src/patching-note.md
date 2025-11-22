### Patching note

- Only patch files in `crypto/zkp`
- Submit a patch as a ZIP file in the following structure (unmodified files can be omitted):

  ```
  ---patch.zip
     |---crypto
         |---zkp
             |---hash.py
             |---mta.py
             |---affg.py
             |---enc.py
             |---fac.py
             |---logstar.py
             |---mod.py
             |---prm.py
             |---sch.py
  ```

- A patch file is invalid if one of the following occurs (including but not limited to):
    - The intended functionality or behaviour is changed.
    - The associated Cryptographic algorithms are changed.
    - The Levenshtein distance (from the original source file) exceeds **25**.

- Automatic checks can not be perfect. If you find out that a deployed patch is invalid, please report to us so that the patch can be manually taken down.

_Good luck and have fun!_