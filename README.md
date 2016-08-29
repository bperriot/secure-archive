# Secure archive

This project is a proof-of-concept in early stage. It's absolutely not ready for production.

It's the specification and implemention of a secured archive file format, designed with backup applications in mind.
The archive must be protected against corruption (reed-solomon), compressed and encrypted. It must support file diff, arbitrary metadata (including file owner and permission) and links.

