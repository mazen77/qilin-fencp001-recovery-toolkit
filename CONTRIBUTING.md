# Contributing

Contributions that improve defensive recovery are welcome.

Please include:

1. a clear description of the Qilin/container generation;
2. hashes and metadata rather than sensitive victim data;
3. reproducible tests using synthetic fixtures;
4. a distinction between verified, profile-derived and heuristic recovery;
5. no live malware, stolen credentials or private victim data.

Run tests before submitting:

```bash
python3 -m unittest discover -s tests -v
```
