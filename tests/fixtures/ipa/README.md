# Shared IPA compatibility fixtures

These fixtures are synthetic and contain no third-party application code. `ipaview-contract.json`
records the stable JSON keys and rule behavior from IPAView's `IPAAuditCore`. Both IPAView and
ByteTrawl can consume this language-neutral contract when validating compatibility.

The executable fixtures are generated deterministically in tests from minimal Mach-O headers so
the suite covers thin arm64 and fat arm64+x86_64 without checking binary applications into Git.

