# Dataset provenance

## Submitted hybrid training set

`hybrid_emails_dataset.csv` contains 2,501 records:

- 1,301 real labelled ham/spam messages parsed from the Apache SpamAssassin Public Corpus.
- 1,200 synthetic records used only for phishing, BEC and malware scenario coverage.

The real corpus is included as the derived, feature-ready file `real_spamassassin.csv`; it was downloaded by `download_real_corpus.py` from these Apache corpus archives:

- `20030228_easy_ham.tar.bz2` — legitimate/ham
- `20030228_spam.tar.bz2` — spam

Source: https://spamassassin.apache.org/old/publiccorpus/

## Reproducibility

```bash
python data/download_real_corpus.py
python data/build_hybrid_dataset.py
python src/train.py
```

The report describes the evaluation as hybrid. It must not be described as an independent real-world phishing, BEC, or malware benchmark.
