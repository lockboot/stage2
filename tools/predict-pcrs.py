#!/usr/bin/env python3
# Reproduce the PCRs our stage2 loader leaves for its payload -- the stage2 link of the
# verification path.
#
# Input: the previous stage's predicted PCRs (stage1's `pcrs.json`, from stage1's
# tools/predict-pcrs.py -- or any stage1 that leaves the same contract), and the exact config
# bytes stage1 hands stage2 on stdin. Output: the complete PCR state when the payload's /init
# starts, per bank. Every input PCR is carried through; only stage2's own event is appended:
#
#   PCR15  sha256 bank ONLY: TPM2_PCR_Extend with the raw digest sha256(config) (not re-hashed;
#          tpm-derive extend_config_pcr). Other banks' PCR15 are untouched by stage2.
#
# The config bytes are what stage2 actually reads: the user-data document verbatim when `_stage2`
# was admitted directly, or stage1's re-serialization of the manifest-merged document when it was
# resolved through a signed manifest. Pass those bytes; this tool does not re-derive them.
#
# PCR10 (IMA) also moves during this stage and is not predicted (stage2 does not bind it).
#
# The verifier never needs the config itself -- only its sha256, which the operator can disclose
# without revealing the contents (stage2 records it in /run/lockboot/stage2.attest). The hash hides
# the config only if it is not guessable: a config with no high-entropy field could be confirmed by
# hashing candidates, so include a random nonce if that matters.
#
# usage: predict-pcrs.py --prev pcrs.json (--config FILE | --config-sha256 HEX) [--out F] [--check LOG]
import argparse
import hashlib
import json
import re
import sys


def predict(prev, config_sha256, banks):
    out = {}
    for bank in banks:
        H = getattr(hashlib, bank)
        p = prev["pcrs"].get(bank)
        if p is None:
            raise SystemExit(f"input pcrs.json has no {bank} bank")
        p = {int(k): v for k, v in p.items()}
        zero = "00" * H().digest_size
        if bank == "sha256":
            p[15] = H(bytes.fromhex(p.get(15, zero)) + config_sha256).hexdigest()
        else:
            p.setdefault(15, zero)
        out[bank] = {str(k): v for k, v in sorted(p.items())}
    return {"pcrs": out}


def check(pred, log_path):
    with open(log_path, "rb") as f:
        txt = f.read().decode("latin1").replace("\r", "")
    seen = {(a, int(i)): v for a, i, v in
            re.findall(r"^(?:payload: )?PCR (\w+) (\d\d) ([0-9a-f]+)$", txt, re.M)}
    bad = 0
    for bank, pcrs in pred["pcrs"].items():
        for i, want in pcrs.items():
            got = seen.get((bank, int(i)))
            status = "ok" if got == want else ("MISSING" if got is None else "MISMATCH")
            bad += status != "ok"
            print(f"{bank:7} PCR{int(i):<2} {status:8} predicted {want[:16]}"
                  + ("" if status == "ok" or got is None else f"  read {got[:16]}"))
    print("ALL PREDICTED PCRS MATCH" if not bad else f"{bad} PREDICTED PCR(S) DO NOT MATCH")
    return bad == 0


def main():
    ap = argparse.ArgumentParser(description="Reproduce the PCRs after the stage2 loader")
    ap.add_argument("--prev", required=True, help="previous stage's pcrs.json (stage1's output)")
    cfg = ap.add_mutually_exclusive_group(required=True)
    cfg.add_argument("--config", help="the exact config bytes stage2 receives")
    cfg.add_argument("--config-sha256", help="or just their sha256 (what the operator discloses; "
                     "stage2 records it in /run/lockboot/stage2.attest)")
    ap.add_argument("--banks", default="sha256,sha384", help="comma-separated (default sha256,sha384)")
    ap.add_argument("--out", help="write JSON here (default stdout)")
    ap.add_argument("--check", metavar="LOG", help="compare against a serial log's PCR dump")
    a = ap.parse_args()
    with open(a.prev) as f:
        prev = json.load(f)
    if a.config:
        with open(a.config, "rb") as f:
            digest = hashlib.sha256(f.read()).digest()
    else:
        digest = bytes.fromhex(a.config_sha256)
    pred = predict(prev, digest, a.banks.split(","))
    if a.check:
        sys.exit(0 if check(pred, a.check) else 1)
    js = json.dumps(pred, indent=2) + "\n"
    if a.out:
        with open(a.out, "w") as f:
            f.write(js)
    else:
        sys.stdout.write(js)


if __name__ == "__main__":
    main()
