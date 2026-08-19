#!/usr/bin/env python3
"""Render a Trivy JSON report as Markdown, grouped by the image layer that
introduced each finding, with the fix for that layer.

Env: REPORT_JSON, REPORT_TARGET, REPORT_SEVERITY, REPORT_EXIT_CODE, REPORT_MD, REPORT_MAX_ROWS.
Exits 1 on findings (unless REPORT_EXIT_CODE=0) and always on an unreadable report.
"""
import json, os, sys

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
FIX = {"alpine": "apk add --no-cache --upgrade {spec}",
       "debian": "apt-get update && apt-get install -y --only-upgrade {spec}",
       "ubuntu": "apt-get update && apt-get install -y --only-upgrade {spec}",
       "python-pkg": "pin in requirements.txt -> {spec}",
       "node-pkg": "bump in package.json and commit the lockfile -> {spec}"}
MAX = int(os.getenv("REPORT_MAX_ROWS") or "25")

cell = lambda v: str(v if v is not None else "").replace("|", "\\|").replace("\n", " ").strip()
rank = lambda s: SEV.index(s) if s in SEV else len(SEV)
plural = lambda n: "" if n == 1 else "s"


def layers(report):
    """DiffID -> (position, Dockerfile instruction) from the image config history."""
    cfg = (report.get("Metadata") or {}).get("ImageConfig") or {}
    diffs = (cfg.get("rootfs") or {}).get("diff_ids") or []
    steps = [h for h in (cfg.get("history") or []) if not h.get("empty_layer")]
    out = {}
    for i, d in enumerate(diffs):
        by = (steps[i].get("created_by") if i < len(steps) else "") or ""
        by = by.replace("/bin/sh -c #(nop) ", "").replace("/bin/sh -c ", "RUN ")
        out[d] = (i + 1, " ".join(by.split())[:150] or "(no recorded instruction)")
    return out


def fix_hint(pkg_type, rows):
    """Concrete remediation for one layer's fixable packages."""
    fixable = sorted({r["pkg"]: r for r in rows if r["fixed"]}.values(), key=lambda r: r["pkg"])
    if not fixable:
        return ("No fixed version is published yet. Track upstream, or add a `.trivyignore` "
                "entry with an expiry date if the risk is accepted.")
    spec = " ".join(f"{r['pkg']}>={r['fixed']}" for r in fixable[:6])
    tmpl = FIX.get(pkg_type, "upgrade -> {spec}")
    more = f" (+{len(fixable) - 6} more)" if len(fixable) > 6 else ""
    return f"`{tmpl.format(spec=spec)}`{more}"


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows[:MAX]]
    if len(rows) > MAX:
        out.append(f"\n_Showing {MAX} of {len(rows)}. Full detail in the run artifact._")
    return "\n".join(out)


def main():
    path = os.getenv("REPORT_JSON") or "trivy-results.json"
    target = os.getenv("REPORT_TARGET") or "target"
    sevs = os.getenv("REPORT_SEVERITY") or "CRITICAL,HIGH"
    summary = os.getenv("GITHUB_STEP_SUMMARY")

    try:
        report = json.load(open(path))
    except (OSError, ValueError) as e:
        # Never render as "clean": a scan that did not run must not look like a
        # scan that found nothing.
        md = (f"## Trivy scan - `{target}`\n\n**Scan produced no usable report.** "
              f"Could not read `{path}`: {e}\n\nTreat this as a failed scan.\n")
        if summary: open(summary, "a").write(md)
        print(md, file=sys.stderr)
        return 1

    lmap = layers(report)
    groups, extras = {}, []
    for res in report.get("Results") or []:
        ptype = res.get("Type") or ""
        for v in res.get("Vulnerabilities") or []:
            diff = (v.get("Layer") or {}).get("DiffID") or ""
            pos, instr = lmap.get(diff, (0, "not attributed to a layer"))
            groups.setdefault((pos, instr, ptype), []).append(
                {"pkg": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                 "fixed": v.get("FixedVersion"), "sev": (v.get("Severity") or "UNKNOWN").upper(),
                 "id": v.get("VulnerabilityID"), "url": v.get("PrimaryURL")})
        for s in res.get("Secrets") or []:
            extras.append(("Secret", (s.get("Severity") or "UNKNOWN").upper(),
                           res.get("Target"), s.get("RuleID") or s.get("Title"), ""))
        for m in res.get("Misconfigurations") or []:
            extras.append(("Misconfig", (m.get("Severity") or "UNKNOWN").upper(),
                           res.get("Target"), m.get("Title"), m.get("Resolution")))

    vulns = [r for rows in groups.values() for r in rows]
    total = len(vulns) + len(extras)
    counts = {}
    for s in [r["sev"] for r in vulns] + [e[1] for e in extras]:
        counts[s] = counts.get(s, 0) + 1
    fixable = sum(1 for r in vulns if r["fixed"])

    md = [f"## Trivy scan - `{target}`", ""]
    if not total:
        md.append(f"**Clean** - no {sevs} findings.")
    else:
        breakdown = ", ".join(f"{counts[s]} {s.lower()}" for s in SEV if counts.get(s))
        md.append(f"**{total} finding{plural(total)}** - {breakdown}. "
                  f"{fixable} of {len(vulns)} vulnerabilities have a published fix.")
        md.append("")
        md.append("Findings are grouped by the image layer that introduced them, so a fix "
                  "goes into the layer named in the heading.")

    for (pos, instr, ptype), rows in sorted(
            groups.items(), key=lambda kv: (min(rank(r["sev"]) for r in kv[1]), kv[0][0])):
        rows.sort(key=lambda r: (rank(r["sev"]), str(r["pkg"])))
        nfix = sum(1 for r in rows if r["fixed"])
        md += ["", f"### Layer {pos} - `{cell(instr)}`",
               f"{len(rows)} finding{plural(len(rows))} - {nfix} fixable" +
               (f" - `{ptype}` packages" if ptype else ""), "",
               table(["Package", "Installed", "Fixed in", "Severity", "ID"],
                     [[f"`{cell(r['pkg'])}`", cell(r["installed"]), cell(r["fixed"]) or "_none yet_",
                       r["sev"], f"[{cell(r['id'])}]({r['url']})" if r.get("url") else cell(r["id"])]
                      for r in rows]),
               "", f"**Fix:** {fix_hint(ptype, rows)}"]

    if extras:
        extras.sort(key=lambda e: rank(e[1]))
        md += ["", "### Secrets and misconfigurations", "",
               table(["Kind", "Severity", "Target", "Finding", "Resolution"],
                     [[e[0], e[1], f"`{cell(e[2])}`", cell(e[3]), cell(e[4])] for e in extras])]

    out = "\n".join(md).rstrip() + "\n"
    if os.getenv("REPORT_MD"):
        open(os.environ["REPORT_MD"], "w").write(out)
    if summary:
        open(summary, "a").write(out)
    if os.getenv("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
            fh.write(f"total={total}\nfixable={fixable}\n")
            for s in SEV:
                fh.write(f"{s.lower()}={counts.get(s, 0)}\n")
    print(out)
    return 1 if total and (os.getenv("REPORT_EXIT_CODE") or "1") != "0" else 0


if __name__ == "__main__":
    sys.exit(main())
