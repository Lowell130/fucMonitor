"""Command line entry point, handy for one-off runs inside the container.

    python -m app.cli ingest            # all sources
    python -m app.cli ingest kev
    python -m app.cli backfill-epss 2026-10-01 2026-10-31
    python -m app.cli backfill-epss 2021-04-14 2025-11-01 --step 7
"""

import argparse
import sys
from datetime import date

from . import runner
from .config import get_settings
from .sources import SOURCES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fucmonitor")
    sub = parser.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("ingest", help="Download today's snapshot")
    ingest.add_argument("source", nargs="?", choices=sorted(SOURCES))
    backfill = sub.add_parser("backfill-epss", help="Download historical EPSS days")
    backfill.add_argument("start", type=date.fromisoformat)
    backfill.add_argument("end", type=date.fromisoformat)
    backfill.add_argument("--step", type=int, default=1, help="Days between files: 1 daily, 7 weekly")
    exp = sub.add_parser("epss-experiment", help="Walk-forward CVE-level vs EPSS comparison")
    exp.add_argument("--horizon", type=int, default=30, help="Outcome window in days: 30, 7 or 90")
    exp.add_argument("--json", action="store_true", help="Print the full result as JSON")
    args = parser.parse_args(argv)

    settings = get_settings()
    failed = False
    if args.command == "ingest":
        for name in [args.source] if args.source else list(SOURCES):
            run = runner.run_source(settings, name, "cli")
            print(f"{name}: {run['status']} {run.get('snapshot_date') or ''} {run.get('message') or ''}")
            failed |= run["status"] != "success"
    elif args.command == "backfill-epss":
        have = set(SOURCES["epss"].snapshot_dates(settings))
        for n in range(args.start.toordinal(), args.end.toordinal() + 1, max(1, args.step)):
            day = date.fromordinal(n)
            if day in have:
                continue
            run = runner.run_source(settings, "epss", "backfill", backfill_day=day)
            print(f"epss {day}: {run['status']} {run.get('message') or ''}")
            failed |= run["status"] != "success"
    elif args.command == "epss-experiment":
        import json as _json

        from .analysis import epss_experiment

        out = epss_experiment.run(settings, horizon=args.horizon)
        if args.json:
            print(_json.dumps(out, indent=2))
        else:
            _print_experiment(out)
    return 1 if failed else 0


def _print_experiment(out: dict) -> None:
    from .analysis import epss_experiment

    wf = out["walk_forward"]
    print(f"\nTarget: {out['target']}")
    print(f"  ({out['target_note']})")
    print(f"Walk-forward: {wf['test_dates']} monthly dates {wf['first']}..{wf['last']}, "
          f"{wf['rows']:,} examples, {wf['positives']} positives (prevalence {wf['prevalence']:.2e})")
    print(f"  eval-date gaps (days): {wf['eval_gap_days']}  vs horizon {out['horizon_days']}")
    print(f"\n{'model':12}{'ROCpool':>9}{'ROCin-day':>10}{'PR-AUC':>9}{'Brier':>11}{'BSSvsBase':>11}{'ECE':>9}")
    for m in epss_experiment.MODELS:
        r = out["models"][m]
        rp = f"{r['roc_auc_pooled']:9.3f}" if "roc_auc_pooled" in r else f"{'-':>9}"
        rw = f"{r['roc_auc_within_date_mean']:10.3f}" if "roc_auc_within_date_mean" in r else f"{'-':>10}"
        pr = f"{r['pr_auc']:9.4f}" if "pr_auc" in r else f"{'-':>9}"
        ec = f"{r['ece']:9.4f}" if "ece" in r else f"{'-':>9}"
        print(f"{m:12}{rp}{rw}{pr}{r['brier']:11.6f}{r['brier_skill_vs_base_rate']:11.4f}{ec}")
    print("\nContribution of each feature (within-date ROC-AUC mean):")
    for m in ("raw_epss", "epss_platt", "epss_age", "epss_trend", "feat_model"):
        print(f"  {m:12} {out['models'][m]['roc_auc_within_date_mean']:.3f}")
    print("\nROC-AUC by year (each year = a separate temporal evaluation):")
    for yy, v in out["roc_auc_by_year"].items():
        print(f"  {yy}: dates={v['test_dates']:2d} pos={v['positives']:3d}  raw={v['raw_epss']:.3f}  "
              f"recal={v['epss_platt']:.3f}  +age={v['epss_age']:.3f}  +trend={v['epss_trend']:.3f}  "
              f"feat={v['feat_model']:.3f}")
    print("\nPrecision/recall at fixed alert budgets per day:")
    for b, d in out["precision_recall_by_budget_per_day"].items():
        print(f"  budget {b}/day:")
        for m in ("raw_epss", "feat_model"):
            x = d[m]
            print(f"    {m:12} prec={x['precision']:.3f} recall={x['recall']:.3f} "
                  f"tp={x['tp']} lead_median={x['lead_median']}")
    print(f"\n{out['repeated_cves_and_overlap']}")
    print(f"\nVerdict: {out['verdict']}")
    print("\nLimits:")
    for lim in out["limits"]:
        print(f"  - {lim}")


if __name__ == "__main__":
    sys.exit(main())
