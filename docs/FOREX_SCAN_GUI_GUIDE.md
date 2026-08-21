# FOREX SCAN GUI operator guide

Install offline from an approved wheelhouse with `pip install --no-index
--find-links WHEELHOUSE '.[ui]'`. Rich is pinned to 15.0.0 and remains an optional
extra; importing and running the scanner core does not start the GUI.

Run `python3 src/main.py ui --once` or omit `--once` for bounded refresh. Views:
overview, assets, endpoints, findings, changes, coverage, history and runtime.
Titles and borders use DarkYellow `#808000`; primary information uses yellow;
secondary text uses grey62/bright_black. `NO_COLOR` disables ANSI color.

Refresh is read-only and retains the last valid state as STALE after failure.
PLAN must precede START with the exact same request. Actions call only
`FOREXSCANWorkflow`; the UI contains no scanner, probe, finding or risk logic.
