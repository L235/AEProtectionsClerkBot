# Design: Community Sanctions (GS) Pipeline

**Issue:** #5 — expand to cover CCTOPs and community ECRs
**Date:** 2026-03-26
**Approach:** Dual-pipeline (Approach A)

## Overview

Add a second parallel pipeline for community sanctions (General Sanctions / GS) alongside the existing AE pipeline. Both pipelines share core infrastructure (entry formatting, page updating, dedup) but have independent filtering, topic detection, and target page configuration.

Covers all three types of community-authorised sanctions:
- Community-designated contentious topics (CCTOPs)
- Extended confirmed restrictions (ECRs)
- Page-protection-only sanctions (e.g., Beauty Pageants)

## Data from live Wikipedia

Analysis of 5000 recent protect log events:
- **707** match AE keywords only
- **28** match GS keywords only
- **68** match both (71% of all GS-related events)

The dominant dual-match pattern is admins citing both authorities: `[[WP:CT/KURD]]/[[WP:GS/KURD]]`. This is common for topics like Kurds and Armenia-Azerbaijan that have both an ArbCom CTOP and a community GS.

## Configuration

### New environment variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `CLERKBOT_GS_TARGET_PAGE` | No | `""` (disabled) | Target page for GS entries. Empty = GS pipeline skipped. |
| `CLERKBOT_GS_NOTIFY_ADMINS` | No | `"false"` | Notification mode for GS. Defaults to disabled. |
| `CLERKBOT_GS_NOTIFICATIONS_DRYRUN_PAGE` | No | `{GS_TARGET_PAGE}/notifications_dryrun` | Debug notification page for GS. |
| `CLERKBOT_GS_NOTIFY_TEMPLATE` | No | `""` | Reserved for future separate notification template (#19). |

The GS pipeline is enabled when `gs_target_page` is non-empty.

### On-wiki config.json changes

Three new keys added to `User:ClerkBot/T3/config.json` alongside existing AE keys:

```json
{
  "codes": ["ap", "blp", ...],
  "specific_pages": { ... },
  "override_strings": { ... },
  "gs_codes": ["scw&isil", "crypto", "pw", "mj", "pageant", "rusukr", "uyghur", "aa", "kurd", "acas", "we"],
  "gs_specific_pages": {
    "Wikipedia:General sanctions/Syrian Civil War and Islamic State of Iraq and the Levant": "scw&isil",
    "Wikipedia:General sanctions/Blockchain and cryptocurrencies": "crypto",
    "Wikipedia:General sanctions/Professional wrestling": "pw",
    "Wikipedia:General sanctions/Michael Jackson": "mj",
    "Wikipedia:General sanctions/Armenia and Azerbaijan": "aa",
    "Wikipedia:General sanctions/Kurds and Kurdistan": "kurd",
    "Wikipedia:General sanctions/Assyrian, Chaldean, Aramean and Syriac topics": "acas",
    "Wikipedia:General sanctions/Weather events": "we"
  },
  "gs_override_strings": {
    "gs/scw": "scw&isil",
    "gs/isil": "scw&isil",
    "gs/crypto": "crypto",
    "gs/pw": "pw",
    "gs/mj": "mj",
    "gs/pageant": "pageant",
    "gs/rusukr": "rusukr",
    "gs/uyghur": "uyghur",
    "gs/aa": "aa",
    "gs/kurd": "kurd",
    "gs/acas": "acas",
    "ct/we": "we"
  }
}
```

The bot gracefully handles absence of these keys (GS topic detection returns empty strings).

## Filtering

### New trigger phrases in `filters.py`

```python
GS_TRIGGERS = [
    "general sanction",
    "community sanction",
    "community-designated contentious topic",
    "wp:gs/",
    "wikipedia:gs/",
    "wp:gs|",
    "wikipedia:gs|",
    "wp:gs]",
    "wikipedia:gs]",
    "wikipedia:general sanctions/",
]
```

`is_arbitration_enforcement()` is unchanged. `is_community_sanction()` is a new parallel function.

### Dedup behavior for dual-match events

Events matching both filters (71% of GS events) are handled by logid-based dedup:
- **Separate pages:** Event appears on both logs (correct — it is both an AE and GS action).
- **Same page:** AE pipeline runs first and logs it; GS pipeline sees it via `existing_logids` and skips.

No special mutual-exclusion logic needed.

## Topic Detection

No changes to the `TopicDetector` class. `load_topics()` creates two instances from the same JSON:
- AE detector: uses `codes`, `specific_pages`, `override_strings`
- GS detector: uses `gs_codes`, `gs_specific_pages`, `gs_override_strings`

`WP:GS/<code>` shortcuts are handled via `gs_override_strings` (e.g., `"gs/kurd": "kurd"`) rather than adding a new regex heuristic to the class.

## Bot Orchestration

### `_run_pipeline()` helper

Extract pipeline logic into a reusable function:

```python
def _run_pipeline(
    site, detector, filter_fn, target_page,
    notify_mode, dryrun_page, bot_usernames, config
) -> int:
    """Run one pipeline (AE or GS). Returns 0 on success, nonzero on error."""
```

### `main()` flow

```
main()
├── load config from env
├── load merged topic config → ae_detector, gs_detector
├── connect to Wikipedia
├── fetch bot usernames (shared)
│
├── AE pipeline (always runs)
│   └── _run_pipeline(ae_detector, is_arbitration_enforcement, ...)
│
├── GS pipeline (only if gs_target_page is set)
│   └── _run_pipeline(gs_detector, is_community_sanction, ...)
│
└── return 0
```

Both pipelines independently call `enumerate_protect_logevents()` and `enumerate_stable_logevents()`. The API calls happen twice — slightly redundant but keeps pipelines independent and avoids caching complexity. The GS pipeline re-fetches its target page after AE saves, so it sees fresh content (important for the shared-page case).

## Entry Format

Both pipelines use `{{User:ClerkBot/AE entry}}`. No new template.

## Notifications

GS notifications default to disabled (`CLERKBOT_GS_NOTIFY_ADMINS=false`). A separate notification template is tracked in #19.

## Testing

1. **`test_filters.py`** — `is_community_sanction()`: matches GS triggers, rejects unrelated comments, no false positives from substrings like "recreated" containing "ecr".
2. **`test_topic.py`** — GS `TopicDetector`: override strings, specific pages, bare codes.
3. **`test_config.py`** — GS config fields: defaults, pipeline skip when empty.
4. **`test_bot.py`** — `_run_pipeline()` and dual-pipeline orchestration: AE-only, GS-only, dual-match (separate pages), dual-match (shared page), GS skipped when unconfigured.

Existing AE tests are unchanged.

## Not in scope

- Separate GS notification template (#19)
- Separate entry template
- Unified pipeline refactor (Approach B) — future work
- On-wiki config.json edits — manual step after deploy
- Year-month log suffix (#2)
- Lua module / CSS filtering (#18)

## Future: migrating to Approach B

When the time comes to unify into a single pipeline:
1. Merge filter functions into one returning a source tag (`"ae"` / `"gs"` / `None`)
2. Collapse two `_run_pipeline` calls into one pass bucketing entries by source
3. Route entries to target pages by source tag

Estimated effort: half-day refactor. Nothing in Approach A prevents this.
