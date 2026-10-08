# Red Team Space CTF: patch submissions

This repository is a target in the Red Team Space CTF "Secure Development" game (Oct 7–9, 2026): find a vulnerability in one of the training apps, patch it, and get it scored by opening a pull request. Rules: https://ctf.redteamspace.team/rules

The targets live in the `redteamspace-ctf` GitHub org: `DVWA`, `juice-shop`, `VulnerableApp`, `WebGoat`, `SecurityShepherd`, `VAmPI`. Each has a `ctf` branch with the scoring workflow (`.github/workflows/ctf-score.yml`).

## Submitting a patch (read before opening any PR)

- Compete as the GitHub account **noeltalit**. Points credit the PR author, so `gh` must be on noeltalit: check with `gh auth status`, switch with `gh auth switch -u noeltalit`. Never submit from noeltri-NX.
- Work in the fork `noeltalit/<repo>` (a fork of `redteamspace-ctf/<repo>`), on a branch based on `ctf`.
- Open the PR **against the event repo's `ctf` branch, never inside the fork**:

  ```
  gh pr create --repo redteamspace-ctf/<repo> --base ctf --head noeltalit:<branch>
  ```

  A PR inside the fork (`noeltalit/<repo>` → `ctf`) is never scored. Either the fork's Actions don't run at all, or the scoring run fails at "Pull scorer image" with `denied` and the bot says "event setup problem". That message is misleading: the fork simply can't pull the private scorer image, nothing is wrong on the organizers' side, and the fix is to open the PR against `redteamspace-ctf/<repo>`. The leaderboard only reads PRs on the event repos.
- Every push to the PR branch re-scores it. There is a 5-minute cooldown, and spamming pushes to farm scoring runs can get the account rate-limited or disqualified, so push complete, tested batches.
- The score arrives as a github-actions comment on the PR. Only the `score` check matters; upstream CI that also runs (CodeQL, e2e, docker-test, ...) doesn't affect it.
- Don't attack or reverse-engineer the scoring pipeline (for example, don't pull the scorer image to read its tests) and don't publish solutions. Using AI is explicitly encouraged by the event.


## What the scorer looks for (observed on DVWA)

- It builds and boots the app, logs in by script, then runs every challenge's regression test in about 10 seconds. Keep login/setup flows working exactly as before and don't add sleeps or delays to request handlers.
- It judges HTTP behaviour as well as the exploit: a blocked request should still get a normal page (200 with a message). Answering with 404/500, or a bare error with no page, was scored as not patched; access-denied pages must really send 403.
- Patch every security level the app has (DVWA scores low, medium and high separately).

## Scored PRs (as of 2026-10-08)

| Target | PR | Branch |
| --- | --- | --- |
| DVWA | https://github.com/redteamspace-ctf/DVWA/pull/11 | `fix/patch-vulnerabilities` |
| juice-shop | https://github.com/redteamspace-ctf/juice-shop/pull/12 | `claude/adoring-cori-km8k9v` |
| VulnerableApp | https://github.com/redteamspace-ctf/VulnerableApp/pull/19 | `claude/keen-wozniak-3ilxyc` |
| SecurityShepherd | https://github.com/redteamspace-ctf/SecurityShepherd/pull/11 | `fix/patch-vulnerabilities` |
| VAmPI | https://github.com/redteamspace-ctf/VAmPI/pull/11 | `fix/patch-vulnerabilities` |
| WebGoat | https://github.com/redteamspace-ctf/WebGoat/pull/49 | `fix/patch-vulnerabilities` |

Keep pushing fixes to the same branch; that updates and re-scores the existing PR.
