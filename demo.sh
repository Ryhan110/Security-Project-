#!/usr/bin/env bash
# RationGuard demo: seed -> transactions -> verify (green) -> attack -> verify (red).
#
#   ./demo.sh                      the main story (tamper_transaction)
#   ./demo.sh delete_transaction   any script name from attacks/
#   ./demo.sh all                  every attack, each on a fresh database
#
# WARNING: this wipes and re-creates the local demo database and anchor file.
set -euo pipefail
cd "$(dirname "$0")"

BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; RESET=$'\033[0m'
step() { echo; echo "${BOLD}=== $* ===${RESET}"; }

DB_ATTACKS="tamper_transaction delete_transaction tamper_and_recompute_hash tamper_audit_log reorder_transactions truncate_log_tail insert_ghost_transaction"
APP_ATTACKS="idor_attempt self_approve_change"

run_story() {
  local attack="$1"
  if [[ ! -f "attacks/${attack}.py" ]]; then
    echo "Unknown attack '${attack}'. Choose from: ${DB_ATTACKS} ${APP_ATTACKS}"; exit 2
  fi

  echo; echo "${BOLD}################  DEMO: ${attack}  ################${RESET}"

  step "1. Fresh database with fictional households"
  python -m rationguard reset --yes
  python -m rationguard seed

  step "2. A dealer records three distributions (through the real app)"
  python scripts/demo_issue.py dealer1 HH-000101 rice 5
  python scripts/demo_issue.py dealer1 HH-000104 wheat 3
  python scripts/demo_issue.py dealer1 HH-000107 sugar 2
  python -m rationguard anchor

  step "3. Verification BEFORE the attack (expected: all green)"
  local before_status=0
  python -m rationguard verify || before_status=$?
  echo; echo "  Transactions table BEFORE:"
  python scripts/show_state.py

  step "4. ATTACK: ${attack}"
  python "attacks/${attack}.py"

  step "5. Verification AFTER the attack"
  local after_status=0
  python -m rationguard verify || after_status=$?
  echo; echo "  Transactions table AFTER:"
  python scripts/show_state.py

  step "6. Alerts for the auditor"
  python -m rationguard alerts

  step "7. Before / after summary"
  if [[ " ${APP_ATTACKS} " == *" ${attack} "* && "${attack}" == "idor_attempt" ]]; then
    echo "  This attack went through the app and was BLOCKED (HTTP 403), so no data changed."
    echo "  before: verify exit code ${before_status} (0 = green)   after: verify exit code ${after_status}"
    [[ ${before_status} -eq 0 && ${after_status} -eq 0 ]] \
      && echo "  ${GREEN}OK: blocked and logged; integrity still green.${RESET}" \
      || { echo "  ${RED}UNEXPECTED RESULT${RESET}"; exit 1; }
  else
    echo "  before the attack: verify exit code ${before_status}  -> $([[ ${before_status} -eq 0 ]] && echo "${GREEN}GREEN${RESET}" || echo "${RED}RED${RESET}")"
    echo "  after  the attack: verify exit code ${after_status}  -> $([[ ${after_status} -eq 0 ]] && echo "${GREEN}GREEN${RESET}" || echo "${RED}RED (tampering detected)${RESET}")"
    [[ ${before_status} -eq 0 && ${after_status} -eq 1 ]] \
      && echo "  ${GREEN}OK: the attack was detected. See the finding above for the exact record and field.${RESET}" \
      || { echo "  ${RED}UNEXPECTED RESULT${RESET}"; exit 1; }
  fi
}

# Keys are generated locally on first run; they are never committed.
if [[ ! -f .env ]]; then
  step "0. First run: generating local keys"
  python scripts/setup_keys.py
fi

target="${1:-tamper_transaction}"
if [[ "${target}" == "all" ]]; then
  for attack in ${DB_ATTACKS} ${APP_ATTACKS}; do run_story "${attack}"; done
  echo; echo "${GREEN}${BOLD}All attack stories ran as expected.${RESET}"
else
  run_story "${target}"
fi
