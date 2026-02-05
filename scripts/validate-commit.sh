#!/bin/bash

COMMIT_MSG_FILE=$1
COMMIT_MSG=$(head -n1 "$COMMIT_MSG_FILE")

TYPES="feat fix docs style refactor perf test build ci chore revert"
SCOPES="farm hub pkg infra deps tests"
TYPES_REGEX="${ALLOWED_TYPES// /|}"
SCOPES_REGEX="${ALLOWED_SCOPES// /|}"
REGEX="^($TYPES_REGEX)(\(($SCOPES_REGEX)\))?: .+$"

if [[ ! $COMMIT_MSG =~ $REGEX ]]; then
  echo "x  Error: Invalid Commit Message Format"
  echo "----------------------------------------------------"
  echo "   Your message: \"$COMMIT_MSG\""
  echo ""
  echo "   Format:      <type>(<scope>): <subject>"
  echo "   Example:     feat(farm): add moisture sensor driver"
  echo ""
  echo "   [Allowed Types]"
  echo "   $ALLOWED_TYPES"
  echo ""
  echo "   [Allowed Scopes]"
  echo "   $ALLOWED_SCOPES"
  echo "----------------------------------------------------"
  exit 1
fi
exit 0
