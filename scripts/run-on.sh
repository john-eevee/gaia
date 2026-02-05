#!/bin/bash
CMD="$@"

if [ -z "$CMD" ]; then
  echo "Usage: $0 <command>"
  exit 1
fi

FAILED=0

MODULE_DIRS=$(find . -name "go.mod" -not -path "*/vendor/*" -exec dirname {} \; | sort)

for DIR in $MODULE_DIRS; do
  # Run the command in a subshell so we don't need to 'cd ..' back
  (cd "$DIR" && $CMD)

  # Check exit code
  if [ $? -ne 0 ]; then
    echo "⨯ Failed in $DIR"
    FAILED=1
  else
    echo "✓ Success in $DIR"
  fi
  echo ""
done

if [ $FAILED -ne 0 ]; then
  echo "⨯ One or more modules failed."
  exit 1
fi

echo "✓  All modules passed."
exit 0
