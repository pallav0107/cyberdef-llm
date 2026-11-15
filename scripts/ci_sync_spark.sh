#!/usr/bin/env bash
# Copy the pipeline code from the box (the canonical copy) to Spark so both machines run byte-identical code, then
# confirm the fingerprints match. Run on the box:  bash scripts/ci_sync_spark.sh
# Refuses while a CI step holds Spark (bash reads ci_step.sh as it runs, so swapping it mid-step could break that step).
set -eo pipefail
cd "$(dirname "$0")/.."
read -r SPARK SPARK_REPO < <(cd scripts && python3 -c "import ci_pipeline as c; print(c.SPARK, c.SPARK_REPO)")
if ssh -o BatchMode=yes "$SPARK" "f=$SPARK_REPO/.ci_priority; [ -s \$f ] && kill -0 \$(cut -d' ' -f1 \$f) 2>/dev/null"; then
  echo "a CI step is running on Spark ($(ssh -o BatchMode=yes "$SPARK" "cat $SPARK_REPO/.ci_priority")); try again when it finishes"; exit 1
fi
FILES=$(bash scripts/ci_step.sh manifest | awk '$1 != "MISSING" {print $2}')
echo "$FILES" | rsync -a --files-from=- ./ "$SPARK:$SPARK_REPO/"
bash scripts/ci_step.sh manifest > /tmp/ci_code_box.txt
ssh -o BatchMode=yes "$SPARK" "cd $SPARK_REPO && bash scripts/ci_step.sh manifest" > /tmp/ci_code_spark.txt
ssh -o BatchMode=yes "$SPARK" "cat > $SPARK_REPO/results/ci_code_manifest_box.txt" < /tmp/ci_code_box.txt
if diff -q /tmp/ci_code_box.txt /tmp/ci_code_spark.txt >/dev/null; then
  echo "Spark now runs the same pipeline code as the box ($(wc -l < /tmp/ci_code_box.txt) files, fingerprint $(sha256sum /tmp/ci_code_box.txt | cut -c1-12))"
else
  echo "still different:"; diff /tmp/ci_code_box.txt /tmp/ci_code_spark.txt; exit 1
fi
