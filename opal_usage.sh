set -e

function unreadable() {
  sleep 0.5
  if dd if="$1" bs=1 count=1 skip=0 &>>"${LOG_FILE}"; then
    echo "bad" | tee -a "${LOG_FILE}"
  else
    echo "good" | tee -a "${LOG_FILE}"
  fi
}

function readable() {
  sleep 0.5
  if dd if="$1" bs=1 count=1 skip=0 &>>"${LOG_FILE}"; then
    echo "good" | tee -a "${LOG_FILE}"
  else
    echo "bad" | tee -a "${LOG_FILE}"
  fi
}

OPAL_UTIL="./a.out"
SDB_PSID="B7Y5GWTASWXKQT7XTU5AFYJ6NJQUVC9U"
ADMIN_SDB_PIN="c580e74014ad882cba75c61c6370a07149d79b3d3ed3ee53409215df53bfa67a"
USER_1_PIN="7777777777777777777777777777777777777777777777777777777777777777"
USER_2_PIN="6666666666666666666666666666666666666666666666666666666666666666"
LOG_FILE="./test_log"

echo "test_start" | tee "${LOG_FILE}"

sedutil-cli --yesIreallywanttoERASEALLmydatausingthePSID "${SDB_PSID}" /dev/sdb &>>"${LOG_FILE}"
sedutil-cli --initialsetup password /dev/sdb &>"${LOG_FILE}"

"${OPAL_UTIL}" setup_user /dev/sdb --user 1 --verify-pin "${ADMIN_SDB_PIN}" --assign-pin "${USER_1_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" setup_user /dev/sdb --user 2 --verify-pin "${ADMIN_SDB_PIN}" --assign-pin "${USER_2_PIN}" &>>"${LOG_FILE}"

readable /dev/sdb

echo "locking range does not affect data outside of the range" | tee -a "${LOG_FILE}"
"${OPAL_UTIL}" setup_range /dev/sdb --locking-range 1 --locking-range-start 512 --locking-range-length 512 --verify-pin "${ADMIN_SDB_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" unlock /dev/sdb --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 1 &>>"${LOG_FILE}"
readable /dev/sdb
"${OPAL_UTIL}" unlock /dev/sdb --user 2 --verify-pin "${USER_2_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
readable /dev/sdb

echo "locking range does affect data inside the range" | tee -a "${LOG_FILE}"
"${OPAL_UTIL}" setup_range /dev/sdb --locking-range 1 --locking-range-start 0 --locking-range-length 512 --verify-pin "${ADMIN_SDB_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" unlock /dev/sdb --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 1 &>>"${LOG_FILE}"
unreadable /dev/sdb
echo "can't unlock with wrong password" | tee -a "${LOG_FILE}"
"${OPAL_UTIL}" unlock /dev/sdb --user 2 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
unreadable /dev/sdb
"${OPAL_UTIL}" unlock /dev/sdb --user 2 --verify-pin "${USER_2_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
readable /dev/sdb