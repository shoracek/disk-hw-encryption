function unreadable() {
  if dd if="$1" bs=1 count=512 skip=0 &>>"${LOG_FILE}"; then
    echo "bad"
  else
    echo "good"
  fi
}

function readable() {
  if dd if="$1" bs=1 count=512 skip=0 &>>"${LOG_FILE}"; then
    echo "good"
  else
    echo "bad"
  fi
}

OPAL_UTIL="./a.out"
SDB_PSID="B7Y5GWTASWXKQT7XTU5AFYJ6NJQUVC9U"
ADMIN_SDB_PIN="c580e74014ad882cba75c61c6370a07149d79b3d3ed3ee53409215df53bfa67a"
USER_1_PIN="7777777777777777777777777777777777777777777777777777777777777777"
USER_2_PIN="6666666666666666666666666666666666666666666666666666666666666666"
LOG_FILE="./test_log"

sedutil-cli --yesIreallywanttoERASEALLmydatausingthePSID "${SDB_PSID}" &>>"${LOG_FILE}"
sedutil-cli --initialsetup password &>"${LOG_FILE}"

"${OPAL_UTIL}" setup_user /dev/sdb --user 1 --verify-pin "${ADMIN_SDB_PIN}" --assign-pin "${USER_1_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" setup_user /dev/sdb --user 2 --verify-pin "${ADMIN_SDB_PIN}" --assign-pin "${USER_2_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" setup_range /dev/sdb --locking-range 1 --verify-pin "${ADMIN_SDB_PIN}" &>>"${LOG_FILE}"

"${OPAL_UTIL}" unlock /dev/sdb --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 1 &>>"${LOG_FILE}"
unreadable /dev/sdb
"${OPAL_UTIL}" unlock /dev/sdb --user 2 --verify-pin "${USER_2_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
readable /dev/sdb
