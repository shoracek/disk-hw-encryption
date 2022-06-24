set -e

function unreadable() {
  sleep 0.5
  if dd if="${DEV}" bs=1 count=1 skip=0 &>>"${LOG_FILE}"; then
    echo " bad" | tee -a "${LOG_FILE}"
  else
    echo " good" | tee -a "${LOG_FILE}"
  fi
}

function readable() {
  sleep 0.5
  if dd if="${DEV}" bs=1 count=1 skip=0 &>>"${LOG_FILE}"; then
    echo " good" | tee -a "${LOG_FILE}"
  else
    echo " bad" | tee -a "${LOG_FILE}"
  fi
}

DEV="${1}"
OPAL_UTIL="./a.out"
if [ "${DEV}" == "/dev/sda" ]; then
  PSID="02270104000000000000000000111253"
  ADMIN_PIN="c1ef2aaaf6a6ac7bd9791cdb64f3ac2a4f4296ddb44f29982087b7b3d8baa2a9"
elif [ "${DEV}" == "/dev/sdb" ]; then
  PSID="B7Y5GWTASWXKQT7XTU5AFYJ6NJQUVC9U"
  ADMIN_PIN="c580e74014ad882cba75c61c6370a07149d79b3d3ed3ee53409215df53bfa67a"
else
  echo "yikes"
  exit 1
fi
USER_1_PIN="7777777777777777777777777777777777777777777777777777777777777777"
USER_2_PIN="6666666666666666666666666666666666666666666666666666666666666666"
LOG_FILE="./test_log"

echo "test_start" | tee "${LOG_FILE}"

sedutil-cli --yesIreallywanttoERASEALLmydatausingthePSID "${PSID}" "${DEV}" &>>"${LOG_FILE}"
sedutil-cli --initialsetup password "${DEV}" &>"${LOG_FILE}"

"${OPAL_UTIL}" setup_user "${DEV}" --user 1 --verify-pin "${ADMIN_PIN}" --assign-pin "${USER_1_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" setup_user "${DEV}" --user 2 --verify-pin "${ADMIN_PIN}" --assign-pin "${USER_2_PIN}" &>>"${LOG_FILE}"

readable "${DEV}"

echo "locking range does not affect data outside of the range" | tee -a "${LOG_FILE}"
"${OPAL_UTIL}" setup_range "${DEV}" --locking-range 1 --locking-range-start 512 --locking-range-length 512 --verify-pin "${ADMIN_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" unlock "${DEV}" --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 1 &>>"${LOG_FILE}"
readable "${DEV}"
"${OPAL_UTIL}" unlock "${DEV}" --user 2 --verify-pin "${USER_2_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
readable "${DEV}"

echo "locking range does affect data inside the range" | tee -a "${LOG_FILE}"
"${OPAL_UTIL}" setup_range "${DEV}" --locking-range 1 --locking-range-start 0 --locking-range-length 512 --verify-pin "${ADMIN_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" unlock "${DEV}" --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 1 &>>"${LOG_FILE}"
unreadable "${DEV}"
echo "can't unlock with wrong password" | tee -a "${LOG_FILE}"
"${OPAL_UTIL}" unlock "${DEV}" --user 2 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
unreadable "${DEV}"
"${OPAL_UTIL}" unlock "${DEV}" --user 2 --verify-pin "${USER_2_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
readable "${DEV}"

echo "locking range does affect data inside the range (admin)" | tee -a "${LOG_FILE}"
"${OPAL_UTIL}" setup_range "${DEV}" --locking-range 1 --locking-range-start 0 --locking-range-length 512 --verify-pin "${ADMIN_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" unlock "${DEV}" --user 0 --verify-pin "${ADMIN_PIN}" --locking-range 1 --read-locked 1 &>>"${LOG_FILE}"
unreadable "${DEV}"
"${OPAL_UTIL}" unlock "${DEV}" --user 0 --verify-pin "${ADMIN_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
readable "${DEV}"

