#!/bin/bash

# test_tajnik.sh - Automatski testni okvir za BoxLock password manager
# Pretpostavlja se:
# - boxlock.py postoji u trenutnom direktoriju
# - Python 3.6+ je instaliran
# - pycryptodome je instaliran u virtualnom okruženju i virtualno okruženje je aktivirano

# Pokrenuti: chmod +x test.sh
# i zatim : ./test.sh

# Konfiguracija
BOXLOCK="python3 boxlock.py"
DB_FILE="boxlock.db"
MASTER_PWD="correct_horse_battery_staple"
WRONG_PWD="wrong_password"
TEST_ADDRESS1="bank.example.com"
TEST_PWD1="s3cr3tP@ssw0rd!"
TEST_ADDRESS2="social.media.com"
TEST_PWD2="p@$$w0rd123"
TEST_ADDRESS3="email.provider.com"
TEST_PWD3="p@$$w0rd123"  # Namjerno ista kao TEST_PWD2

# Funkcije za pomoć
print_header() {
    echo -e "\n\e[34m=== $1 ===\e[0m"
}

print_step() {
    echo -e "\n\e[33m➤ $1\e[0m"
}

print_db() {
    echo -e "\n\e[35m[Database]:\e[0m"
    xxd $DB_FILE
    echo -e "\n\e[35m[Hexdump for addresses]:\e[0m"
    strings $DB_FILE | grep -iE "bank|social|email" || echo "No plaintext addresses"
}

# Počisti prijašnje stanje
rm -f $DB_FILE *.bak

# -------------------------------------------------------------------
print_header "1. TEST CORE FUNCTIONALITY"
# -------------------------------------------------------------------

print_step "1.1 Initialize empty database"
echo "Before initialization:"
[ -f $DB_FILE ] && print_db || echo "Database does not exist."
echo "▶ $BOXLOCK init $MASTER_PWD"
$BOXLOCK init "$MASTER_PWD"
echo "After initialization:"
print_db
cp $DB_FILE init_state.db

print_step "1.2 Add first password for $TEST_ADDRESS1 ($TEST_PWD1)"
echo "Database before adding password:"
print_db
echo "▶ $BOXLOCK put $MASTER_PWD $TEST_ADDRESS1 $TEST_PWD1"
$BOXLOCK put "$MASTER_PWD" "$TEST_ADDRESS1" "$TEST_PWD1"
echo "Database after adding password:"
print_db
cp $DB_FILE after_first_entry.db

print_step "1.3 Retrieve password for $TEST_ADDRESS1"
echo "▶ $BOXLOCK get $MASTER_PWD $TEST_ADDRESS1"
$BOXLOCK get "$MASTER_PWD" "$TEST_ADDRESS1"

print_step "1.4 Reinitialize database (should overwrite old one)"
echo "Database before reinitialization:"
print_db
echo "▶ $BOXLOCK init $MASTER_PWD"
$BOXLOCK init "$MASTER_PWD"
echo "Database after reinitialization:"
print_db

# -------------------------------------------------------------------
print_header "2. TEST CONFIDENTIALITY OF PASSWORDS"
# -------------------------------------------------------------------

print_step "2.1 Add passwords of different lengths"
echo "Database before adding passwords of different lengths:"
print_db
echo "▶ $BOXLOCK put $MASTER_PWD short 123"
$BOXLOCK put "$MASTER_PWD" "short" "123"
echo "▶ $BOXLOCK put $MASTER_PWD long 50_characters_long_password_1234567890!@#$%^&"
$BOXLOCK put "$MASTER_PWD" "long" "50_characters_long_password_1234567890!@#$%^&"
echo "Database after adding different lengths:"
print_db

print_step "2.2 Add identical passwords for different addresses"
echo "Database before adding identical passwords for different addresses:"
print_db
echo "▶ $BOXLOCK put $MASTER_PWD $TEST_ADDRESS2 $TEST_PWD2"
$BOXLOCK put "$MASTER_PWD" "$TEST_ADDRESS2" "$TEST_PWD2"
echo "▶ $BOXLOCK put $MASTER_PWD $TEST_ADDRESS3 $TEST_PWD3"
$BOXLOCK put "$MASTER_PWD" "$TEST_ADDRESS3" "$TEST_PWD3"
echo "Database after adding identical passwords:"
print_db

print_step "2.3 Retrieve all stored passwords"
echo "Retrieving password for $TEST_ADDRESS1:"
$BOXLOCK get "$MASTER_PWD" "$TEST_ADDRESS1"
echo "Retrieving password for $TEST_ADDRESS2:"
$BOXLOCK get "$MASTER_PWD" "$TEST_ADDRESS2"
echo "Retrieving password for $TEST_ADDRESS3:"
$BOXLOCK get "$MASTER_PWD" "$TEST_ADDRESS3"
echo "Retrieving password for 'short':"
$BOXLOCK get "$MASTER_PWD" "short"
echo "Retrieving password for 'long':"
$BOXLOCK get "$MASTER_PWD" "long"

# -------------------------------------------------------------------
print_header "3. TEST CONFIDENTIALITY OF ADDRESSES"
# -------------------------------------------------------------------

print_step "3.1 Check for addresses in database"
echo "▶ hexdump -C $DB_FILE | grep -iE 'bank|social|email'"
hexdump -C $DB_FILE | grep -iE "bank|social|email" || echo "Addresses not found"

print_step "3.2 Add new address and count entries"
cp $DB_FILE before_new_entry.db
echo "Database before adding new address:"
print_db
echo "▶ $BOXLOCK put $MASTER_PWD new_address new_password"
$BOXLOCK put "$MASTER_PWD" "new_address" "new_password"
echo "Database after adding new address:"
print_db
echo "File sizes of database files:"
ls -l *.db | awk '{print $5 " " $9}'

# -------------------------------------------------------------------
print_header "4. TEST DATA INTEGRITY"
# -------------------------------------------------------------------

print_step "4.1 Attack: Modify HMAC"
cp after_first_entry.db tampered.db
dd if=/dev/urandom of=tampered.db bs=1 count=32 seek=200 conv=notrunc 2>/dev/null
echo "Database with modified HMAC:"
xxd tampered.db
echo "▶ Running get with tampered database (HMAC modified)"
cp tampered.db $DB_FILE
$BOXLOCK get "$MASTER_PWD" "$TEST_ADDRESS1"

print_step "4.2 Attack: Modify ciphertext"
cp after_first_entry.db tampered.db
dd if=/dev/urandom of=tampered.db bs=1 count=16 seek=100 conv=notrunc 2>/dev/null
echo "Database with modified ciphertext:"
xxd tampered.db
echo "▶ Running get with tampered database (ciphertext modified)"
cp tampered.db $DB_FILE
$BOXLOCK get "$MASTER_PWD" "$TEST_ADDRESS1"

print_step "4.3 Attack: Modify IV"
cp after_first_entry.db tampered.db
dd if=/dev/urandom of=tampered.db bs=1 count=16 seek=32 conv=notrunc 2>/dev/null
echo "Database with modified IV:"
xxd tampered.db
echo "▶ Running get with tampered database (IV modified)"
cp tampered.db $DB_FILE
$BOXLOCK get "$MASTER_PWD" "$TEST_ADDRESS1"

# -------------------------------------------------------------------
print_header "5. ADDITIONAL TEST CASES"
# -------------------------------------------------------------------

print_step "5.1 Incorrect master password"
echo "▶ $BOXLOCK get $WRONG_PWD $TEST_ADDRESS1"
$BOXLOCK get "$WRONG_PWD" "$TEST_ADDRESS1"

print_step "5.2 Non-existent address"
echo "▶ $BOXLOCK get $MASTER_PWD non_existent"
$BOXLOCK get "$MASTER_PWD" "non_existent"

print_step "5.3 Change master password"
echo "Database before reinitialization with new master password:"
print_db
echo "▶ Initialize with new master password 'new_master_password'"
$BOXLOCK init "new_master_password"
echo "Database after reinitialization with new master password:"
print_db
echo "▶ Attempt to read with old master password ($MASTER_PWD)"
$BOXLOCK get "$MASTER_PWD" "$TEST_ADDRESS1"

# Čišćenje
rm -f *.db *.bak tampered.db
echo -e "\n\e[32mTests completed!\e[0m"
