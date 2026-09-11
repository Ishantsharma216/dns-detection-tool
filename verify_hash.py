import hashlib

# The hash you captured from the camera
captured_hash = "27adc263dcd84ce16fdc45c41efbfb0ec37c7c4b66e6f73ed0c6940bba1b35c9"

# List of common default passwords to check
common_passwords = [
    "12345", "123456", "admin", "12345678", "123456789", 
    "888888", "password", "1234", "1234567", "000000","admin@123"
]

print(f"Analyzing Hash: {captured_hash}\n")
print("Checking against common passwords...\n")

found = False
for password in common_passwords:
    # Convert password to bytes, then hash it using SHA-256
    # Note: The camera might add a salt/timestamp, so this might not match
    # but it's the only way to verify.
    hash_object = hashlib.sha256(password.encode())
    hex_digest = hash_object.hexdigest()
    
    print(f"Password: '{password}' -> Hash: {hex_digest}")
    
    if hex_digest == captured_hash:
        print(f"✅ MATCH FOUND! The password is likely: '{password}'")
        found = True
        break

if not found:
    print("\n❌ No match found in the common list.")
    print("This means:")
    print("1. The password is not in the common list.")
    print("2. OR the camera added a 'salt' or 'timestamp' to the password before hashing.")
    print("3. OR the hashing algorithm is different (e.g., SHA-512, MD5, or proprietary).")
    print("\n⚠️  Without the original password or the salt, the hash cannot be 'decoded'.")