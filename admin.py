import os
import json
from ecies import encrypt, decrypt
from ecdsa import VerifyingKey, SigningKey
from secretsharing import HexToHexSecretSharer
from crypto_engine import sign_message, create_keys
from setup_user import load_private_key

BID_STORAGE = "data/bid.json"
ADMIN_KEY_DIR = "data/admin"
STATE_FILE = "data/procurement_state.json"

# ==========================================
# PROCUREMENT STATE HELPERS
# ==========================================
def get_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {"status": "none"}  # possible: "none", "open", "closed"

def set_state(status):
    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump({"status": status}, f)

def print_status_banner():
    state = get_state()
    status = state.get("status", "none")
    if status == "none":
        label = "No Active Procurement"
    elif status == "open":
        label = "Bidding is OPEN"
    elif status == "closed":
        label = "Bidding is CLOSED"
    print(f"\n  Current Status: {label}")


# ==========================================
# INITIALIZE PROCUREMENT
# ==========================================
def initialize_procurement():
    state = get_state()

    if state["status"] == "open":
        print("\n  WARNING: A procurement session is already active and bidding is OPEN.")
        print("   Initializing again would generate a NEW key, making all existing bids unreadable.")
        confirm = input("   Type CONFIRM to wipe and restart, or anything else to cancel: ").strip()
        if confirm != "CONFIRM":
            print("Initialization cancelled. Existing session preserved.")
            return

    elif state["status"] == "closed":
        print("\n  WARNING: A previous procurement session exists (bidding closed).")
        confirm = input("   Type CONFIRM to start a fresh session, or anything else to cancel: ").strip()
        if confirm != "CONFIRM":
            print("Initialization cancelled.")
            return

    print("\n--- INITIALIZING PROCUREMENT SESSION ---")
    os.makedirs(ADMIN_KEY_DIR, exist_ok=True)

    if os.path.exists(BID_STORAGE):
        os.remove(BID_STORAGE)
        print("Previous bid ledger cleared.")

    admin_private, admin_public = create_keys()

    with open(os.path.join(ADMIN_KEY_DIR, "admin_public.pem"), "wb") as f:
        f.write(admin_public.to_pem())

    with open(os.path.join(ADMIN_KEY_DIR, "admin_private.pem"), "wb") as f:
        f.write(admin_private.to_pem())

    print("Success! Admin identity established.")
    print(f"   -> Public key saved to {ADMIN_KEY_DIR}/admin_public.pem")


# ==========================================
# SUBMIT BID
# ==========================================
def submit_bid():
    state = get_state()

    if state["status"] == "none":
        print("Error: No active procurement session. Please wait for the Admin to initialize.")
        return
    if state["status"] == "closed":
        print("Error: Bidding is closed. No more bids are being accepted.")
        return

    user_id = input("Enter your Student/Company ID: ")
    password = input("Enter your private key password: ")

    private_key = load_private_key(user_id, password)
    if not private_key:
        return

    bid_amount = input("Enter your bid amount (e.g., 500000): ")

    admin_pub_path = os.path.join(ADMIN_KEY_DIR, "admin_public.pem")
    if not os.path.exists(admin_pub_path):
        print("Error: Admin public key not found.")
        return

    with open(admin_pub_path, "rb") as f:
        admin_public_pem = f.read()

    vk = VerifyingKey.from_pem(admin_public_pem)
    raw_admin_public_key = vk.to_string("compressed")

    encrypted_bid = encrypt(raw_admin_public_key, bid_amount.encode())
    signature = sign_message(private_key, bid_amount)

    bid_data = {
        "user_id": user_id,
        "encrypted_bid": encrypted_bid.hex(),
        "signature": signature.hex()
    }

    os.makedirs("data", exist_ok=True)
    bids = []
    if os.path.exists(BID_STORAGE):
        try:
            with open(BID_STORAGE, "r") as f:
                content = f.read().strip()
                if content:
                    bids = json.loads(content)
        except json.JSONDecodeError:
            print("Warning: bids.json was corrupted. Starting a new ledger.")
            bids = []

    bids.append(bid_data)

    with open(BID_STORAGE, "w") as f:
        json.dump(bids, f, indent=4)

    print(f"Bid submitted and signed successfully!")


# ==========================================
# CLOSE BIDDING & DECRYPT
# ==========================================
def close_bidding_and_decrypt():
    state = get_state()

    if state["status"] == "none":
        print("Error: No procurement session has been initialized.")
        return

    print("\n--- RECONSTRUCTING KEY FROM SHARES ---")
    print("Two keyholders must enter their shares to unlock the bids.\n")

    share1_num = input("Keyholder 1 - Share number (1, 2, or 3): ").strip()
    share1_val = input("Keyholder 1 - Share value: ").strip()
    share2_num = input("Keyholder 2 - Share number (1, 2, or 3): ").strip()
    share2_val = input("Keyholder 2 - Share value: ").strip()

    share1 = f"{share1_num}-{share1_val}"
    share2 = f"{share2_num}-{share2_val}"

    try:
        recovered_hex = HexToHexSecretSharer.recover_secret([share1, share2])
        recovered_hex = recovered_hex.strip()
        recovered_hex = "".join(c for c in recovered_hex if c in "0123456789abcdefABCDEF")
        if len(recovered_hex) % 2 != 0:
            recovered_hex = "0" + recovered_hex
        raw_admin_private_key = bytes.fromhex(recovered_hex)

        if not os.path.exists(BID_STORAGE):
            print("Error: No bids have been submitted yet.")
            return

        with open(BID_STORAGE, "r") as f:
            bids = json.load(f)

        print(f"\nFound {len(bids)} bid(s). Decrypting...")
        print("=" * 45)

        results = []
        for bid in bids:
            user_id = bid['user_id']
            try:
                encrypted_bytes = bytes.fromhex(bid['encrypted_bid'])
                decrypted_amount = decrypt(raw_admin_private_key, encrypted_bytes).decode()
                results.append((user_id, int(decrypted_amount)))
                print(f"  Bidder: {user_id:<15} | Amount: Rs. {int(decrypted_amount):,}")
            except Exception as e:
                print(f"  Failed to decrypt bid for {user_id}: {e}")

        print("=" * 45)

        if results:
            winner = min(results, key=lambda x: x[1])
            print(f"\n  LOWEST BID: {winner[0]} with Rs. {winner[1]:,}")

        print("\nDecryption complete.")
        set_state("closed")

    except Exception as e:
        print(f"\nFailed to reconstruct key: {e}")
        print("   Make sure both share numbers and values are entered correctly.")


# ==========================================
# SPLIT ADMIN KEY
# ==========================================
def split_admin_key():
    admin_priv_path = os.path.join(ADMIN_KEY_DIR, "admin_private.pem")
    if not os.path.exists(admin_priv_path):
        print("Error: Admin key not found. Initialize procurement first.")
        return

    with open(admin_priv_path, "rb") as f:
        admin_priv_pem = f.read()

    sk = SigningKey.from_pem(admin_priv_pem)
    raw_key_hex = sk.to_string().hex()

    shares = HexToHexSecretSharer.split_secret(raw_key_hex, 2, 3)

    os.remove(admin_priv_path)

    print("\n" + "=" * 55)
    print("  KEY SPLITTING COMPLETE - DISTRIBUTE SHARES NOW")
    print("=" * 55)
    print("  Each share must be given to a DIFFERENT person.")
    print("  Any 2 of 3 shares can reconstruct the key.")
    print("  This screen will NOT show these shares again!")
    print("=" * 55)

    for i, share in enumerate(shares):
        input(f"\nPress Enter when Keyholder {i+1} is ready...")
        share_num, share_val = share.split("-", 1)
        print(f"\n  Keyholder {i+1} - Copy BOTH values down carefully:")
        print(f"   Share Number : {share_num}")
        print(f"   Share Value  : {share_val}\n")
        input(f"Keyholder {i+1}: Press Enter once you have saved your share...")
        print("  Acknowledged.")

    print("\n" + "=" * 55)
    print("  All shares distributed. Original key destroyed.")
    print("  Bidding is now OPEN.")
    print("=" * 55)

    set_state("open")