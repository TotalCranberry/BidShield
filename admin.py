import os
import json
from ecies import encrypt, decrypt
from ecdsa import VerifyingKey, SigningKey
from secretsharing import HexToHexSecretSharer
from crypto_engine import sign_message, create_keys
from setup_user import load_private_key

DATA_DIR = "data/procurements"


# ==========================================
# PROCUREMENT REGISTRY HELPERS
# Each procurement lives in its own folder:
#   data/procurements/<proc_id>/
#       meta.json          (name, status, created)
#       admin_public.pem   (used by bidders to encrypt)
#       admin_private.pem  (deleted after key split)
#       bids.json          (encrypted bid ledger)
# ==========================================

def _proc_dir(proc_id):
    return os.path.join(DATA_DIR, proc_id)

def _meta_path(proc_id):
    return os.path.join(_proc_dir(proc_id), "meta.json")

def _load_meta(proc_id):
    with open(_meta_path(proc_id), "r") as f:
        return json.load(f)

def _save_meta(proc_id, meta):
    with open(_meta_path(proc_id), "w") as f:
        json.dump(meta, f, indent=4)

def list_procurements():
    """Return list of all procurement meta dicts, sorted by creation time."""
    if not os.path.exists(DATA_DIR):
        return []
    procs = []
    for proc_id in os.listdir(DATA_DIR):
        meta_file = _meta_path(proc_id)
        if os.path.exists(meta_file):
            meta = _load_meta(proc_id)
            meta["id"] = proc_id
            procs.append(meta)
    procs.sort(key=lambda x: x.get("created", ""))
    return procs

def list_open_procurements():
    return [p for p in list_procurements() if p["status"] == "open"]

def get_state():
    """Legacy-compatible: summarise overall system state for main menu banner."""
    procs = list_procurements()
    if not procs:
        return {"status": "none"}
    if any(p["status"] == "open" for p in procs):
        return {"status": "open"}
    if any(p["status"] == "closed" for p in procs):
        return {"status": "closed"}
    return {"status": "none"}

def print_status_banner():
    procs = list_procurements()
    if not procs:
        print("  No procurements created yet.")
        return
    for p in procs:
        if p["status"] == "open":
            icon = "🟢"
        elif p["status"] == "closed":
            icon = "🔴"
        else:
            icon = "⚪"
        print(f"  {icon} [{p['id']}] {p['name']}  ({p['status'].upper()})")


# ==========================================
# INITIALIZE A NEW PROCUREMENT
# ==========================================
def initialize_procurement():
    print("\n--- NEW PROCUREMENT SETUP ---")

    name = input("Enter a name for this procurement (e.g. 'Road Construction Tender'): ").strip()
    if not name:
        print("Procurement name cannot be empty.")
        return

    # Build a safe folder ID from the name
    import re
    from datetime import datetime
    safe_id = re.sub(r"[^a-zA-Z0-9_]", "_", name)[:30]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    proc_id = f"{safe_id}_{timestamp}"
    proc_dir = _proc_dir(proc_id)

    os.makedirs(proc_dir, exist_ok=True)

    # Generate keys
    admin_private, admin_public = create_keys()

    with open(os.path.join(proc_dir, "admin_public.pem"), "wb") as f:
        f.write(admin_public.to_pem())

    with open(os.path.join(proc_dir, "admin_private.pem"), "wb") as f:
        f.write(admin_private.to_pem())

    # Save metadata
    from datetime import datetime
    meta = {
        "name": name,
        "status": "pending",   # pending until keys are split
        "created": datetime.now().isoformat()
    }
    _save_meta(proc_id, meta)

    print(f"\nProcurement '{name}' created successfully (ID: {proc_id})")
    return proc_id


# ==========================================
# SPLIT ADMIN KEY FOR A PROCUREMENT
# ==========================================
def split_admin_key(proc_id=None):
    if proc_id is None:
        print("No procurement ID provided.")
        return

    proc_dir = _proc_dir(proc_id)
    admin_priv_path = os.path.join(proc_dir, "admin_private.pem")

    if not os.path.exists(admin_priv_path):
        print("Error: Admin key not found for this procurement.")
        return

    with open(admin_priv_path, "rb") as f:
        admin_priv_pem = f.read()

    sk = SigningKey.from_pem(admin_priv_pem)
    raw_key_hex = sk.to_string().hex()
    shares = HexToHexSecretSharer.split_secret(raw_key_hex, 2, 3)

    os.remove(admin_priv_path)

    meta = _load_meta(proc_id)
    print("\n" + "=" * 55)
    print(f"  KEY SPLITTING — {meta['name']}")
    print("=" * 55)
    print("  Each share must be given to a DIFFERENT person.")
    print("  Any 2 of 3 shares can reconstruct the key.")
    print("  This screen will NOT show these shares again!")
    print("=" * 55)

    for i, share in enumerate(shares):
        input(f"\nPress Enter when Keyholder {i+1} is ready...")
        share_num, share_val = share.split("-", 1)
        print(f"\n  Keyholder {i+1} — Copy BOTH values carefully:")
        print(f"   Share Number : {share_num}")
        print(f"   Share Value  : {share_val}\n")
        input(f"Keyholder {i+1}: Press Enter once you have saved your share...")
        print("  Acknowledged.")

    meta["status"] = "open"
    _save_meta(proc_id, meta)

    print("\n" + "=" * 55)
    print(f"  '{meta['name']}' is now OPEN for bidding.")
    print("=" * 55)


# ==========================================
# SUBMIT A BID
# ==========================================
def submit_bid():
    open_procs = list_open_procurements()

    if not open_procs:
        print("\nNo procurements are currently open for bidding.")
        return

    print("\n--- OPEN PROCUREMENTS ---")
    for i, p in enumerate(open_procs, 1):
        print(f"  {i}. {p['name']}")

    choice = input("\nSelect a procurement to bid on (number): ").strip()
    try:
        proc = open_procs[int(choice) - 1]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    proc_id = proc["id"]
    print(f"\nBidding on: {proc['name']}")

    user_id = input("Enter your Student/Company ID: ")
    password = input("Enter your private key password: ")

    private_key = load_private_key(user_id, password)
    if not private_key:
        return

    bid_amount = input("Enter your bid amount (e.g., 500000): ").strip()

    admin_pub_path = os.path.join(_proc_dir(proc_id), "admin_public.pem")
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

    bids_path = os.path.join(_proc_dir(proc_id), "bids.json")
    bids = []
    if os.path.exists(bids_path):
        try:
            with open(bids_path, "r") as f:
                content = f.read().strip()
                if content:
                    bids = json.loads(content)
        except json.JSONDecodeError:
            bids = []

    bids.append(bid_data)
    with open(bids_path, "w") as f:
        json.dump(bids, f, indent=4)

    print(f"\nBid submitted successfully for '{proc['name']}'!")


# ==========================================
# CLOSE BIDDING & DECRYPT A PROCUREMENT
# ==========================================
def close_bidding_and_decrypt():
    procs = [p for p in list_procurements() if p["status"] in ("open", "closed")]

    if not procs:
        print("\nNo active or closed procurements found.")
        return

    print("\n--- SELECT PROCUREMENT TO DECRYPT ---")
    for i, p in enumerate(procs, 1):
        status_icon = "🟢" if p["status"] == "open" else "🔴"
        print(f"  {i}. {status_icon} {p['name']}")

    choice = input("\nSelect a procurement (number): ").strip()
    try:
        proc = procs[int(choice) - 1]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    proc_id = proc["id"]
    print(f"\n--- DECRYPTING: {proc['name']} ---")
    print("Two keyholders must enter their shares.\n")

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

        bids_path = os.path.join(_proc_dir(proc_id), "bids.json")
        if not os.path.exists(bids_path):
            print("No bids have been submitted for this procurement.")
            return

        with open(bids_path, "r") as f:
            bids = json.load(f)

        print(f"\nFound {len(bids)} bid(s). Decrypting...")
        print("=" * 50)

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

        print("=" * 50)

        if results:
            winner = min(results, key=lambda x: x[1])
            print(f"\n  LOWEST BID: {winner[0]} with Rs. {winner[1]:,}")

        # Mark as closed
        meta = _load_meta(proc_id)
        meta["status"] = "closed"
        _save_meta(proc_id, meta)

        print("\nDecryption complete. Procurement is now CLOSED.")

    except Exception as e:
        print(f"\nFailed to reconstruct key: {e}")
        print("  Make sure both share numbers and values are entered correctly.")