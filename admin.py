import os
import json
from ecies import encrypt, decrypt
from ecdsa import VerifyingKey, SigningKey
from secretsharing import SecretSharingWrapper as ssw
from secretsharing import PlaintextToHexSecretSharer
from crypto_engine import sign_message, create_keys
from setup_user import load_private_key

BID_STORAGE = "data/bid.json"
ADMIN_KEY_DIR = "data/admin"

def initialize_procurement():
    print("\n--- 🛡️ INITIALIZING PROCUREMENT SESSION ---")
    
    # Ensure the admin directory exists
    os.makedirs(ADMIN_KEY_DIR, exist_ok=True)
    
    # 1. Generate Admin ECC Keys using the SECP256k1 curve
    admin_private, admin_public = create_keys()
    
    # 2. Save Admin Public Key (This will be used by bidders later to encrypt bid amounts)
    with open(os.path.join(ADMIN_KEY_DIR, "admin_public.pem"), "wb") as f:
        f.write(admin_public.to_pem())
        
    # 3. Save Admin Private Key (Used for decryption after bidding closes)
    with open(os.path.join(ADMIN_KEY_DIR, "admin_private.pem"), "wb") as f:
        f.write(admin_private.to_pem())
        
    print(f"✅ Success! Admin identity established.")
    print(f"   -> Public key saved to {ADMIN_KEY_DIR}/admin_public.pem")


def submit_bid():
    user_id = input("Enter your Student/Company ID: ")
    password = input("Enter your private key password: ")
    
    # Load the key
    private_key = load_private_key(user_id, password)
    if not private_key:
        return

    bid_amount = input("Enter your bid amount (e.g., 500000): ")

    admin_pub_path = os.path.join(ADMIN_KEY_DIR, "admin_public.pem")
    if not os.path.exists(admin_pub_path):
        print("❌ Error: Procurement has not been initialized by Admin yet.")
        return
        
    with open(admin_pub_path, "rb") as f:
        admin_public_pem = f.read()

    vk = VerifyingKey.from_pem(admin_public_pem)
    raw_admin_public_key = vk.to_string("compressed")

    encrypted_bid = encrypt(raw_admin_public_key, bid_amount.encode())
    
    signature = sign_message(private_key, bid_amount)
    
    bid_data = {
        "user_id": user_id,
        "encrypted_bid": encrypted_bid.hex(), # Store encrypted bytes as hex string
        "signature": signature.hex() 
    }
    
    # Save to a JSON file
    os.makedirs("data", exist_ok=True)
    bids = []
    if os.path.exists(BID_STORAGE):
        try:
            with open(BID_STORAGE, "r") as f:
                content = f.read().strip()
                if content:
                    bids = json.loads(content)
        except json.JSONDecodeError:
            print("⚠️ Warning: bids.json was corrupted. Starting a new ledger.")
            bids = []
            
    bids.append(bid_data)
    
    with open(BID_STORAGE, "w") as f:
        json.dump(bids, f, indent=4)
        
    print(f"✅ Bid of {bid_amount} submitted successfully and signed!")


def close_bidding_and_decrypt():
    print("\n--- 🛡️ RECONSTRUCTING KEY FROM SHARES ---")
    
    # Collect shares from different admins
    share1 = input("Enter Admin Share 1: ")
    share2 = input("Enter Admin Share 2: ")
    
    try:
        # Reconstruct the original PEM private key
        recovered_pem = PlaintextToHexSecretSharer.recover_secret([share1, share2])
        
        # Now use the recovered_pem to decrypt as we did before
        sk = SigningKey.from_pem(recovered_pem.encode())
        raw_admin_private_key = sk.to_string()
        
        # 3. Load the Ledger
        if not os.path.exists(BID_STORAGE):
            print("❌ Error: No bids have been submitted yet.")
            return

        with open(BID_STORAGE, "r") as f:
            bids = json.load(f)

        print(f"Found {len(bids)} bids. Decrypting...")
        print("-" * 30)

        for bid in bids:
            user_id = bid['user_id']
            encrypted_hex = bid['encrypted_bid']
            signature_hex = bid['signature']

            try:
                # 4. Decrypt the bid amount
                encrypted_bytes = bytes.fromhex(encrypted_hex)
                decrypted_amount = decrypt(raw_admin_private_key, encrypted_bytes).decode()

                # 5. Verification (Optional but Recommended)
                # You would load the bidder's public key from data/keys/ 
                # and use check_signature() to verify the decrypted_amount.
                
                print(f"👤 Bidder: {user_id} | 💰 Amount: Rs. {decrypted_amount}")
            except Exception as e:
                print(f"❌ Failed to decrypt bid for {user_id}: {e}")

        print("-" * 30)
        print("✅ Decryption Complete.")

    except Exception as e:
        print(f"❌ Failed to reconstruct key: {e}. Are the shares correct?")
    


def split_admin_key():
    admin_priv_path = os.path.join(ADMIN_KEY_DIR, "admin_private.pem")
    if not os.path.exists(admin_priv_path):
        print("❌ Error: Admin key not found. Initialize procurement first.")
        return

    with open(admin_priv_path, "rb") as f:
        admin_priv_pem = f.read().decode()

    # Split the PEM string into 3 shares, requiring 2 to reconstruct
    shares = PlaintextToHexSecretSharer.split_secret(admin_priv_pem, 2, 3)

    # Save each share to a separate file (In reality, these go to different people)
    for i, share in enumerate(shares):
        share_path = os.path.join(ADMIN_KEY_DIR, f"admin_share_{i+1}.txt")
        with open(share_path, "w") as f:
            f.write(share)
    
    # IMPORTANT: Delete the original full private key for maximum security
    os.remove(admin_priv_path) 
    print("✅ Admin Private Key has been split into 3 shares (Threshold: 2).")
    print(f"   Shares saved in {ADMIN_KEY_DIR}")