import sys
from setup_user import register_secure_user
from admin import initialize_procurement, submit_bid, close_bidding_and_decrypt, split_admin_key, get_state, print_status_banner


# ==========================================
# MAIN MENU
# ==========================================
def main_menu():
    while True:
        state = get_state()
        status = state.get("status", "none")

        if status == "none":
            status_label = "⚪ No Active Procurement"
        elif status == "open":
            status_label = "🟢 Bidding is OPEN"
        elif status == "closed":
            status_label = "🔴 Bidding is CLOSED"

        print("\n" + "=" * 55)
        print("🏛️  CSePS - Government e-Procurement System")
        print(f"     {status_label}")
        print("=" * 55)
        print("1. Bidder Portal (Register & Submit Bids)")
        print("2. Administrator Portal (Setup & Decrypt Bids)")
        print("3. Exit System")
        print("=" * 55)

        choice = input("Select your role (1-3): ")

        if choice == '1':
            bidder_menu()
        elif choice == '2':
            admin_menu()
        elif choice == '3':
            print("Exiting CSePS. Goodbye!")
            sys.exit()
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


# ==========================================
# BIDDER MENU
# ==========================================
def bidder_menu():
    while True:
        state = get_state()
        status = state.get("status", "none")

        print("\n--- BIDDER PORTAL ---")
        print("1. Register New Bidder Identity (Generate Keys)")

        # Only show the bid option when bidding is actually open
        if status == "open":
            print("2. Submit a Secure Bid")
        else:
            print("2. Submit a Secure Bid  [unavailable - bidding is not open]")

        print("3. Return to Main Menu")

        choice = input("Select an option (1-3): ")

        if choice == '1':
            print("\n--- IDENTITY REGISTRATION ---")
            user_id = input("Enter your Student/Company ID (e.g., S20335): ")

            while True:
                password = input("Create a strong password to lock your private key: ")
                confirm_password = input("Confirm your password: ")
                if password == confirm_password:
                    break
                else:
                    print("Passwords do not match. Please try again.\n")

            register_secure_user(user_id, password)

        elif choice == '2':
            submit_bid()
        elif choice == '3':
            break
        else:
            print("Invalid choice.")


# ==========================================
# ADMINISTRATOR MENU
# ==========================================
def admin_menu():
    print("\n--- ADMINISTRATOR AUTHENTICATION ---")
    admin_pin = input("Enter Admin PIN to access portal: ")

    if admin_pin != "admin123":
        print("Access Denied. You are not authorized.")
        return

    while True:
        state = get_state()
        status = state.get("status", "none")

        print("\n--- ADMINISTRATOR PORTAL ---")

        if status == "none":
            print("1. Initialize Procurement")
            print("2. Close Bidding & Decrypt Ledger  [unavailable - no active session]")
        elif status == "open":
            print("1. Initialize Procurement  [WARNING: will reset active session]")
            print("2. Close Bidding & Decrypt Ledger")
        elif status == "closed":
            print("1. Initialize New Procurement")
            print("2. View Decrypted Results Again")

        print("3. Return to Main Menu")

        choice = input("Select an option (1-3): ")

        if choice == '1':
            initialize_procurement()
            # Only run key splitting if initialization created a new key
            if os.path.exists("data/admin/admin_private.pem"):
                split_admin_key()
        elif choice == '2':
            close_bidding_and_decrypt()
        elif choice == '3':
            break
        else:
            print("Invalid choice.")


# ==========================================
# SYSTEM START
# ==========================================
import os

if __name__ == "__main__":
    main_menu()