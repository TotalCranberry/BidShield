import sys
# This pulls the registration function from the file we built earlier!
from setup_user import register_secure_user
from admin import initialize_procurement, submit_bid, close_bidding_and_decrypt, split_admin_key


# ==========================================
# MAIN MENU (THE FRONT DOOR)
# ==========================================
def main_menu():
    while True:
        print("\n" + "=" * 55)
        print("🏛️  CSePS - Government e-Procurement System")
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
            print("❌ Invalid choice. Please enter 1, 2, or 3.")


# ==========================================
# BIDDER MENU (UPDATED WITH VERIFICATION)
# ==========================================
def bidder_menu():
    while True:
        print("\n--- 👤 BIDDER PORTAL ---")
        print("1. Register New Bidder Identity (Generate Keys)")
        print("2. Submit a Secure Bid")
        print("3. Return to Main Menu")

        choice = input("Select an option (1-3): ")

        if choice == '1':
            print("\n--- IDENTITY REGISTRATION ---")
            user_id = input("Enter your Student/Company ID (e.g., S20335): ")

            # NEW: Password Verification Loop
            while True:
                password = input("Create a strong password to lock your private key: ")
                confirm_password = input("Confirm your password: ")

                if password == confirm_password:
                    # Passwords match! Break out of the loop and continue.
                    break
                else:
                    # Passwords failed to match. The loop restarts.
                    print("❌ Passwords do not match. Please try again.\n")

            # We only reach this line if the passwords matched perfectly
            register_secure_user(user_id, password)

        elif choice == '2':
            submit_bid()
        elif choice == '3':
            break  # This breaks out of the Bidder Menu and returns to the Main Menu
        else:
            print("❌ Invalid choice.")
# ==========================================
# ADMINISTRATOR MENU
# ==========================================
def admin_menu():
    print("\n--- 🛡️ ADMINISTRATOR AUTHENTICATION ---")
    admin_pin = input("Enter Admin PIN to access portal: ")

    # Layer 1 Security: Only allow access if they know the secret PIN
    if admin_pin != "admin123":
        print("❌ Access Denied. You are not authorized.")
        return  # Kicks them immediately back to the Main Menu

    while True:
        print("\n--- 🛡️ ADMINISTRATOR PORTAL ---")
        print("1. Initialize Procurement (Create Bidding Item & Admin Keys)")
        print("2. Close Bidding & Decrypt Ledger")
        print("3. Return to Main Menu")

        choice = input("Select an option (1-3): ")

        if choice == '1':
            initialize_procurement()
            split_admin_key()
        elif choice == '2':
            close_bidding_and_decrypt()
        elif choice == '3':
            break  # Returns to Main Menu
        else:
            print("❌ Invalid choice.")


# ==========================================
# SYSTEM START
# ==========================================
if __name__ == "__main__":
    main_menu()