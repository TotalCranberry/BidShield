import sys
import os
from setup_user import register_secure_user
from admin import (initialize_procurement, submit_bid, close_bidding_and_decrypt,
                   split_admin_key, list_procurements, print_status_banner,
                   admin_pin_exists, setup_admin_pin, verify_admin_pin)


# ==========================================
# MAIN MENU
# ==========================================
def main_menu():
    # First-run: create config.env if it doesn't exist yet
    if not admin_pin_exists():
        setup_admin_pin()  # creates config.env and exits with instructions

    while True:
        procs = list_procurements()

        print("\n" + "=" * 55)
        print("🏛️  CSePS - Government e-Procurement System")
        print("=" * 55)
        if not procs:
            print("  No procurements active.")
        else:
            print_status_banner()
        print("=" * 55)
        print("1. Bidder Portal")
        print("2. Administrator Portal")
        print("3. Exit")
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
            print("Invalid choice.")


# ==========================================
# BIDDER MENU
# ==========================================
def bidder_menu():
    while True:
        from admin import list_open_procurements
        open_procs = list_open_procurements()

        print("\n--- BIDDER PORTAL ---")
        print("1. Register New Bidder Identity")
        if open_procs:
            print(f"2. Submit a Bid  [{len(open_procs)} procurement(s) open]")
        else:
            print("2. Submit a Bid  [no open procurements]")
        print("3. Return to Main Menu")

        choice = input("Select an option (1-3): ")

        if choice == '1':
            print("\n--- IDENTITY REGISTRATION ---")
            user_id = input("Enter your Student/Company ID (e.g., S20335): ").strip()
            while True:
                password = input("Create a strong password: ")
                confirm = input("Confirm your password: ")
                if password == confirm:
                    break
                print("Passwords do not match. Try again.\n")
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
    pin = input("Enter Admin PIN: ").strip()

    if not verify_admin_pin(pin):
        print("Access Denied. Incorrect PIN.")
        return

    while True:
        procs = list_procurements()

        print("\n--- ADMINISTRATOR PORTAL ---")
        print("-" * 45)
        if not procs:
            print("  No procurements yet.")
        else:
            print_status_banner()
        print("-" * 45)
        print("1. Create New Procurement")
        print("2. Close Bidding & Decrypt a Procurement")
        print("3. Return to Main Menu")
        print("=" * 45)

        choice = input("Select an option (1-3): ")

        if choice == '1':
            proc_id = initialize_procurement()
            if proc_id and os.path.exists(f"data/procurements/{proc_id}/admin_private.pem"):
                split_admin_key(proc_id)
        elif choice == '2':
            close_bidding_and_decrypt()
        elif choice == '3':
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main_menu()