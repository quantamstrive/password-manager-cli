import json
import os
import getpass
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime

class PasswordManager:
    def __init__(self, data_file='passwords.enc', salt_file='salt.key'):
        self.data_file = data_file
        self.salt_file = salt_file
        self.cipher = None
        self.passwords = {}
        
    def _derive_key(self, master_password, salt):
        """Derive encryption key from master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key
    
    def _get_or_create_salt(self):
        """Get existing salt or create new one"""
        if os.path.exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            return salt
    
    def initialize(self, master_password):
        """Initialize the password manager with master password"""
        salt = self._get_or_create_salt()
        key = self._derive_key(master_password, salt)
        self.cipher = Fernet(key)
        self._load_passwords()
    
    def _load_passwords(self):
        """Load and decrypt passwords from file"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'rb') as f:
                    encrypted_data = f.read()
                    if encrypted_data:
                        decrypted_data = self.cipher.decrypt(encrypted_data)
                        self.passwords = json.loads(decrypted_data.decode())
                    else:
                        self.passwords = {}
            except Exception as e:
                print(f"Error loading passwords: {e}")
                print("Invalid master password or corrupted file.")
                self.passwords = {}
        else:
            self.passwords = {}
    
    def _save_passwords(self):
        """Encrypt and save passwords to file"""
        try:
            json_data = json.dumps(self.passwords, indent=2)
            encrypted_data = self.cipher.encrypt(json_data.encode())
            with open(self.data_file, 'wb') as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            print(f"Error saving passwords: {e}")
            return False
    
    def add_password(self, service, username, password, notes=""):
        """Add a new password entry"""
        if service.lower() in self.passwords:
            print(f"Entry for '{service}' already exists. Use update instead.")
            return False
        
        self.passwords[service.lower()] = {
            'service': service,
            'username': username,
            'password': password,
            'notes': notes,
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat()
        }
        
        if self._save_passwords():
            print(f"✓ Password for '{service}' added successfully!")
            return True
        return False
    
    def get_password(self, service):
        """Retrieve a password entry"""
        entry = self.passwords.get(service.lower())
        if entry:
            return entry
        return None
    
    def update_password(self, service, username=None, password=None, notes=None):
        """Update an existing password entry"""
        if service.lower() not in self.passwords:
            print(f"No entry found for '{service}'")
            return False
        
        entry = self.passwords[service.lower()]
        
        if username is not None:
            entry['username'] = username
        if password is not None:
            entry['password'] = password
        if notes is not None:
            entry['notes'] = notes
        
        entry['modified'] = datetime.now().isoformat()
        
        if self._save_passwords():
            print(f"✓ Password for '{service}' updated successfully!")
            return True
        return False
    
    def delete_password(self, service):
        """Delete a password entry"""
        if service.lower() in self.passwords:
            del self.passwords[service.lower()]
            if self._save_passwords():
                print(f"✓ Password for '{service}' deleted successfully!")
                return True
        else:
            print(f"No entry found for '{service}'")
        return False
    
    def search_passwords(self, query):
        """Search for passwords by service name or username"""
        query = query.lower()
        results = []
        
        for key, entry in self.passwords.items():
            if (query in entry['service'].lower() or 
                query in entry['username'].lower() or
                query in entry.get('notes', '').lower()):
                results.append(entry)
        
        return results
    
    def list_all(self):
        """List all stored services"""
        return list(self.passwords.values())
    
    def generate_password(self, length=16, use_symbols=True):
        """Generate a random secure password"""
        import secrets
        import string
        
        chars = string.ascii_letters + string.digits
        if use_symbols:
            chars += string.punctuation
        
        password = ''.join(secrets.choice(chars) for _ in range(length))
        return password


def print_banner():
    """Print application banner"""
    print("\n" + "="*50)
    print("  🔐 SECURE PASSWORD MANAGER CLI")
    print("="*50 + "\n")


def print_menu():
    """Print main menu"""
    print("\n--- MENU ---")
    print("1. Add new password")
    print("2. Retrieve password")
    print("3. Update password")
    print("4. Delete password")
    print("5. Search passwords")
    print("6. List all services")
    print("7. Generate random password")
    print("8. Exit")
    print("-----------")


def display_entry(entry):
    """Display a password entry"""
    print(f"\n{'─'*50}")
    print(f"Service:  {entry['service']}")
    print(f"Username: {entry['username']}")
    print(f"Password: {entry['password']}")
    if entry.get('notes'):
        print(f"Notes:    {entry['notes']}")
    print(f"Created:  {entry['created'][:19]}")
    print(f"Modified: {entry['modified'][:19]}")
    print(f"{'─'*50}\n")


def main():
    """Main application loop"""
    print_banner()
    
    # Initialize password manager
    pm = PasswordManager()
    
    # Get master password
    while True:
        if os.path.exists(pm.data_file):
            master_pwd = getpass.getpass("Enter your master password: ")
        else:
            print("First time setup - Create a master password")
            master_pwd = getpass.getpass("Create master password: ")
            confirm_pwd = getpass.getpass("Confirm master password: ")
            if master_pwd != confirm_pwd:
                print("Passwords don't match. Try again.")
                continue
        
        pm.initialize(master_pwd)
        
        # Test if master password is correct by trying to load
        if os.path.exists(pm.data_file):
            if not pm.passwords and os.path.getsize(pm.data_file) > 0:
                print("Invalid master password. Try again.\n")
                continue
        
        print("✓ Authentication successful!\n")
        break
    
    # Main menu loop
    while True:
        print_menu()
        choice = input("Select an option (1-8): ").strip()
        
        if choice == '1':
            # Add password
            print("\n--- ADD NEW PASSWORD ---")
            service = input("Service name: ").strip()
            username = input("Username/Email: ").strip()
            
            gen = input("Generate random password? (y/n): ").lower()
            if gen == 'y':
                length = input("Password length (default 16): ").strip()
                length = int(length) if length.isdigit() else 16
                symbols = input("Include symbols? (y/n): ").lower() == 'y'
                password = pm.generate_password(length, symbols)
                print(f"Generated password: {password}")
            else:
                password = getpass.getpass("Password: ")
            
            notes = input("Notes (optional): ").strip()
            pm.add_password(service, username, password, notes)
        
        elif choice == '2':
            # Retrieve password
            service = input("\nService name: ").strip()
            entry = pm.get_password(service)
            if entry:
                display_entry(entry)
            else:
                print(f"No entry found for '{service}'")
        
        elif choice == '3':
            # Update password
            print("\n--- UPDATE PASSWORD ---")
            service = input("Service name: ").strip()
            entry = pm.get_password(service)
            
            if not entry:
                print(f"No entry found for '{service}'")
                continue
            
            print("Leave blank to keep current value")
            username = input(f"Username [{entry['username']}]: ").strip()
            password = getpass.getpass("New password [unchanged]: ")
            notes = input(f"Notes [{entry.get('notes', '')}]: ").strip()
            
            pm.update_password(
                service,
                username if username else None,
                password if password else None,
                notes if notes else None
            )
        
        elif choice == '4':
            # Delete password
            service = input("\nService name to delete: ").strip()
            confirm = input(f"Delete '{service}'? (y/n): ").lower()
            if confirm == 'y':
                pm.delete_password(service)
        
        elif choice == '5':
            # Search passwords
            query = input("\nSearch query: ").strip()
            results = pm.search_passwords(query)
            
            if results:
                print(f"\nFound {len(results)} result(s):")
                for entry in results:
                    display_entry(entry)
            else:
                print("No results found.")
        
        elif choice == '6':
            # List all
            entries = pm.list_all()
            if entries:
                print(f"\n{'Service':<20} {'Username':<25} {'Modified'}")
                print("─" * 70)
                for entry in sorted(entries, key=lambda x: x['service'].lower()):
                    print(f"{entry['service']:<20} {entry['username']:<25} {entry['modified'][:10]}")
                print(f"\nTotal: {len(entries)} entries")
            else:
                print("\nNo passwords stored yet.")
        
        elif choice == '7':
            # Generate password
            length = input("\nPassword length (default 16): ").strip()
            length = int(length) if length.isdigit() else 16
            symbols = input("Include symbols? (y/n): ").lower() == 'y'
            password = pm.generate_password(length, symbols)
            print(f"\nGenerated password: {password}")
        
        elif choice == '8':
            # Exit
            print("\n👋 Goodbye! Your passwords are secure.\n")
            break
        
        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye! Your passwords are secure.\n")
    except Exception as e:
        print(f"\n❌ Error: {e}\n")
