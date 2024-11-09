import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import font as tkFont
import falcon  
import os
import pickle  # Used for serialization

# Global variables for public and secret keys
public_key = None
secret_key = None
signature = None
file_data = None
verify_file_data = None

def upload_file():
    global file_data
    file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf"), ("Image files", "*.jpg;*.jpeg;*.png"), ("DOC files", "*.doc")])
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, os.path.basename(file_path))
        with open(file_path, "rb") as file:
            file_data = file.read()

def sign_file():
    global secret_key, public_key, signature, file_data
    if file_data is None:
        messagebox.showwarning("Warning", "Please upload a document first.")
        return

    # Generate secret and public keys
    secret_key = falcon.SecretKey(512)
    public_key = falcon.PublicKey(secret_key)

    # Sign the binary data
    signature = secret_key.sign(file_data)

    # Save the keys and signature to text files
    save_keys_and_signature()
    #messagebox.showinfo("Signing Process", "Signing completed successfully! Public Key and Signature have been saved as text files.")
    messagebox.showinfo("Signing Process", "Signing completed successfully!")


def save_keys_and_signature():
    if file_data is None:
        return

    # Get the base name of the uploaded file (without extension)
    pdf_name = os.path.splitext(file_entry.get())[0]

    # Serialize the public key, convert to hex, and save as text
    public_key_path = f"{pdf_name}_publickey.txt"
    with open(public_key_path, "w") as pk_file:
        pk_file.write(pickle.dumps(public_key).hex())  # Serialize and convert to hex

    # Serialize the secret key, convert to hex, and save as text
    secret_key_path = f"{pdf_name}_secretkey.txt"
    with open(secret_key_path, "w") as sk_file:
        sk_file.write(pickle.dumps(secret_key).hex())  # Serialize and convert to hex

    # Save the signature in hexadecimal format
    signature_path = f"{pdf_name}_signature.txt"
    with open(signature_path, "w") as sig_file:
        sig_file.write(signature.hex())

    messagebox.showinfo("Save Location", f"Keys and signature saved as:\n{public_key_path}\n{secret_key_path}\n{signature_path}")



def select_verify_file():
    global verify_file_data
    file_path = filedialog.askopenfilename(title="Select the Document for Verification", filetypes=[("PDF files", "*.pdf"), ("Image files", "*.jpg;*.jpeg;*.png"), ("DOC files", "*.doc")])
    if file_path:
        verify_file_entry.delete(0, tk.END)
        verify_file_entry.insert(0, os.path.basename(file_path))
        with open(file_path, "rb") as file:
            verify_file_data = file.read()

def verify_signature():
    # Check for public key input from entry or file
    public_key_input = public_key_entry.get().strip()
    if not public_key_input:
        messagebox.showwarning("Warning", "Please enter the public key or select a valid Public Key file.")
        return

    # Determine if input is from text or file
    if os.path.exists(public_key_input):
        # Load public key from hex-encoded text file and deserialize it
        with open(public_key_input, "r") as pk_file:
            global public_key
            public_key_hex = pk_file.read().strip()
            public_key = pickle.loads(bytes.fromhex(public_key_hex))  # Convert from hex and deserialize
    else:
        messagebox.showerror("Error", "Public key must be loaded from a file.")
        return

    if verify_file_data is None:
        messagebox.showwarning("Warning", "Please select a document for verification.")
        return

    # Retrieve the signature text from the entry
    saved_signature = signature_entry.get().strip()
    if not saved_signature:
        messagebox.showwarning("Warning", "Please enter the signature text.")
        return

    # Convert the signature from hex format
    saved_signature = bytes.fromhex(saved_signature)

    # Verify the signature
    is_valid = public_key.verify(verify_file_data, saved_signature)
    if is_valid:
        messagebox.showinfo("Verification Result", "The signature is valid.", icon='info')
    else:
        messagebox.showerror("Verification Result", "The signature is invalid.", icon='error')


def browse_public_key():
    public_key_file_path = filedialog.askopenfilename(title="Select Public Key File", filetypes=[("Text files", "*.txt")])
    if public_key_file_path:
        public_key_entry.delete(0, tk.END)
        public_key_entry.insert(0, public_key_file_path)

# Setting up the GUI
root = tk.Tk()
root.title("Falcon Digital Signature GUI")
root.geometry("650x700")
root.configure(bg="#cafcd9")  

# Custom font
custom_font = tkFont.Font(family="Helvetica", size=11)

# Sign Document Frame
# sign_frame = tk.LabelFrame(root, text="Sign Document", bg="#e0f7fa", font=tkFont.Font(family="Helvetica", size=17, weight="bold"))
# sign_frame.pack(pady=30, padx=20, fill="both", expand=True)
# sign_frame.configure(labelanchor="n", padx=20, pady=20)  # Centering with padding inside the frame

# Sign Document Frame
sign_label = tk.Label(root, text="Sign Document", bg="#b3e5fc", font=tkFont.Font(family="Helvetica", size=15, weight="bold"), relief="solid", borderwidth=1, width=20, height=2)
sign_label.pack(pady=(30, 0.6), padx=20, fill="x")

# Sign Document Frame
sign_frame = tk.Frame(root, bg="#e0f7fa", bd=1, relief="solid")
sign_frame.pack(padx=20, pady=(0, 50), fill="both", expand=True)


# Center the widgets within the frame
file_label = tk.Label(sign_frame, text="Select Document:", bg="#e0f7fa", font=custom_font)
file_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

file_entry = tk.Entry(sign_frame, width=40, font=custom_font)
file_entry.grid(row=0, column=1, padx=10, pady=5)

upload_button = tk.Button(sign_frame, text="Browse", command=upload_file, bg="#4CAF50", fg="white", font=custom_font, borderwidth=2, relief="groove")
upload_button.grid(row=0, column=2, padx=10, pady=5)

sign_button = tk.Button(sign_frame, text="Generate Keys & Sign", command=sign_file, bg="#00796b", fg="white", font=custom_font, borderwidth=6, relief="groove")
sign_button.grid(row=3, column=0, columnspan=3, pady=30)

# Verify Document Frame
# verify_frame = tk.LabelFrame(root, text="Verify Document", bg="#e0f7fa", font=tkFont.Font(family="Helvetica", size=17, weight="bold"))
# verify_frame.pack(pady=30, padx=20, fill="both", expand=True)
# verify_frame.configure(labelanchor="n", padx=20, pady=20) 

verify_label = tk.Label(root, text="Verify Document", bg="#b3e5fc", font=tkFont.Font(family="Helvetica", size=15, weight="bold"), relief="solid", borderwidth=1, width=20, height=2)
verify_label.pack(pady=(30, 0), padx=20, fill="x")

# Verify Document Frame
verify_frame = tk.Frame(root, bg="#e0f7fa", bd=1, relief="solid")
verify_frame.pack(padx=20, pady=(0.6, 30), fill="both", expand=True)

verify_file_label = tk.Label(verify_frame, text="Select Document:", bg="#e0f7fa", font=custom_font)
verify_file_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

verify_file_entry = tk.Entry(verify_frame, width=40, font=custom_font)
verify_file_entry.grid(row=0, column=1, padx=10, pady=5)

verify_upload_button = tk.Button(verify_frame, text="Browse", command=select_verify_file, bg="#4CAF50", fg="white", font=custom_font, borderwidth=2, relief="groove")
verify_upload_button.grid(row=0, column=2, padx=10, pady=5)

public_key_label = tk.Label(verify_frame, text="Public Key (File):", bg="#e0f7fa", font=custom_font)
public_key_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")

public_key_entry = tk.Entry(verify_frame, width=40, font=custom_font)
public_key_entry.grid(row=1, column=1, padx=10, pady=5)

public_key_browse_button = tk.Button(verify_frame, text="Browse", command=browse_public_key, bg="#4CAF50", fg="white", font=custom_font, borderwidth=2, relief="groove")
public_key_browse_button.grid(row=1, column=2, padx=10, pady=5)

signature_label = tk.Label(verify_frame, text="Signature (Text):", bg="#e0f7fa", font=custom_font)
signature_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")

signature_entry = tk.Entry(verify_frame, width=40, font=custom_font)
signature_entry.grid(row=2, column=1, padx=10, pady=5)

verify_button = tk.Button(verify_frame, text="Verify Signature", command=verify_signature, bg="#00796b", fg="white", font=custom_font, borderwidth=6, relief="groove")
verify_button.grid(row=3, column=1, columnspan=1, pady=30)

footer_label = tk.Label(root, text="Falcon Digital Signature Tool", bg="#d2f8d2", font=tkFont.Font(family="Helvetica", size=10, slant="italic"))
footer_label.pack(side="bottom", pady=10)

# Animation effect: color change on hover
def on_enter(e):
    e.widget['background'] = '#00FFFF'  # Lighter shade on hover

def on_leave(e):
    e.widget['background'] = '#00796b'  # Original button color

# Apply animation effect to buttons
for button in root.winfo_children():
    if isinstance(button, tk.Button):
        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)

# Run the application
root.mainloop()
