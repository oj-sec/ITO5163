#!/usr/bin/env python3

# Python script to recursively pipe files through the ITO5163 ChaCha20 encryption routine to gather data

import argparse
import os
import glob
import subprocess
import json

def start(path, output, stripe, skip):

    for file in glob.glob(path + "/**/*", recursive=True):
        if os.path.isfile(os.path.join(path, file)):
            print(f"Processing target: {file}")

            feature = subprocess.run(["./target/release/ITO5163", "--path", file, "--stripe", stripe, "--skip", skip, '-d'], capture_output=True, text=True)
            
            if len(feature.stdout) > 0:

                try:
                    loaded_feature = json.loads(feature.stdout)

                    write(loaded_feature, output)
                except Exception as e:
                    print(f"Exception at {file}:")
                    print(str(e))
                
def write(loaded_feature, output):

    with open(output, 'a') as f:
        json.dump(loaded_feature, f)  
        f.write("\n")      

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--path", "-p", required=True, help="Directory to commence traversal from.")
    parser.add_argument("--output", "-o", required=True, help="File to collect ndJSON results into.")
    parser.add_argument("--stripe", "-s", required=True, help="Encryption stripe size (bytes).")
    parser.add_argument("--skip", "-k", required=True, help="Encryption skip section size (bytes).")

    args = parser.parse_args()

    start(args.path, args.output, args.stripe, args.skip)