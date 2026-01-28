import os


def run(cmd):
    # Intentional vuln for SAST demo: command injection via os.system
    os.system(cmd)


if __name__ == "__main__":
    user_input = input("cmd> ")
    run(user_input)
