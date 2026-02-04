import sys
import os
import shlex
import json

# Setup paths to import M2 server
current_dir = os.path.dirname(os.path.abspath(__file__))
m2_path = os.path.join(current_dir, "models", "mcps", "M2")
ghidra_client_path = os.path.join(current_dir, "mcps", "ghidra_tools", "client")
pwn_server_path = os.path.join(current_dir, "mcps", "pwntools_tools", "server")

sys.path.append(m2_path)
sys.path.append(ghidra_client_path)
sys.path.append(pwn_server_path)

try:
    # Importing the functions directly from m2_server
    # Note: FastMCP decorators usually preserve the original function call behavior
    import m2_server
except ImportError as e:
    print(f"Error importing M2 server: {e}")
    sys.exit(1)

# Map command names to functions
COMMANDS = {
    # Ghidra
    "meta": m2_server.get_metadata,
    "funcs": m2_server.list_functions,
    "search_func": m2_server.search_functions,
    "asm": m2_server.read_assembly,
    "decompile": m2_server.decompile_function,
    "hex": m2_server.read_memory_hex,
    "search_str": m2_server.search_string,
    
    # Pwntools
    "read_pwn": m2_server.read_exploit_payload,
    "write_pwn": m2_server.write_exploit_payload,
}

def print_help():
    print("\nAvailable Commands:")
    print("  === Ghidra ===")
    print("  meta [binary_path]       : Get binary metadata")
    print("  funcs                    : List all functions")
    print("  search_func <pattern>    : Search functions by name")
    print("  asm <addr> [count]       : Read assembly")
    print("  decompile <name>         : Decompile function")
    print("  hex <addr> [size]        : Read memory hex")
    print("  search_str <pattern>     : Search strings")
    print("\n  === Pwntools ===")
    print("  read_pwn <path>                  : Read payload file")
    print("  write_pwn <content> <filename>   : Write payload")
    print("\n  exit / quit              : Exit")

def main():
    print("=== PwnAutomator Interactive Console ===")
    print("Type 'help' for commands.")
    
    while True:
        try:
            user_input = input("\n>>> ").strip()
            if not user_input:
                continue
                
            if user_input.lower() in ["exit", "quit"]:
                break
                
            if user_input.lower() == "help":
                print_help()
                continue
            
            # Parse input
            parts = shlex.split(user_input)
            cmd_name = parts[0]
            args = parts[1:]
            
            if cmd_name in COMMANDS:
                func = COMMANDS[cmd_name]
                try:
                    # Dynamically call the function with arguments
                    # Python's flexible argument unpacking helps here
                    result = func(*args)
                    
                    # Try to pretty print JSON
                    try:
                        parsed = json.loads(result)
                        print(json.dumps(parsed, indent=2, ensure_ascii=False))
                    except:
                        print(result)
                        
                except TypeError as e:
                    print(f"Error: Incorrect arguments. {e}")
                except Exception as e:
                    print(f"Error executing {cmd_name}: {e}")
            else:
                print(f"Unknown command: {cmd_name}")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"System Error: {e}")

if __name__ == "__main__":
    main()
