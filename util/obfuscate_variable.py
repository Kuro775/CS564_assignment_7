import ast
import random
import string
import argparse


# Function to generate a random string of fixed length
def random_string(length=8):
    # Ensure the first character is a letter (a-z or A-Z)
    first_char = random.choice(string.ascii_letters)
    # The rest of the characters can be letters or digits
    rest_of_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length-1))
    return first_char + rest_of_string


# List of standard Python functions and variables to preserve
STANDARD_FUNCTIONS = {
    "print", "open", "input", "len", "range", "iter", "next", "abs", "str", "int", "float", "bool",
    "list", "dict", "tuple", "set", "sorted", "sum", "max", "min", "type", "isinstance", "issubclass",
    "__name__"
}

# Class to visit and rename function names and variables in the AST
class RenameVariables(ast.NodeTransformer):
    def __init__(self, imports):
        self.name_map = {}  # Store the mapping of original variable and function names to random names
        self.imports = imports  # List of imports and aliases to be preserved (not renamed)
    
    def visit_Name(self, node):
        if isinstance(node, ast.Name):
            # Skip renaming for names that are part of import statements (e.g., imported functions or modules)
            if node.id in self.imports or node.id in STANDARD_FUNCTIONS:
                return node  # Leave imports and standard functions intact
            
            # If the variable name has already been mapped, reuse the mapped name
            if node.id not in self.name_map:
                self.name_map[node.id] = random_string()  # Generate a new random name for the variable
            node.id = self.name_map[node.id]  # Replace with the mapped random name
        return node

    def visit_FunctionDef(self, node):
        # Skip renaming for function names that are part of standard functions
        if node.name in STANDARD_FUNCTIONS:
            return node
        
        # Rename the function name itself
        if node.name not in self.name_map:
            self.name_map[node.name] = random_string()  # Generate a new random name for the function
        node.name = self.name_map[node.name]  # Replace function name with the mapped random name

        # Rename the function arguments
        for arg in node.args.args:
            if arg.arg not in self.name_map:
                self.name_map[arg.arg] = random_string()  # Generate a new random name for the argument
            arg.arg = self.name_map[arg.arg]  # Replace argument name with the mapped random name
        
        # Continue transforming the body of the function
        return self.generic_visit(node)


def obfuscate_code(source_code):
    # Parse the source code into an AST
    tree = ast.parse(source_code)
    
    # Identify all imported module names (to exclude them from renaming)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
                if alias.asname:
                    imports.add(alias.asname)  # Add alias to the imports list
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module)
            for alias in node.names:
                imports.add(alias.name)  # Handle imports like 'from x import y'
                if alias.asname:
                    imports.add(alias.asname)  # Add alias to the imports list
    
    # Rename all variables and function names in the AST, but skip imports and standard functions
    tree = RenameVariables(imports).visit(tree)
    
    # Convert the modified AST back to source code
    obfuscated_code = ast.unparse(tree)  # Python 3.9+ required
    
    return obfuscated_code


def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Obfuscate Python source code.")
    parser.add_argument("input_file", help="Input Python source code file")
    parser.add_argument("output_file", help="Output file to write the obfuscated code")
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Read the source code from the input file
    try:
        with open(args.input_file, "r") as f:
            source_code = f.read()
    except FileNotFoundError:
        print(f"Error: The file {args.input_file} does not exist.")
        return
    
    # Obfuscate the code
    obfuscated_code = obfuscate_code(source_code)
    
    # Write the obfuscated code to the output file
    with open(args.output_file, "w") as f:
        f.write(obfuscated_code)
    
    print(f"Obfuscated code has been written to {args.output_file}")


if __name__ == "__main__":
    main()
