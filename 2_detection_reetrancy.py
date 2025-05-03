
import sys
import networkx as nx
from solcx import install_solc, compile_source
import re

def get_ast_from_solidity(source_code, solc_version="0.4.26"):
    
    #install_solc(solc_version)
    
    try:
        # Compile with AST output
        compiled = compile_source(
            source_code,
            solc_version=solc_version,
            output_values=["ast"],
        )
        
        # Find the first contract AST (assuming single contract compilation)
        for contract_id, contract_data in compiled.items():
            if contract_id != "<stdin>":
                return contract_data['ast']
        
        # Fallback if no contract found
        if '<stdin>' in compiled:
            return compiled['<stdin>']['ast']
            
        raise ValueError("No contract AST found in compilation output")
        
    except Exception as e:
        raise RuntimeError(f"Failed to compile or parse AST: {str(e)}")


def traverse_ast_and_build_cfg(ast_root):
    """Traverse AST and build a simple CFG. Detect reentrancy pattern."""
    cfg = nx.DiGraph()
    functions = {}  # Map function names to their bodies
    vulnerabilities = []

    stack = [ast_root]

    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue

        node_type = node.get("name")
        
        # Handle function definitions
        if node_type == "FunctionDefinition":
            func_name = node.get("attributes", {}).get("name", "anonymous")
            
            body = node.get("children", [])
        
            functions[func_name] = body

        # Traverse children
        if 'children' in node:
            stack.extend(node['children'])

    # Analyze each function for reentrancy
    for func, body in functions.items():

        found_external_call = False
        found_state_change = False

        visit_stack = list(body)

        while visit_stack:
            node = visit_stack.pop()
            if not isinstance(node, dict):
                continue

            node_name = node.get("name")
            

            # Detect external calls (e.g., .call.value(), .transfer, .send)
            if node_name == "FunctionCall":
                
                expression = node.get('children', [{}])[0]
             
                if isinstance(expression, dict):
                    value = expression.get('attributes', {}).get('member_name', '')
                   
                    if any(ext in value for ext in ['call', 'send', 'transfer']):
                    
                        found_external_call = True
                        called = value
                        # print(called)
                        cfg.add_edge(func, f"external_call:{called}")

            # Detect state changes (VariableAssignment, etc.)
            if node_name in ["ExpressionStatement", "Assignment"]:
                found_state_change = True
                cfg.add_edge(func, "state_change")

            # Continue traversal
            if 'children' in node:
                visit_stack.extend(node['children'])

        # Detect reentrancy pattern
        if found_external_call and not found_state_change:
            vulnerabilities.append((func, "Potential single-function reentrancy"))
        elif found_external_call and found_state_change:
            vulnerabilities.append((func, "Potential cross-function reentrancy"))

    return vulnerabilities




def detect_reentrancy(contract_code):
    warnings = []

    # Normalize whitespace
    lines = contract_code.split('\n')
    for i, line in enumerate(lines):
        line = line.strip()

        # Look for vulnerable low-level call
        if re.search(r'\.call\.value\s*\(', line):
            # Look ahead in a few lines for state update to balances AFTER the call
            context = lines[i:i+10]  # Check next 10 lines
            for j, follow_line in enumerate(context):
                if re.search(r'balances\s*\[\s*msg\.sender\s*\]\s*[-+*/]?=', follow_line):
                    if j > 0:  # This means call.value came before balance update
                        warnings.append({
                            "line": i + 1,
                            "issue": "Potential reentrancy vulnerability: external call before state update",
                            "code": line
                        })
                    break

    return warnings


def analyze_solidity_file(file_path):
    if not file_path.endswith(".sol"):
        print("Error: Please provide a Solidity (.sol) file.")
        return
    else:
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
          
            ast = get_ast_from_solidity(content)
            regex = detect_reentrancy(content)
  
            if ast and regex:
                warnings = traverse_ast_and_build_cfg(ast)
                print("=== Control Flow Graph Nodes ===")
             
                print("\n=== Reentrancy Warnings ===\n")
                print("\n=== from regex ===\n")
                for iss in regex:
                    print(f"Line {iss['line']}: {iss['issue']}")
                    print(f"→ {iss['code']}")
                print("\n =====from CFG===== \n")

                for func, issue in warnings:
                    print(f"[!] {func}: {issue}")
            else:
                print("✅ Solidity correct syntax code!!!. ")
                print("✅ No obvious reentrancy issues found.")
            
        except FileNotFoundError:
            print(f"Error: The file '{file_path}' was not found.")
        except Exception as e:
            print(f"An error occurred: {e}")



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <solidity_file.sol>")
    else:
        analyze_solidity_file(sys.argv[1])
