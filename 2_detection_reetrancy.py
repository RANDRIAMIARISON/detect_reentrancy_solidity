import solcx
import networkx as nx
import pprint
import sys 

def compile_contract(contract_source):
    #solcx.install_solc('0.8.25')  # Install Solidity compiler version 0.8.0
    solcx.set_solc_version('0.8.25')
    compiled_sol = solcx.compile_source(contract_source, output_values=['ast'])
    return compiled_sol

def state_changes(ast):
    cfg = nx.DiGraph()  # Initialize directed graph for CFG
    state_change = []  # Track the current function being traversed
    nodes_to_visit = ast[:]  # Stack for iterative traversal
    
    # print(nodes_to_visit)
    while nodes_to_visit:
        node = nodes_to_visit.pop()        
        if isinstance(node, dict):
            # Detect state changes (e.g., assignment to state variables)
            if node.get('nodeType') == 'Assignment':
                left_hand_side = node.get('leftHandSide', {})
                basedexpress = left_hand_side.get('baseExpression',{})
                if basedexpress.get('nodeType') == 'Identifier' and basedexpress.get('referencedDeclaration', ''):
                    state_change.append(basedexpress.get('name', ''))
                
            # Add child nodes to the list for further traversal
            for key in node:
                if isinstance(node[key], list):
                    nodes_to_visit.extend(node[key])
                elif isinstance(node[key], dict):
                    nodes_to_visit.append(node[key])

    return state_change


def detect_external_calls(ast):
    cfg = nx.DiGraph()  # Initialize directed graph for CFG
    external_calls = []  # Track the current function being traversed
    nodes_to_visit = ast[:]  # Stack for iterative traversal
    
    # print(nodes_to_visit)
    while nodes_to_visit:
        node = nodes_to_visit.pop()        
        if isinstance(node, dict):
            # Detect external calls (e.g., .call, .send, .transfer)
            if node.get('nodeType') == 'MemberAccess' and node.get('memberName', '') in ['call', 'delegatecall', 'sender', 'transfer']:
                # print("etoooooooohery")
                external_calls.append(node.get('memberName', ''))    

                
            # Add child nodes to the list for further traversal
            for key in node:
                if isinstance(node[key], list):
                    nodes_to_visit.extend(node[key])
                elif isinstance(node[key], dict):
                    nodes_to_visit.append(node[key])

    return external_calls


def traverse_ast_iteratively(ast):
    cfg = nx.DiGraph()  # Initialize directed graph for CFG
    current_function = None  # Track the current function being traversed
    nodes_to_visit = ast[:]  # Stack for iterative traversal
    
    # print(nodes_to_visit)
    while nodes_to_visit:
        node = nodes_to_visit.pop()        
        if isinstance(node, dict):
            # Check if this node is a FunctionCall
            if node.get('nodeType') == 'FunctionDefinition':
                # print("izyyy")
                function_name = node.get('name')
                
                cfg.add_node(function_name) #tong etoooo alohaaa
                # print(function_name) #attack() withdraw() deposit() grand fonction dans le solidity
            if node.get('nodeType') == 'FunctionCall':
                expression = node.get('expression', {})
                if expression.get('nodeType') == 'Identifier':

                    callee = expression['name']
                    # print(callee) #fonction anatny withdraw() require()
                    cfg.add_edge(callee, callee)
                   
                
            # Add child nodes to the list for further traversal
            for key in node:
                if isinstance(node[key], list):
                    nodes_to_visit.extend(node[key])
                elif isinstance(node[key], dict):
                    nodes_to_visit.append(node[key])

    return cfg


def analyze_retrancy(state_chng,external_fun,nodes_edge):
    # Analyze the control flow graph (CFG) to detect reentrancy vulnerabilities
    vulnerabilities = []

    singl_cros = singl_cross(state_chng,external_fun,nodes_edge)
    print(len(singl_cros))
    
    if singl_cros: #mila boucle for pour récuperer leurs contenus
        for sinc in singl_cros:
            if sinc == 'Single':
                vulnerabilities.append("Potential unrestricted reentrancy vulnerability detected. single type error")
            elif sinc== 'Cross':
                vulnerabilities.append("Potential unrestricted reentrancy vulnerability detected. Cross type error")

    else:
        vulnerabilities.append("No reentrancy vulnerabilities detected.")
    return vulnerabilities

def singl_cross(state_chng,external_fun,nodes_edge):
    vulnerabilities = []
    verif = []
    if state_chng and external_fun and len(nodes_edge)==1:
        vulnerabilities.append("Single")

    elif len(nodes_edge)>=2 and state_chng and external_fun:
        
        for nod in nodes_edge:
            if nod == 'deposit' or nod == 'withdraw':
                verif.append("test")
                
        if len(verif)!=0:        
                vulnerabilities.append("Cross")

    return vulnerabilities




# vulnerablty_or_not = detect_reentrancy_vulnerabilities(ast,state_chng,external_fun,nodes_edge)


# print(state_chng)
# print(external_fun)
# print(nodes_edge.nodes)
# print(nodes_edge.edges)



def analyze_solidity_file(file_path):
    if not file_path.endswith(".sol"):
        print("Error: Please provide a Solidity (.sol) file.")
        return
    else:
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            print(content)

            # vulnerabilities = analyze_solidity_code(content)
            compiled = compile_contract(content)

            # Access the array of AST nodes for the contract "TestContract"
            ast = compiled['<stdin>:ReentrancyExample']['ast']['nodes']


            state_chng = state_changes(ast)
            external_fun = detect_external_calls(ast)
            nodes_edge = traverse_ast_iteratively(ast)
            vuln=analyze_retrancy(state_chng,external_fun,nodes_edge)
            print(vuln)
            
           
            
        except FileNotFoundError:
            print(f"Error: The file '{file_path}' was not found.")
        except Exception as e:
            print(f"An error occurred: {e}")



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <solidity_file.sol>")
    else:
        analyze_solidity_file(sys.argv[1])
