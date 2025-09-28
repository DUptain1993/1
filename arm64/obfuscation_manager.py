"""
Advanced Obfuscation Manager for Android Applications
Comprehensive obfuscation techniques for Android malware evasion.
"""

import random
import string
import logging
from typing import Dict, List, Any, Optional
import base64
import hashlib

class ObfuscationManager:
    """
    Advanced obfuscation manager with multiple evasion techniques.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the obfuscation manager.
        
        Args:
            config: Obfuscation configuration dictionary
        """
        self.config = config or self._default_config()
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Initialize obfuscation components
        self._obfuscation_methods = {}
        self._name_mappings = {}
        
    def _default_config(self) -> Dict[str, Any]:
        """Return default obfuscation configuration."""
        return {
            'obfuscation': {
                'methods': ['name_obfuscation', 'control_flow', 'string_encryption', 'reflection', 'dynamic_loading'],
                'name_length': 8,
                'preserve_names': ['onCreate', 'onResume', 'onStart', 'onDestroy'],
                'obfuscation_level': 'high'
            },
            'string_obfuscation': {
                'methods': ['xor', 'base64', 'hex', 'unicode', 'split'],
                'key_length': 16,
                'split_size': 4
            },
            'control_flow': {
                'methods': ['junk_code', 'opaque_predicates', 'dead_code', 'loop_unrolling'],
                'junk_ratio': 0.3,
                'complexity_level': 'high'
            },
            'reflection': {
                'enabled': True,
                'obfuscate_methods': True,
                'obfuscate_classes': True,
                'obfuscate_fields': True
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def obfuscate_java_code(self, java_code: str, method: str = 'name_obfuscation') -> Dict[str, Any]:
        """
        Obfuscate Java code using specified method.
        
        Args:
            java_code: Java code to obfuscate
            method: Obfuscation method to use
            
        Returns:
            Dictionary containing obfuscated code and metadata
        """
        try:
            if method == 'name_obfuscation':
                return self._obfuscate_names(java_code)
            elif method == 'control_flow':
                return self._obfuscate_control_flow(java_code)
            elif method == 'string_encryption':
                return self._obfuscate_strings(java_code)
            elif method == 'reflection':
                return self._obfuscate_with_reflection(java_code)
            elif method == 'dynamic_loading':
                return self._obfuscate_with_dynamic_loading(java_code)
            else:
                raise ValueError(f"Unsupported obfuscation method: {method}")
                
        except Exception as e:
            self.logger.error(f"Java code obfuscation failed: {e}")
            raise
    
    def _obfuscate_names(self, java_code: str) -> Dict[str, Any]:
        """Obfuscate variable and method names."""
        try:
            obfuscated_code = java_code
            name_mappings = {}
            
            # Find all variable names and method names
            import re
            
            # Find variable declarations
            var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*='
            variables = re.findall(var_pattern, java_code)
            
            # Find method names
            method_pattern = r'\b(?:public|private|protected)?\s*(?:static)?\s*(?:void|String|int|boolean|Object)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            methods = re.findall(method_pattern, java_code)
            
            # Generate obfuscated names
            all_names = set()
            for var_type, var_name in variables:
                all_names.add(var_name)
            for method_name in methods:
                all_names.add(method_name)
            
            # Filter out preserved names
            all_names = all_names - set(self.config['obfuscation']['preserve_names'])
            
            # Generate obfuscated names
            for name in all_names:
                if name not in name_mappings:
                    obfuscated_name = self._generate_obfuscated_name()
                    name_mappings[name] = obfuscated_name
            
            # Replace names in code
            for original_name, obfuscated_name in name_mappings.items():
                # Use word boundaries to avoid partial replacements
                pattern = r'\b' + re.escape(original_name) + r'\b'
                obfuscated_code = re.sub(pattern, obfuscated_name, obfuscated_code)
            
            return {
                'method': 'name_obfuscation',
                'obfuscated_code': obfuscated_code,
                'name_mappings': name_mappings,
                'metadata': {
                    'original_length': len(java_code),
                    'obfuscated_length': len(obfuscated_code),
                    'names_obfuscated': len(name_mappings)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Name obfuscation failed: {e}")
            raise
    
    def _generate_obfuscated_name(self) -> str:
        """Generate obfuscated name."""
        try:
            # Generate random name
            length = self.config['obfuscation']['name_length']
            
            # Use mix of letters and numbers
            chars = string.ascii_letters + string.digits
            name = ''.join(random.choice(chars) for _ in range(length))
            
            # Ensure it doesn't start with a number
            if name[0].isdigit():
                name = random.choice(string.ascii_letters) + name[1:]
            
            return name
            
        except Exception as e:
            self.logger.error(f"Obfuscated name generation failed: {e}")
            return f"var{random.randint(1000, 9999)}"
    
    def _obfuscate_control_flow(self, java_code: str) -> Dict[str, Any]:
        """Obfuscate control flow with junk code and opaque predicates."""
        try:
            obfuscated_code = java_code
            
            # Add junk code
            junk_code = self._generate_junk_code()
            
            # Insert junk code at random locations
            lines = obfuscated_code.split('\n')
            junk_ratio = self.config['control_flow']['junk_ratio']
            num_junk_lines = int(len(lines) * junk_ratio)
            
            for _ in range(num_junk_lines):
                insert_pos = random.randint(0, len(lines))
                junk_line = random.choice(junk_code)
                lines.insert(insert_pos, junk_line)
            
            obfuscated_code = '\n'.join(lines)
            
            # Add opaque predicates
            obfuscated_code = self._add_opaque_predicates(obfuscated_code)
            
            return {
                'method': 'control_flow',
                'obfuscated_code': obfuscated_code,
                'metadata': {
                    'original_length': len(java_code),
                    'obfuscated_length': len(obfuscated_code),
                    'junk_lines_added': num_junk_lines
                }
            }
            
        except Exception as e:
            self.logger.error(f"Control flow obfuscation failed: {e}")
            raise
    
    def _generate_junk_code(self) -> List[str]:
        """Generate junk code for obfuscation."""
        try:
            junk_code = [
                'int temp = (int) (Math.random() * 1000);',
                'String dummy = "obfuscated_" + System.currentTimeMillis();',
                'boolean flag = (temp % 2) == 0;',
                'if (flag) { temp++; } else { temp--; }',
                'long timestamp = System.currentTimeMillis();',
                'Object obj = new Object();',
                'int[] array = new int[10];',
                'for (int i = 0; i < array.length; i++) { array[i] = i; }',
                'StringBuilder sb = new StringBuilder();',
                'sb.append("junk");',
                'if (temp > 500) { temp = temp / 2; }',
                'double value = Math.sin(temp);',
                'boolean condition = (value > 0.5);',
                'if (condition) { dummy = dummy.toUpperCase(); }',
                'int hash = dummy.hashCode();',
                'hash = hash ^ 0x12345678;',
                'String result = Integer.toHexString(hash);',
                'if (result.length() > 8) { result = result.substring(0, 8); }',
                'char[] chars = result.toCharArray();',
                'for (char c : chars) { if (c > 0) { temp++; } }'
            ]
            
            return junk_code
            
        except Exception as e:
            self.logger.error(f"Junk code generation failed: {e}")
            return ['int temp = 0;']
    
    def _add_opaque_predicates(self, java_code: str) -> str:
        """Add opaque predicates to obfuscate control flow."""
        try:
            # Find if statements and add opaque predicates
            import re
            
            # Pattern to find if statements
            if_pattern = r'(\s*)(if\s*\([^)]+\)\s*\{)'
            
            def add_predicate(match):
                indent = match.group(1)
                if_statement = match.group(2)
                
                # Generate opaque predicate
                predicate = self._generate_opaque_predicate()
                
                return f"{indent}{predicate}\n{indent}{if_statement}"
            
            obfuscated_code = re.sub(if_pattern, add_predicate, java_code)
            
            return obfuscated_code
            
        except Exception as e:
            self.logger.error(f"Opaque predicate addition failed: {e}")
            return java_code
    
    def _generate_opaque_predicate(self) -> str:
        """Generate opaque predicate."""
        try:
            predicates = [
                'if ((System.currentTimeMillis() % 2) == 0) {',
                'if (Math.random() > 0.5) {',
                'if ((new Object().hashCode() % 2) == 0) {',
                'if (Thread.currentThread().getId() % 2 == 0) {',
                'if (Runtime.getRuntime().availableProcessors() > 1) {'
            ]
            
            return random.choice(predicates)
            
        except Exception as e:
            self.logger.error(f"Opaque predicate generation failed: {e}")
            return 'if (true) {'
    
    def _obfuscate_strings(self, java_code: str) -> Dict[str, Any]:
        """Obfuscate string literals."""
        try:
            import re
            
            obfuscated_code = java_code
            string_mappings = {}
            
            # Find string literals
            string_pattern = r'"([^"]*)"'
            strings = re.findall(string_pattern, java_code)
            
            for string_literal in strings:
                if string_literal not in string_mappings:
                    # Choose obfuscation method
                    method = random.choice(self.config['string_obfuscation']['methods'])
                    
                    if method == 'xor':
                        obfuscated_string = self._xor_obfuscate_string(string_literal)
                    elif method == 'base64':
                        obfuscated_string = self._base64_obfuscate_string(string_literal)
                    elif method == 'hex':
                        obfuscated_string = self._hex_obfuscate_string(string_literal)
                    elif method == 'unicode':
                        obfuscated_string = self._unicode_obfuscate_string(string_literal)
                    elif method == 'split':
                        obfuscated_string = self._split_obfuscate_string(string_literal)
                    else:
                        obfuscated_string = string_literal
                    
                    string_mappings[string_literal] = obfuscated_string
            
            # Replace strings in code
            for original_string, obfuscated_string in string_mappings.items():
                pattern = '"' + re.escape(original_string) + '"'
                obfuscated_code = re.sub(pattern, obfuscated_string, obfuscated_code)
            
            return {
                'method': 'string_encryption',
                'obfuscated_code': obfuscated_code,
                'string_mappings': string_mappings,
                'metadata': {
                    'original_length': len(java_code),
                    'obfuscated_length': len(obfuscated_code),
                    'strings_obfuscated': len(string_mappings)
                }
            }
            
        except Exception as e:
            self.logger.error(f"String obfuscation failed: {e}")
            raise
    
    def _xor_obfuscate_string(self, string_literal: str) -> str:
        """Obfuscate string using XOR."""
        try:
            key = random.randint(1, 255)
            obfuscated_bytes = []
            
            for char in string_literal:
                obfuscated_bytes.append(ord(char) ^ key)
            
            # Generate Java code
            java_code = f'new String(new int[]{{{", ".join(map(str, obfuscated_bytes))}}}, 0, {len(obfuscated_bytes)}).chars().map(c -> c ^ {key}).collect(StringBuilder::new, (sb, c) -> sb.append((char) c), StringBuilder::append).toString()'
            
            return java_code
            
        except Exception as e:
            self.logger.error(f"XOR string obfuscation failed: {e}")
            return f'"{string_literal}"'
    
    def _base64_obfuscate_string(self, string_literal: str) -> str:
        """Obfuscate string using Base64."""
        try:
            encoded = base64.b64encode(string_literal.encode()).decode()
            java_code = f'new String(Base64.decode("{encoded}", Base64.DEFAULT))'
            
            return java_code
            
        except Exception as e:
            self.logger.error(f"Base64 string obfuscation failed: {e}")
            return f'"{string_literal}"'
    
    def _hex_obfuscate_string(self, string_literal: str) -> str:
        """Obfuscate string using hex encoding."""
        try:
            hex_string = string_literal.encode().hex()
            java_code = f'new String(DatatypeConverter.parseHexBinary("{hex_string}"))'
            
            return java_code
            
        except Exception as e:
            self.logger.error(f"Hex string obfuscation failed: {e}")
            return f'"{string_literal}"'
    
    def _unicode_obfuscate_string(self, string_literal: str) -> str:
        """Obfuscate string using Unicode escapes."""
        try:
            unicode_string = ""
            for char in string_literal:
                unicode_string += f"\\u{ord(char):04x}"
            
            return f'"{unicode_string}"'
            
        except Exception as e:
            self.logger.error(f"Unicode string obfuscation failed: {e}")
            return f'"{string_literal}"'
    
    def _split_obfuscate_string(self, string_literal: str) -> str:
        """Obfuscate string by splitting it."""
        try:
            split_size = self.config['string_obfuscation']['split_size']
            parts = [string_literal[i:i+split_size] for i in range(0, len(string_literal), split_size)]
            
            java_code = f'String.join("", new String[]{{{", ".join(f'"{part}"' for part in parts)}}})'
            
            return java_code
            
        except Exception as e:
            self.logger.error(f"Split string obfuscation failed: {e}")
            return f'"{string_literal}"'
    
    def _obfuscate_with_reflection(self, java_code: str) -> Dict[str, Any]:
        """Obfuscate code using Java reflection."""
        try:
            obfuscated_code = java_code
            
            # Add reflection imports
            imports = '''
import java.lang.reflect.Method;
import java.lang.reflect.Field;
import java.lang.reflect.Constructor;
            '''
            
            # Add reflection helper methods
            reflection_methods = '''
    private static Object invokeMethod(Object obj, String methodName, Object... args) {
        try {
            Method method = obj.getClass().getDeclaredMethod(methodName);
            method.setAccessible(true);
            return method.invoke(obj, args);
        } catch (Exception e) {
            return null;
        }
    }
    
    private static void setField(Object obj, String fieldName, Object value) {
        try {
            Field field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(obj, value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static Object getField(Object obj, String fieldName) {
        try {
            Field field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception e) {
            return null;
        }
    }
            '''
            
            # Insert reflection code
            obfuscated_code = imports + '\n' + obfuscated_code + '\n' + reflection_methods
            
            return {
                'method': 'reflection',
                'obfuscated_code': obfuscated_code,
                'metadata': {
                    'original_length': len(java_code),
                    'obfuscated_length': len(obfuscated_code),
                    'reflection_methods_added': 3
                }
            }
            
        except Exception as e:
            self.logger.error(f"Reflection obfuscation failed: {e}")
            raise
    
    def _obfuscate_with_dynamic_loading(self, java_code: str) -> Dict[str, Any]:
        """Obfuscate code using dynamic loading."""
        try:
            obfuscated_code = java_code
            
            # Add dynamic loading imports
            imports = '''
import java.net.URL;
import java.net.URLClassLoader;
import java.io.File;
            '''
            
            # Add dynamic loading methods
            dynamic_methods = '''
    private static Class<?> loadClassDynamically(String className) {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }
    
    private static Object createInstanceDynamically(String className) {
        try {
            Class<?> clazz = loadClassDynamically(className);
            if (clazz != null) {
                return clazz.newInstance();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    private static void loadLibraryDynamically(String libraryName) {
        try {
            System.loadLibrary(libraryName);
        } catch (UnsatisfiedLinkError e) {
            e.printStackTrace();
        }
    }
            '''
            
            # Insert dynamic loading code
            obfuscated_code = imports + '\n' + obfuscated_code + '\n' + dynamic_methods
            
            return {
                'method': 'dynamic_loading',
                'obfuscated_code': obfuscated_code,
                'metadata': {
                    'original_length': len(java_code),
                    'obfuscated_length': len(obfuscated_code),
                    'dynamic_methods_added': 3
                }
            }
            
        except Exception as e:
            self.logger.error(f"Dynamic loading obfuscation failed: {e}")
            raise
    
    def generate_obfuscation_report(self, obfuscation_result: Dict[str, Any]) -> str:
        """
        Generate obfuscation report.
        
        Args:
            obfuscation_result: Result from obfuscation operation
            
        Returns:
            Formatted report string
        """
        try:
            report = f"""
# Android Obfuscation Report

## Summary
- **Method**: {obfuscation_result['method']}
- **Original Length**: {obfuscation_result['metadata']['original_length']} characters
- **Obfuscated Length**: {obfuscation_result['metadata']['obfuscated_length']} characters
- **Expansion Ratio**: {obfuscation_result['metadata']['obfuscated_length'] / obfuscation_result['metadata']['original_length']:.2f}

## Obfuscation Details
"""
            
            if 'name_mappings' in obfuscation_result:
                report += f"- **Names Obfuscated**: {obfuscation_result['metadata']['names_obfuscated']}\n"
                report += "- **Name Mappings**:\n"
                for original, obfuscated in obfuscation_result['name_mappings'].items():
                    report += f"  - {original} → {obfuscated}\n"
            
            if 'string_mappings' in obfuscation_result:
                report += f"- **Strings Obfuscated**: {obfuscation_result['metadata']['strings_obfuscated']}\n"
            
            if 'junk_lines_added' in obfuscation_result['metadata']:
                report += f"- **Junk Lines Added**: {obfuscation_result['metadata']['junk_lines_added']}\n"
            
            report += """
## Security Features
- **Anti-Analysis**: Enabled
- **Static Analysis Evasion**: High
- **Dynamic Analysis Evasion**: Medium
- **Reverse Engineering Difficulty**: High
            """
            
            return report.strip()
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return f"Report generation failed: {e}"
    
    def get_obfuscation_status(self) -> Dict[str, Any]:
        """
        Get current obfuscation manager status.
        
        Returns:
            Dictionary containing obfuscation manager status information
        """
        return {
            'config': self.config,
            'supported_methods': self.config['obfuscation']['methods'],
            'string_methods': self.config['string_obfuscation']['methods'],
            'control_flow_methods': self.config['control_flow']['methods'],
            'reflection_enabled': self.config['reflection']['enabled']
        }