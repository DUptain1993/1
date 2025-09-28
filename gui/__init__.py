"""
Enhanced GUI Module for The Stealer
Modern graphical user interface components.
"""

__version__ = "2.0.0"
__author__ = "Akki (Akhand Raj)"

from .main_window import MainWindow
from .dialogs import SettingsDialog, AboutDialog, ProgressDialog
from .widgets import DataViewer, LogViewer, StatusBar

__all__ = [
    'MainWindow',
    'SettingsDialog', 
    'AboutDialog',
    'ProgressDialog',
    'DataViewer',
    'LogViewer',
    'StatusBar'
]