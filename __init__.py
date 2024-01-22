import binaryninja as bn
import binaryninjaui as ui

from PySide6.QtWidgets import QTextBrowser, QWidget, QVBoxLayout, QLabel
from .editor import Editor
from .snippet_base import load_all_snippets, run_last_snippet
from .python_snippet import PythonSnippet as _

load_all_snippets()

ui.UIAction.registerAction("Snippets\\Snippet Editor...")
ui.UIAction.registerAction("Snippets\\Rerun Last Snippet")
ui.UIAction.registerAction("Snippets\\Reload All Snippets")
ui.UIActionHandler.globalActions().bindAction("Snippets\\Snippet Editor...", ui.UIAction(Editor.createPane, Editor.canCreatePane))
ui.UIActionHandler.globalActions().bindAction("Snippets\\Rerun Last Snippet", ui.UIAction(run_last_snippet))
ui.UIActionHandler.globalActions().bindAction("Snippets\\Reload All Snippets", ui.UIAction(load_all_snippets))
ui.Menu.mainMenu("Plugins").addAction("Snippets\\Snippet Editor...", "Snippet")
ui.Menu.mainMenu("Plugins").addAction("Snippets\\Rerun Last Snippet", "Snippet")
ui.Menu.mainMenu("Plugins").addAction("Snippets\\Reload All Snippets", "Snippet")
