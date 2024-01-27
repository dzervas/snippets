import binaryninja as bn
import binaryninjaui as ui

from .editor import Editor
from .sidebar import SnippetSidebar as _
from .snippet_base import load_all_snippets, run_last_snippet
from .python_snippet import PythonSnippet as _

bn.Settings().register_group("snippets", "Snippets")
bn.Settings().register_setting("snippets.indentation", """{
	"title" : "Indentation Syntax Highlighting",
	"type" : "string",
	"default" : "    ",
	"description" : "String to use for indentation in snippets (tip: to use a tab, copy/paste a tab from another text field and paste here)",
	"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
}""")

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
