from pathlib import Path
import sys
from typing import List, Union
import binaryninja as bn
import binaryninjaui as ui

from binaryninja.settings import Settings
from PySide6.QtWidgets import QWidget, QLabel, QPushButton, QCheckBox, QKeySequenceEdit, QLineEdit, QHBoxLayout, QVBoxLayout
from PySide6.QtGui import QKeySequence, QFontMetrics
from PySide6.QtCore import Qt, QSettings

from .QCodeEditor import QCodeEditor
from .snippet_base import SNIPPETS_PATH, load_snippet


class Editor(QWidget):
	def __init__(self, context: ui.UIContext, parent: QWidget | None = None) -> None:
		QWidget.__init__(self, parent)

		self.snippet = None
		self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
		self.title = QLabel(self.tr("Snippet Editor"))
		self.setWindowTitle(self.title.text())

		self.saveButton = QPushButton(self.tr("&Save"))
		self.saveButton.setShortcut(QKeySequence(self.tr("Ctrl+Shift+S")))
		self.exportButton = QPushButton(self.tr("&Export to plugin"))
		self.exportButton.setShortcut(QKeySequence(self.tr("Ctrl+E")))
		self.runButton = QPushButton(self.tr("&Run"))
		self.runButton.setShortcut(QKeySequence(self.tr("Ctrl+R")))
		self.editButton = QPushButton(self.tr("Open in Editor"))
		self.updateAnalysis = QCheckBox(self.tr("Update analysis when run"))
		self.clearHotkeyButton = QPushButton(self.tr("Clear Hotkey"))
		# self.updateAnalysis.stateChanged.connect(self.setGlobalUpdateFlag)

		indentation = Settings().get_string("snippets.indentation")
		self.edit = QCodeEditor(delimeter=indentation)
		self.edit.setPlaceholderText("Insert your snippet code here")
		self.resetting = False
		self.context = context

		self.keySequenceEdit = QKeySequenceEdit(self)
		self.currentHotkey = QKeySequence()
		self.currentHotkeyLabel = QLabel("")
		self.currentFile = ""
		self.snippetName = QLineEdit()
		self.snippetName.setPlaceholderText("snippet filename")
		self.snippetDescription = QLineEdit()
		self.snippetDescription.setPlaceholderText("optional description")

		#Make disabled edit boxes visually distinct
		self.setStyleSheet("QLineEdit:disabled, QCodeEditor:disabled { background-color: palette(window); }")

		#Set Editbox Size
		font = ui.getMonospaceFont(self)
		self.edit.setFont(font)
		font = QFontMetrics(font)

		# indentation_character = " "
		# if Settings().get_bool("snippets.inde"):
		self.edit.setTabStopDistance(4 * font.horizontalAdvance(' ')) #TODO, replace with settings API


		# Create layout and add widgets
		optionsAndButtons = QVBoxLayout()

		options = QHBoxLayout()
		options.addWidget(self.clearHotkeyButton)
		options.addWidget(self.keySequenceEdit)
		options.addWidget(self.currentHotkeyLabel)
		options.addWidget(self.updateAnalysis)

		buttons = QHBoxLayout()
		buttons.addWidget(self.exportButton)
		buttons.addWidget(self.editButton)
		buttons.addWidget(self.runButton)
		buttons.addWidget(self.saveButton)

		optionsAndButtons.addLayout(options)
		optionsAndButtons.addLayout(buttons)

		description = QHBoxLayout()
		description.addWidget(QLabel(self.tr("Filename: ")))
		description.addWidget(self.snippetName)
		description.addWidget(QLabel(self.tr("Description: ")))
		description.addWidget(self.snippetDescription)

		# vlayoutWidget = QWidget()
		vlayout = QVBoxLayout()
		# margins = vlayout.getContentsMargins()
		# vlayout.setContentsMargins(0, margins[1], 0, margins[3])
		vlayout.addLayout(description)
		vlayout.addWidget(self.edit)
		vlayout.addLayout(optionsAndButtons)
		# vlayoutWidget.setLayout(vlayout)

		# hlayout = QHBoxLayout()
		# hlayout.addWidget(vlayout)

		self.settings = QSettings("Vector 35", "Snippet Editor")

		if self.settings.contains("ui/snippeteditor/geometry"):
			self.restoreGeometry(self.settings.value("ui/snippeteditor/geometry"))
		else:
			self.edit.setMinimumWidth(80 * font.averageCharWidth())
			self.edit.setMinimumHeight(30 * font.lineSpacing())

		# Set dialog layout
		self.setLayout(vlayout)

		# Add signals
		# self.saveButton.clicked.connect(self.save)
		# self.editButton.clicked.connect(self.editor)
		self.runButton.clicked.connect(lambda: self.snippet.run(self.context) if self.snippet else None)
		# self.exportButton.clicked.connect(self.export)
		# self.clearHotkeyButton.clicked.connect(self.clearHotkey)
		# self.tree.selectionModel().selectionChanged.connect(self.selectFile)
		# self.newSnippetButton.clicked.connect(self.newFileDialog)
		# self.deleteSnippetButton.clicked.connect(self.deleteSnippet)
		# self.browseButton.clicked.connect(self.browseSnippets)

		# if self.settings.contains("ui/snippeteditor/selected"):
		# 	selectedName = self.settings.value("ui/snippeteditor/selected")
		# 	self.tree.selectionModel().select(self.files.index(selectedName), QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)

		# 	if self.tree.selectionModel().hasSelection():
		# 		self.selectFile(self.tree.selectionModel().selection(), None)
		# 		self.edit.setFocus()
		# 		cursor = self.edit.textCursor()
		# 		cursor.setPosition(self.edit.document().characterCount()-1)
		# 		self.edit.setTextCursor(cursor)
		# 	else:
		# 		self.readOnly(True)
		# else:
		# 	self.readOnly(True)

	@staticmethod
	def createPane(context) -> "Editor":
		global EDITORS
		if not Editor.canCreatePane(context):
			return

		# TODO: Add the option to open the editor in its own window
		# It's possible if WidgetPane and openPane are not called but shiboken
		# drops them from memory and the window is destroyed an unhandled exception
		# at the end of __init__ fixes that but that's horrible
		widget = Editor(context)
		EDITORS.append(widget)
		pane = ui.WidgetPane(widget, "Snippet Editor")

		def onEditorClose():
			EDITORS.remove(widget)

		widget.destroyed.connect(onEditorClose)

		# if not context.binaryView:
			# pane.moveToNewWindow()

		context.context.openPane(pane)
		return widget

	@staticmethod
	def canCreatePane(context) -> bool:
		# return context.context
		return True

	def openSnippet(self, path: Union[Path, str]):
		self.snippet = load_snippet(path)
		code = self.snippet.renderableCode

		self.edit.clear()

		if hasattr(self.edit, "number_bar") and self.edit.number_bar is not None:
			self.edit.number_bar.offset = code[0]

		self.edit.setPlainText(code[1])

EDITORS: List[Editor] = []
