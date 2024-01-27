from pathlib import Path
from typing import List, Union
import binaryninja as bn
import binaryninjaui as ui

from binaryninja.settings import Settings
from PySide6.QtWidgets import QWidget, QLabel, QKeySequenceEdit, QLineEdit, QHBoxLayout, QVBoxLayout
from PySide6.QtGui import QKeySequence, QFontMetrics
from PySide6.QtCore import Qt, QSettings, QSize

from .QCodeEditor import QCodeEditor
from .snippet_base import SNIPPETS_PATH, load_snippet
from .utils import makeFloppyIcon, makePlayIcon


class Editor(QWidget):
	def __init__(self, context: ui.UIContext, parent: QWidget | None = None) -> None:
		QWidget.__init__(self, parent)

		self.snippet = None
		self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
		self.title = QLabel(self.tr("Snippet Editor"))
		self.setWindowTitle(self.title.text())

		indentation = Settings().get_string("snippets.indentation")
		self.edit = QCodeEditor(delimeter=indentation)
		self.edit.setPlaceholderText("Insert your snippet code here")
		self.resetting = False
		self.context = context

		# self.snippetName = QLineEdit()
		# self.snippetName.setPlaceholderText("snippet filename")
		# self.snippetDescription = QLineEdit()
		# self.snippetDescription.setPlaceholderText("optional description")

		# Make disabled edit boxes visually distinct
		self.setStyleSheet("QLineEdit:disabled, QCodeEditor:disabled { background-color: palette(window); }")

		# Set Editbox Size
		font = ui.getMonospaceFont(self)
		self.edit.setFont(font)
		font = QFontMetrics(font)

		# indentation_character = " "
		# if Settings().get_bool("snippets.inde"):
		self.edit.setTabStopDistance(4 * font.horizontalAdvance(' ')) #TODO, replace with settings API

		# description = QHBoxLayout()
		# description.addWidget(QLabel(self.tr("Filename: ")))
		# description.addWidget(self.snippetName)
		# description.addWidget(QLabel(self.tr("Description: ")))
		# description.addWidget(self.snippetDescription)

		vlayout = QVBoxLayout()
		vlayout.setContentsMargins(0, 0, 0, 0)
		# vlayout.addLayout(description)
		vlayout.addWidget(self.edit)

		self.settings = QSettings("Vector 35", "Snippet Editor")

		if self.settings.contains("ui/snippeteditor/geometry"):
			self.restoreGeometry(self.settings.value("ui/snippeteditor/geometry"))
		else:
			self.edit.setMinimumWidth(80 * font.averageCharWidth())
			self.edit.setMinimumHeight(30 * font.lineSpacing())

		# Set dialog layout
		self.setLayout(vlayout)

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

		# if not hasattr(context, "binaryView"):
		# 	pane.setWindowModality(Qt.WindowModal)

		found = False
		for child in pane.children():
			for subChild in child.children():
				if isinstance(subChild, ui.PaneHeader):
					found = True

					# TODO: Make the play button scalable by settings
					# TODO: Make the play button a stop button when the snippet is running and back to play when it's done
					play = ui.ClickableIcon(makePlayIcon(), QSize(20, 20))
					play.clicked.connect(lambda: widget.snippet.run(context) if widget.snippet else None)
					subChild.layout().addWidget(play)

					save = ui.ClickableIcon(makeFloppyIcon(), QSize(20, 20))
					save.clicked.connect(lambda: widget.snippet.save() if widget.snippet else None)
					subChild.layout().addWidget(save)


					break

			if found:
				break

		context.context.openPane(pane)
		# pane.setIsActivePane(True)
		return widget

	@staticmethod
	def canCreatePane(context) -> bool:
		# return context.context
		return True

	def openSnippet(self, path: Union[Path, str]):
		if self.snippet is not None:
			# TODO: Track dirtyness and ask for save
			self.snippet.save()
			self.edit.textChanged.disconnect()
			del self.snippet

		self.snippet = load_snippet(path)
		code = self.snippet.renderableCode

		self.edit.clear()

		if hasattr(self.edit, "number_bar") and self.edit.number_bar is not None:
			self.edit.number_bar.offset = code[0]

		self.edit.setPlainText(code[1])
		self.edit.textChanged.connect(lambda: self.snippet.updateCode(self.edit.toPlainText()))

EDITORS: List[Editor] = []
