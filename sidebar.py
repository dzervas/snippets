import binaryninja as bn
from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, ClickableIcon
from PySide6.QtCore import QModelIndex, QPoint, Qt, QFileSystemWatcher, QRectF, QSize, QDir, QFileInfo
from PySide6.QtGui import QImage, QPainter, QColor, QFont, QCursor, QGuiApplication
from PySide6.QtWidgets import QFileSystemModel, QTreeView, QAbstractItemView, QHeaderView, QHBoxLayout, QVBoxLayout, QWidget, QLineEdit, QMenu, QMessageBox, QInputDialog, QSplitter

from .editor import Editor, EDITORS
from .utils import getContext, makePlusMenuIcon, makeReloadIcon, makeSnippetsIcon
from .snippet_base import SNIPPETS_PATH, load_all_snippets, load_snippet


class SnippetSidebar(SidebarWidget):
	def __init__(self, frame, data):
		SidebarWidget.__init__(self, "Snippets")
		self.frame = frame
		self.data = data
		snippets_path_abs = str(SNIPPETS_PATH.resolve())

		self.watcher = QFileSystemWatcher()
		self.watcher.addPath(snippets_path_abs)
		self.watcher.directoryChanged.connect(load_all_snippets)
		self.watcher.fileChanged.connect(load_all_snippets)

		# Make disabled edit boxes visually distinct
		self.setStyleSheet("QLineEdit:disabled, QCodeEditor:disabled { background-color: palette(window); }")

		# Files
		self.files = QFileSystemModel()
		self.files.setRootPath(snippets_path_abs)
		self.files.setReadOnly(False)

		# Tree
		self.tree = QTreeView()
		self.tree.setModel(self.files)
		self.tree.setDragDropMode(QAbstractItemView.InternalMove)
		self.tree.setDragEnabled(True)
		self.tree.setDefaultDropAction(Qt.MoveAction)
		self.tree.setEditTriggers(QAbstractItemView.EditKeyPressed | QAbstractItemView.SelectedClicked)
		self.tree.setSortingEnabled(True)
		self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
		self.tree.customContextMenuRequested.connect(self.contextMenu)
		self.tree.hideColumn(2)
		self.tree.sortByColumn(0, Qt.AscendingOrder)
		self.tree.setRootIndex(self.files.index(snippets_path_abs))
		self.tree.doubleClicked.connect(self.openEditor)

		for x in range(self.files.columnCount() - 1):
			self.tree.resizeColumnToContents(x)
			self.tree.header().setSectionResizeMode(x, QHeaderView.ResizeToContents)

		self.output = QTreeView()

		self.treeSplitter = QSplitter(Qt.Vertical)
		self.treeSplitter.addWidget(self.tree)
		self.treeSplitter.addWidget(self.output)
		self.treeSplitter.setChildrenCollapsible(True)

		self.treeLayout = QVBoxLayout()
		self.treeLayout.setSpacing(0)
		self.treeLayout.setContentsMargins(0, 0, 0, 0)
		self.treeLayout.addWidget(self.treeSplitter)
		self.treeSplitter.setSizes([100000, 200000])

		self.setLayout(self.treeLayout)

		# Header
		self.search = QLineEdit()
		self.search.setPlaceholderText("Search Snippets")

		self.addButton = ClickableIcon(makePlusMenuIcon(), QSize(20, 20))
		# self.addButton.clicked.connect(self.newSnippet)
		self.refreshButton = ClickableIcon(makeReloadIcon(), QSize(20, 20))
		self.addButton.clicked.connect(load_all_snippets)

		self.headerWidgetLayout = QHBoxLayout()
		self.headerWidgetLayout.setContentsMargins(0, 0, 0, 0)
		self.headerWidgetLayout.addWidget(self.search)
		self.headerWidgetLayout.addWidget(self.refreshButton)
		self.headerWidgetLayout.addWidget(self.addButton)
		self._headerWidget = QWidget()
		self._headerWidget.setLayout(self.headerWidgetLayout)

	def headerWidget(self):
		return self._headerWidget

	def contextMenu(self, position: QPoint):
		menu = QMenu()

		index = self.tree.indexAt(position)

		if index.isValid():
			run = menu.addAction("Run")
			run.triggered.connect(self.runSnippet)

			menu.addSeparator()
			editInNew = menu.addAction("Edit in New Pane")
			editInNew.triggered.connect(self.openSnippetInNewPane)
			copyPath = menu.addAction("Copy Path")
			copyPath.triggered.connect(self.copyPath)
			duplicate = menu.addAction("Duplicate")
			# duplicate.triggered.connect(self.duplicateSnippet)
			delete = menu.addAction("Delete")
			delete.triggered.connect(self.deleteSnippet)

			menu.addSeparator()

		newFolder = menu.addAction("New Folder")
		newFolder.triggered.connect(self.newFolder)

		menu.exec_(QCursor.pos())

	def copyPath(self):
		index = self.tree.selectionModel().currentIndex()
		selection = self.files.filePath(index)
		clip = QGuiApplication.clipboard()
		clip.setText(selection)

	def deleteSnippet(self):
		index = self.tree.selectionModel().currentIndex()
		snippetName = self.files.fileName(index)

		if self.files.isDir(index):
			questionText = self.tr("Confirm deletion of folder AND ALL CONTENTS: ")
		else:
			questionText = self.tr("Confirm deletion of snippet: ")

		question = QMessageBox.question(self, self.tr("Confirm"), questionText + snippetName)

		if (question != QMessageBox.StandardButton.Yes):
			return

		self.tree.clearSelection()
		# log_debug("Snippets: Deleting %s." % snippetName)
		# if snippetName == example_name:
		# 	question = QMessageBox.question(self, self.tr("Confirm"), self.tr("Should snippets prevent this file from being recreated?"))
		# 	if (question == QMessageBox.StandardButton.Yes):
		# 		Path(rm_dst_examples).touch()
		self.files.remove(index)
		load_all_snippets()

	def newFolder(self):
		(folderName, ok) = QInputDialog.getText(self, self.tr("Create New Folder"), self.tr("New Folder Name: "))
		if ok and folderName:
			index = self.tree.selectionModel().currentIndex()
			selection = self.files.filePath(index)
			if QFileInfo(selection).isDir():
				QDir(selection).mkdir(folderName)
			else:
				QDir(str(SNIPPETS_PATH.resolve())).mkdir(folderName)

	def openEditor(self, index: QModelIndex, force_new=False):
		global EDITORS
		if self.files.isDir(index):
			return

		if len(EDITORS) > 0 and not force_new:
			editor = EDITORS[-1]
		else:
			editor = Editor.createPane(getContext())

		try:
			editor.openSnippet(self.files.filePath(index))
		except ValueError:
			return
		except RuntimeError:
			# The editor object got deleted from memory
			if len(EDITORS) > 0:
				EDITORS.remove(editor)
				del editor
			return self.openEditor(index)

		self.tree.clearSelection()

	def openSnippetInNewPane(self):
		index = self.tree.selectionModel().currentIndex()
		self.openEditor(index, force_new=True)

	def runSnippet(self):
		index = self.tree.selectionModel().currentIndex()

		try:
			snippet = load_snippet(self.files.filePath(index))
		except ValueError:
			return

		snippet.run()


class SnippetSidebarType(SidebarWidgetType):
	def __init__(self):
		SidebarWidgetType.__init__(self, makeSnippetsIcon(), "Snippets")

	def createWidget(self, frame, data):
		return SnippetSidebar(frame, data)


Sidebar.addSidebarWidgetType(SnippetSidebarType())
