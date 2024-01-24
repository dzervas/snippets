from pathlib import Path
from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler, ClickableIcon
from PySide6.QtCore import Qt, QFileSystemWatcher, QRectF, QSize, QDir, QFileInfo
from PySide6.QtGui import QIcon, QImage, QPainter, QColor, QFont, QPixmap, QCursor, QGuiApplication
from PySide6.QtWidgets import QPushButton, QFileSystemModel, QTreeView, QAbstractItemView, QHeaderView, QHBoxLayout, QVBoxLayout, QWidget, QLineEdit, QMenu, QMessageBox, QInputDialog, QSplitter, QLayout

from .utils import makePlusMenuIcon, makeReloadIcon
from .snippet_base import SNIPPETS_PATH, load_all_snippets


class SnippetSidebar(SidebarWidget):
	def __init__(self, frame, data):
		SidebarWidget.__init__(self, "Snippet Editor")
		self.frame = frame
		self.data = data
		snippets_path_abs = str(SNIPPETS_PATH.resolve())

		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		self.browseButton = QPushButton("Browse Snippets")
		self.browseButton.setIcon(QIcon.fromTheme("edit-undo"))
		self.deleteSnippetButton = QPushButton("Delete")
		self.newSnippetButton = QPushButton("New Snippet")
		self.watcher = QFileSystemWatcher()
		self.watcher.addPath(snippets_path_abs)
		# self.watcher.directoryChanged.connect(self.snippetDirectoryChanged)
		# self.watcher.fileChanged.connect(self.snippetDirectoryChanged)

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
		self.tree.setSortingEnabled(True)
		self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
		self.tree.customContextMenuRequested.connect(self.contextMenu)
		self.tree.hideColumn(2)
		self.tree.sortByColumn(0, Qt.AscendingOrder)
		self.tree.setRootIndex(self.files.index(snippets_path_abs))
		# self.tree.doubleClicked.connect(self.openSnippet)

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

	def contextMenu(self, position):
		menu = QMenu()

		run = menu.addAction("Run")
		# run.triggered.connect(self.runSnippet)

		menu.addSeparator()
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
		# index = self.tree.selectedIndexes()[::self.files.columnCount() - 1][0] # treeview returns each selected element in the row
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


class SnippetSidebarType(SidebarWidgetType):
	def __init__(self):
		icon = QImage(56, 56, QImage.Format_RGB32)
		icon.fill(0)

		p = QPainter()
		p.begin(icon)
		p.setFont(QFont("Open Sans", 56))
		p.setPen(QColor(255, 255, 255, 255))
		p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "S")
		p.end()

		SidebarWidgetType.__init__(self, icon, "Snippet Editor")

	def createWidget(self, frame, data):
		return SnippetSidebar(frame, data)


Sidebar.addSidebarWidgetType(SnippetSidebarType())
