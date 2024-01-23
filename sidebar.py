from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler, ClickableIcon
from PySide6.QtCore import Qt, QFileSystemWatcher, QRectF, QSize
from PySide6.QtGui import QIcon, QImage, QPainter, QColor, QFont, QPixmap, QCursor
from PySide6.QtWidgets import QPushButton, QFileSystemModel, QTreeView, QAbstractItemView, QHeaderView, QHBoxLayout, QVBoxLayout, QWidget, QLineEdit, QMenu

from .utils import makePlusMenuIcon, makeReloadIcon
from .snippet_base import SNIPPETS_PATH


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

		treeLayout = QVBoxLayout()
		treeLayout.setSpacing(0)
		treeLayout.setContentsMargins(0, 0, 0, 0)
		treeLayout.addWidget(self.tree)

		# treeButtons = QHBoxLayout()
		# treeButtons.addWidget(self.browseButton)
		# treeButtons.addWidget(self.newSnippetButton)
		# treeButtons.addWidget(self.deleteSnippetButton)
		# treeLayout.addLayout(treeButtons)

		# treeWidget = QWidget()
		# treeWidget.setLayout(treeLayout)

		# vlayout = QVBoxLayout()
		# vlayout.addWidget(self.tree)
		# vlayout.addWidget(treeButtons)
		#vlayout.addWidget(self.newFolderButton)
		self.setLayout(treeLayout)
		# self.show()
		# self.addWidget(self.tree)

		self.search = QLineEdit()
		self.search.setPlaceholderText("Search Snippets")

		addIcon = QPixmap(QSize(56, 56))
		# addIcon.fill(0)
		addIconPainter = QPainter()
		addIconPainter.begin(addIcon)
		addIconPainter.setFont(QFont("Open Sans", 56))
		addIconPainter.setPen(QColor(255, 255, 255, 255))
		addIconPainter.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "+")
		addIconPainter.end()

		self.addButton = ClickableIcon(makePlusMenuIcon(), QSize(20, 20))
		self.refreshButton = ClickableIcon(makeReloadIcon(), QSize(20, 20))

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
		# copyPath.triggered.connect(self.copyPath)
		duplicate = menu.addAction("Duplicate")
		# duplicate.triggered.connect(self.duplicateSnippet)
		delete = menu.addAction("Delete")
		# delete.triggered.connect(self.deleteSnippet)

		menu.addSeparator()
		newFolder = menu.addAction("New Folder")
		# newFolder.triggered.connect(self.newFolder)

		menu.exec_(QCursor.pos())


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
