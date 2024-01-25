from collections import namedtuple
from binaryninjaui import UIContext
from PySide6.QtCore import QLine, QRectF, QLineF
from PySide6.QtGui import QImage, QPainter, QPen, QColor

def getContext():
	ctx = UIContext.activeContext()
	dummycontext = {'binaryView': None, 'address': None, 'function': None, 'token': None, 'lowLevelILFunction': None, 'mediumLevelILFunction': None}

	if not ctx:
		ctx = UIContext.allContexts()[0]

	if not ctx:
		#There is no tab open at all but we still want other snippest to run that don't rely on context.
		context = namedtuple("context", dummycontext.keys())(*dummycontext.values())

	else:
		handler = ctx.contentActionHandler()
		if handler:
			context = handler.actionContext()
		else:
			context = namedtuple("context", dummycontext.keys())(*dummycontext.values())

	return context

def makeReloadIcon() -> QImage:
	icon = QImage(56, 56, QImage.Format.Format_RGB32)
	icon.fill(0)

	painter = QPainter()
	painter.begin(icon)
	painter.setRenderHint(QPainter.RenderHint.Antialiasing)

	# Draw the circular arrow
	pen = QPen(QColor("white"), 3)
	painter.setPen(pen)
	painter.drawArc(QRectF(12, 12, 34, 34), 82 * 16, 280 * 16)  # Start at 315 degrees, span 270 degrees

	# Draw arrowhead
	painter.drawLine(QLineF(29, 7, 36, 13))
	painter.drawLine(QLineF(36, 13, 29, 19))

	painter.end()

	return icon

def makePlusMenuIcon() -> QImage:
	"""Creates a plus menu icon using QPainter to draw it."""
	# Create an image to draw on
	icon = QImage(56, 56, QImage.Format.Format_RGB32)
	icon.fill(0)

	painter = QPainter()
	painter.begin(icon)
	painter.setRenderHint(QPainter.RenderHint.Antialiasing)
	painter.setPen(QPen(QColor("white"), 5))

	horizontal_line = QLine(12, 28, 44, 28)
	painter.drawLine(horizontal_line)
	vertical_line = QLine(28, 12, 28, 44)
	painter.drawLine(vertical_line)

	painter.end()

	return icon
