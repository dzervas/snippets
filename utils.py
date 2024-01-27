from collections import namedtuple
from binaryninjaui import UIContext
from PySide6.QtCore import QLine, QRectF, QLineF, QRect, Qt
from PySide6.QtGui import QImage, QPainter, QPen, QColor, QFont, QPainterPath
import math

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
	painter.drawArc(QRectF(12, 12, 34, 34), 82 * 16, 280 * 16)  # Start at 82 degrees, span 280 degrees

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

def makePlayIcon(scale: float = 1.0) -> QImage:
	size = 56 * scale
	icon = QImage(size, size, QImage.Format.Format_RGB32)
	icon.fill(0)

	painter = QPainter()
	painter.begin(icon)
	painter.setRenderHint(QPainter.RenderHint.Antialiasing)
	painter.setPen(QPen(QColor("white"), 5))

	painter.drawLine(QLineF(12 + 0.1 * size, 12, 44 - 0.1 * size, size / 2))
	painter.drawLine(QLineF(44 - 0.1 * size, size / 2, 12 + 0.1 * size, size - 12))
	painter.drawLine(QLineF(12 + 0.1 * size, 12, 12 + 0.1 * size, size - 12))

	painter.end()

	return icon

def makeGearIcon() -> QImage:
	"""Creates a gear icon using QPainter to draw it."""
	# Create an image to draw on
	icon = QImage(56, 56, QImage.Format.Format_RGB32)
	icon.fill(0)

	painter = QPainter()
	painter.begin(icon)
	painter.setRenderHint(QPainter.RenderHint.Antialiasing)
	painter.setPen(QPen(QColor("white"), 5))

	for i in range(5):
		start_angle = i * 2 * (180 / 5) * 16
		span = (180 / 10) * 16

		# Outer arc
		painter.drawArc(QRectF(6, 6, 44, 44), start_angle, span)

		# Inner arc
		painter.drawArc(QRectF(14, 14, 28, 28), start_angle + span * 2, span)

		# Connect the arcs
		painter.drawLine(QLineF(
			22 * math.cos(math.radians(start_angle / 16)) + 28,
			22 * math.sin(math.radians(start_angle / 16)) + 28,
			14 * math.cos(math.radians(start_angle / 16)) + 28,
			14 * math.sin(math.radians(start_angle / 16)) + 28
		))

		painter.drawLine(QLineF(
			22 * math.cos(math.radians((start_angle - span) / 16)) + 28,
			22 * math.sin(math.radians((start_angle - span) / 16)) + 28,
			14 * math.cos(math.radians((start_angle - span) / 16)) + 28,
			14 * math.sin(math.radians((start_angle - span) / 16)) + 28
		))

	painter.end()

	return icon

def makeSnippetsIcon() -> QImage:
	icon = QImage(56, 56, QImage.Format_RGB32)
	icon.fill(0)

	painter = QPainter()
	painter.begin(icon)
	painter.setRenderHint(QPainter.RenderHint.Antialiasing)
	painter.setPen(QPen(QColor("white"), 5))

	# Left side
	painter.drawLine(QLine(12, 12, 12, 44))
	# Right side
	painter.drawLine(QLine(44, 12, 44, 44))

	# Top curl
	painter.drawArc(QRect(12, 6, 10, 10), 90 * 16, 90 * 16)
	painter.drawLine(QLine(16, 6, 48, 6))
	painter.drawArc(QRect(44, 6, 10, 10), 0, 360 * 16)

	# Bottom curl
	painter.drawArc(QRect(2, 44, 10, 10), 90 * 16, 180 * 16)
	painter.drawLine(QLine(12, 44, 34, 44))
	painter.drawArc(QRect(34, 44, 10, 10), 0, 360 * 16)
	painter.drawLine(QLine(12, 54, 38, 54))

	# Fake text
	painter.setFont(QFont("Open Sans", 10))
	painter.setPen(QPen(QColor("gray"), 3))
	painter.drawText(QRect(0, 0, 56, 56), Qt.AlignCenter, "hi")
	painter.end()

	return icon

def makeFloppyIcon() -> QImage:
	icon = QImage(56, 56, QImage.Format_RGB32)
	icon.fill(0)

	painter = QPainter()
	painter.begin(icon)
	painter.setRenderHint(QPainter.RenderHint.Antialiasing)
	painter.setPen(QPen(QColor("white"), 5))

	# Outline
	path = QPainterPath()
	path.moveTo(12, 44)
	path.lineTo(12, 12)
	path.lineTo(36, 12)
	path.lineTo(44, 20)
	path.lineTo(44, 44)
	path.lineTo(12, 44)
	painter.drawPath(path)

	# Top rectangle
	painter.drawRect(QRect(18, 12, 12, 8))

	# Center circle (actually 4 pixels off center on the Y)
	painter.drawEllipse(QRect(24, 28, 8, 8))

	painter.end()

	return icon
