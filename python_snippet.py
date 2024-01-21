from collections import namedtuple
from typing import Any
from .snippet_base import Snippet

class PythonSnippet(Snippet):
	type_name = "Python"
	file_extension = ".py"
	comment_line_start = "#"

	def setup_globals(self) -> dict[str, Any]:
		context = self.context()
		snippetGlobals = {}

		# BinaryView
		snippetGlobals["current_view"] = context.binaryView
		snippetGlobals["bv"] = context.binaryView

		# Function
		snippetGlobals["current_token"] = None
		snippetGlobals["current_hlil"] = None
		snippetGlobals["current_mlil"] = None
		snippetGlobals["current_function"] = None
		snippetGlobals["current_llil"] = None
		snippetGlobals["current_basic_block"] = None

		if context.function:
			snippetGlobals["current_function"] = context.function
			snippetGlobals["current_mlil"] = context.function.mlil
			snippetGlobals["current_hlil"] = context.function.hlil
			snippetGlobals["current_llil"] = context.function.llil

			snippetGlobals["current_basic_block"] = context.function.get_basic_block_at(context.address)

			if context.token:
				# Doubly nested because the first token is a HighlightTokenState
				snippetGlobals["current_token"] = context.token

		# Address
		snippetGlobals["here"] = context.address
		snippetGlobals["current_address"] = context.address
		snippetGlobals["current_selection"] = None

		if context.address is not None and isinstance(context.length, int):
			snippetGlobals["current_selection"] = (context.address, context.address+context.length)

		# UIContext
		snippetGlobals["uicontext"] = context

		return snippetGlobals

	def runner(self, **kwargs) -> None:
		snippetGlobals = self.setup_globals()
		snippetGlobals["inputs"] = namedtuple("inputs", kwargs.keys())(kwargs.values())

		if self.context.binaryView:
			self.context.binaryView.begin_undo_actions()

		exec("from binaryninja import *", snippetGlobals)
		exec(self.code, snippetGlobals)

		# if gUpdateAnalysisOnRun:
		# 	exec("bv.update_analysis_and_wait()", snippetGlobals)

		if self.context.binaryView:
			if "here" in snippetGlobals and hasattr(self.context, "address") and snippetGlobals['here'] != self.context.address:
				self.context.binaryView.file.navigate(self.context.binaryView.file.view, snippetGlobals['here'])

			if "current_address" in snippetGlobals and hasattr(self.context, "address") and snippetGlobals['current_address'] != self.context.address:
				self.context.binaryView.file.navigate(self.context.binaryView.file.view, snippetGlobals['current_address'])

			self.context.binaryView.commit_undo_actions()

Snippet.register(PythonSnippet)
