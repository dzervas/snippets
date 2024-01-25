from collections import namedtuple
from typing import List, NamedTuple, Optional, Self, Type, Union
import binaryninja as bn
import json

from pathlib import Path
from binaryninjaui import UIContext, UIAction, UIActionHandler, Menu
from PySide6.QtGui import QKeySequence

SNIPPETS_PATH: Path = Path(bn.user_plugin_path()) / ".." / "snippets"


class Snippet():
	type_name: str = "Base"
	file_extension: str = ""
	comment_line_start: str = ""
	comment_line_end: str = ""

	def __init__(self, name: str, code: str) -> None:
		name = name.strip()
		if not name.endswith(self.file_extension):
			raise ValueError(f"Snippet is not supported by {self.__class__.__name__}")

		self.name = name
		self.code = code.strip()

	@property
	def label(self) -> str:
		if hasattr(self.metadata, "description") and self.metadata.description:
			return self.metadata.description
		return self.name

	@classmethod
	def isValid(cls, path: Path) -> bool:
		return cls.file_extension != "" and path.is_file() and path.name.endswith(cls.file_extension)

	def edit(self) -> None:
		raise NotImplementedError

	def duplicate(self, target: str) -> None:
		raise NotImplementedError

	def rename(self, name: str) -> None:
		raise NotImplementedError

	def runner(self, **kwargs) -> None:
		raise NotImplementedError

	def run(self, _context: Optional[UIContext] = None, **kwargs) -> None:
		global _LAST_SNIPPET
		_LAST_SNIPPET = self

		class Runner(bn.BackgroundTaskThread):
			def __init__(self, snippet: Snippet) -> None:
				super().__init__(f"Running snippet '{snippet.label}'...")
				self.snippet = snippet

			def run(self) -> None:
				self.snippet.runner(**kwargs)

		runner = Runner(self)
		runner.start()
		return runner

	def context(self) -> Union[NamedTuple, UIContext]:
		dummy_context = {
			"binaryView": None,
			"address": None,
			"function": None,
			"token": None,
			"lowLevelILFunction": None,
			"mediumLevelILFunction": None
		}

		ctx = UIContext.activeContext()
		if not ctx:
			ctx = UIContext.allContexts()[0]

		if not ctx:
			#There is no tab open at all but we still want other snippets to run that don't rely on context.
			context = namedtuple("context", dummy_context.keys())(*dummy_context.values())
		else:
			handler = ctx.contentActionHandler()
			if handler:
				context = handler.actionContext()
			else:
				context = namedtuple("context", dummy_context.keys())(*dummy_context.values())

		return context

	def save(self) -> None:
		with open(SNIPPETS_PATH / self.name, "w") as f:
			f.write(self.code)

	@classmethod
	def load(cls: Type[Self], path: Union[str, Path]) -> Self:
		if not isinstance(path, Path):
			path = Path(path)

		with open(path, "r") as f:
			code = f.read()

		return cls(path.name, code)

	@property
	def metadata(self) -> NamedTuple:
		result = {}

		index = 0
		for line in self.code.splitlines():
			stripped = line.strip()

			if not stripped.startswith(self.comment_line_start) or not stripped.endswith(self.comment_line_end):
				break

			data = stripped[len(self.comment_line_start):-len(self.comment_line_end)].strip()
			result_key = len(result.keys())
			result_value = data

			if index == 0:
				result_key = "description"
			elif index == 1:
				result_key = "hotkey"
				result_value = QKeySequence(data)
			elif ":" in data:
				result_key, result_value = data.split(":", 1)

				try:
					result_value = json.loads(result_value)
				except json.decoder.JSONDecodeError:
					pass

			result[result_key] = result_value

		return namedtuple("metadata", result.keys())(*result.values())

	@metadata.setter
	def metadata(self, value: dict) -> None:
		old_keys = self.metadata.keys()
		replace_lines = len(old_keys)

		comments = [
			f"{self.comment_line_start} {value['description']} {self.comment_line_end}".strip(),
			f"{self.comment_line_start} {value['hotkey'].toString()} {self.comment_line_end}".strip(),
		]

		del value["description"]
		del value["hotkey"]

		for key, data in value.items():
			comments.append(f"{self.comment_line_start} {key}: {json.dumps(data)} {self.comment_line_end}".strip())

		new_code_lines = comments.extend(self.code.splitlines()[replace_lines:])
		self.code = "\n".join(new_code_lines)

	@staticmethod
	def register(snippet_type: Type[Self]) -> None:
		_SNIPPET_TYPES.append(snippet_type)


_SNIPPET_TYPES: List[Type[Snippet]] = []
_LAST_SNIPPET: Optional[Snippet] = None

def run_last_snippet(context: UIContext) -> None:
	if _LAST_SNIPPET:
		# TODO: Background?
		_LAST_SNIPPET.run()

def is_valid_snippet(path: Union[str, Path]) -> bool:
	for snippet_type in _SNIPPET_TYPES:
		if snippet_type.isValid(path):
			return True

	return False

def load_snippet(path: Union[str, Path]) -> Snippet:
	for snippet_type in _SNIPPET_TYPES:
		try:
			return snippet_type.load(path)
		except ValueError:
			pass

	raise ValueError(f"Snippet is not supported by any registered snippet type: {path}")

def load_all_snippets(_context: Optional[UIContext] = None) -> List[Snippet]:
	for action in list(filter(lambda x: x.startswith("Snippets\\"), UIAction.getAllRegisteredActions())):
		if action in ["Snippets\\Snippet Editor...", "Snippets\\Reload All Snippets", "Snippets\\Rerun Last Snippet"]:
			continue
		UIActionHandler.globalActions().unbindAction(action)
		Menu.mainMenu("Plugins").removeAction(action)
		UIAction.unregisterAction(action)

	for path in SNIPPETS_PATH.iterdir():
		if not path.is_file():
			continue

		bn.log_info(path)
		try:
			snip = load_snippet(path)
		except ValueError:
			continue

		metadata = snip.metadata
		if hasattr(metadata, "hotkey") and metadata.hotkey:
			UIAction.registerAction(snip.label, metadata.hotkey)
		else:
			UIAction.registerAction(snip.label)

		UIActionHandler.globalActions().bindAction(f"Snippets\\{snip.label}", UIAction(snip.run))
		Menu.mainMenu("Plugins").addAction(f"Snippets\\{snip.label}", "Snippets")
