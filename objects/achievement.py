from typing import Callable

class Achievement:
	"""Represents one achievement class."""
	def __init__(self, _id: int, file: str, 
		name: str, desc: str, condition: Callable) -> None:
		self.id = _id
		self.file = file
		self.name = name
		self.desc = desc
		self.condition = condition

	@property
	def full_name(self) -> str:
		return f"{self.file}+{self.name}+{self.desc}"

